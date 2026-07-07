package rca

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	aiintegration "github.com/coroot/coroot/ai"
	"github.com/coroot/coroot/model"
)

const aiRCAMaxTokens = 8000

var aiWidgetRefRe = regexp.MustCompile(`WIDGET-(?:<ID>|N|[0-9]+)`)

type aiSummary struct {
	ShortSummary      string   `json:"short_summary"`
	RootCause         string   `json:"root_cause"`
	DetailedRootCause string   `json:"detailed_root_cause_analysis"`
	ImmediateFixes    string   `json:"immediate_fixes"`
	Confidence        string   `json:"confidence"`
	MissingEvidence   []string `json:"missing_evidence"`
}

func EnhanceWithAI(ctx context.Context, builtIn *model.RCA, settings aiintegration.Settings) (*model.RCA, error) {
	if !settings.Enabled() {
		return builtIn, nil
	}
	provider, err := aiintegration.NewProvider(settings)
	if err != nil {
		return builtIn, err
	}
	system, prompt := aiPrompt(builtIn)
	start := time.Now()
	resp, err := provider.Complete(ctx, aiintegration.CompletionRequest{
		System:    system,
		Prompt:    prompt,
		MaxTokens: aiRCAMaxTokens,
		Tool:      recordSummaryTool(),
	})
	builtIn.Provider = provider.Name()
	builtIn.Model = provider.Model()
	builtIn.LatencyMs = time.Since(start).Milliseconds()
	builtIn.TokenInput = estimateTokens(system) + estimateTokens(prompt)
	if err != nil {
		builtIn.ValidatorResult = "ai_provider_error"
		return builtIn, err
	}
	builtIn.TokenOutput = estimateTokens(resp.Text)
	var out aiSummary
	if err = json.Unmarshal([]byte(extractJSONObject(resp.Text)), &out); err != nil {
		builtIn.ValidatorResult = "invalid_model_output"
		return builtIn, err
	}
	if err = validateAISummary(out); err != nil {
		builtIn.ValidatorResult = "invalid_model_output"
		return builtIn, err
	}
	removedWidgets := sanitizeAISummary(&out, len(builtIn.Widgets))
	if len(removedWidgets) > 0 {
		out.MissingEvidence = append(out.MissingEvidence, fmt.Sprintf("AI output referenced unavailable widgets: %s", strings.Join(removedWidgets, ", ")))
		out.MissingEvidence = sanitizeMissingEvidence(out.MissingEvidence)
	}
	builtIn.ShortSummary = out.ShortSummary
	builtIn.RootCause = out.RootCause
	builtIn.DetailedRootCause = out.DetailedRootCause
	builtIn.ImmediateFixes = out.ImmediateFixes
	if len(out.MissingEvidence) > 0 {
		builtIn.MissingEvidence = out.MissingEvidence
	}
	builtIn.ValidatorResult = "grounded"
	if resp.Model != "" {
		builtIn.Model = resp.Model
	}
	return builtIn, nil
}

func aiPrompt(rca *model.RCA) (string, string) {
	system := `You're Coroot, an observability tool helping SREs troubleshoot their apps in production.
Coroot has already performed the root-cause investigation using dependency graph analysis, ML scoring, checks, traces, logs, Kubernetes events, profiles, and charts.
Coroot traverses the dependency graph and checks correlation between metrics. Strong correlations can guide the explanation, but do not mention Pearson coefficients.
Profile reports are always diff profiles comparing anomaly and baseline windows. Ignore profiles whose top-changed functions are unknown, shared libraries, libc/runtime symbols, or low-level process startup frames.
You receive only Coroot findings, not raw telemetry. Your task is explanation and summarization only.
Do not invent services, namespaces, deployments, nodes, widgets, commands, or root causes. Return data only through the record_summary schema or strict JSON with the same fields.`
	var b strings.Builder
	b.WriteString("Render the following Coroot RCA findings as a concise official-style incident RCA.\n")
	b.WriteString("This package is the compact Coroot findings set; do not request or assume raw telemetry outside it.\n")
	b.WriteString("Use the same evidence-first structure as Coroot Enterprise RCA: Incident Overview, Cascading Impact, Trace Evidence, and Remediation.\n\n")
	b.WriteString("Required record_summary fields: short_summary, root_cause, detailed_root_cause_analysis, immediate_fixes. Optional fields: confidence, missing_evidence.\n\n")
	b.WriteString("Built-in anomaly summary:\n")
	b.WriteString(promptSafeText(rca.ShortSummary) + "\n\n")
	if strings.TrimSpace(rca.RootCause) != "" {
		b.WriteString("Built-in root-cause conclusion:\n")
		b.WriteString(promptSafeText(rca.RootCause) + "\n\n")
	}
	if strings.TrimSpace(rca.ImmediateFixes) != "" {
		b.WriteString("Built-in remediation hint:\n")
		b.WriteString(promptSafeText(rca.ImmediateFixes) + "\n\n")
	}
	b.WriteString("Candidates:\n")
	for _, c := range rca.Candidates {
		b.WriteString(fmt.Sprintf("- id=%s component=%s reason=%s scenario=%s score=%.2f confidence=%s evidence=%s\n",
			promptSafeText(c.Id), promptSafeText(c.Component), promptSafeText(c.RootCauseReason), promptSafeText(c.Scenario), c.Score, promptSafeText(c.Confidence), promptSafeText(strings.Join(c.EvidenceRefs, "; "))))
		if c.PyRCAScores != nil {
			b.WriteString(fmt.Sprintf("  pyrca=random_walk %.2f, bayesian %.2f, hypothesis_testing %.2f, domain_prior %.2f, combined %.2f\n",
				c.PyRCAScores.RandomWalk, c.PyRCAScores.Bayesian, c.PyRCAScores.HypothesisTesting, c.PyRCAScores.DomainPrior, c.PyRCAScores.Combined))
			if len(c.PyRCAScores.GraphPaths) > 0 {
				b.WriteString("  graph_paths:\n")
				for _, path := range c.PyRCAScores.GraphPaths {
					b.WriteString("  - " + promptSafeText(strings.Join(path, " -> ")) + "\n")
				}
			}
		}
	}
	appendPropagationMapPrompt(&b, rca.PropagationMap)
	appendWidgetsPrompt(&b, rca.Widgets)
	appendEvidencePrompt(&b, rca.Evidence)
	appendTrajectoryPrompt(&b, rca.Trajectory)
	if len(rca.MissingEvidence) > 0 {
		b.WriteString("\nMissing evidence:\n")
		for _, m := range rca.MissingEvidence {
			b.WriteString("- " + promptSafeText(m) + "\n")
		}
	}
	AppendHistoricalContextPrompt(&b, rca.HistoricalContext)
	b.WriteString("\nConstraints:\n")
	b.WriteString("- short_summary: one sentence, 80-180 chars when possible.\n")
	b.WriteString("- root_cause: direct conclusion grounded in the top candidate.\n")
	b.WriteString("- detailed_root_cause_analysis: Markdown with these sections in order: Incident Overview, Cascading Impact, Trace Evidence, Remediation, Relevant charts.\n")
	b.WriteString("- Issue propagation paths must come from the propagation map or candidate graph_paths only.\n")
	b.WriteString("- Relevant charts must reference available widget ids as WIDGET-N and must not invent chart names.\n")
	b.WriteString("- immediate_fixes: separate mitigation from permanent fix; include commands only when exact resources are present in evidence.\n")
	b.WriteString("- If evidence is missing or weak, say what is missing instead of overstating certainty.\n")
	return system, b.String()
}

func recordSummaryTool() *aiintegration.CompletionTool {
	return &aiintegration.CompletionTool{
		Name:        "record_summary",
		Description: "Record summary of an incident in well-structured JSON",
		Parameters: map[string]any{
			"type":                 "object",
			"additionalProperties": false,
			"properties": map[string]any{
				"short_summary": map[string]any{
					"type":        "string",
					"description": "One concise sentence summarizing the incident and most likely root cause.",
				},
				"root_cause": map[string]any{
					"type":        "string",
					"description": "Direct root-cause conclusion grounded only in provided Coroot evidence.",
				},
				"detailed_root_cause_analysis": map[string]any{
					"type":        "string",
					"description": "Markdown RCA details with propagation, evidence, remediation, and relevant charts.",
				},
				"immediate_fixes": map[string]any{
					"type":        "string",
					"description": "Immediate mitigation and permanent fix guidance; include commands only when exact resources are present.",
				},
				"confidence": map[string]any{
					"type":        "string",
					"description": "Evidence-grounded confidence label such as high, medium, or low.",
				},
				"missing_evidence": map[string]any{
					"type": "array",
					"items": map[string]any{
						"type": "string",
					},
					"description": "Evidence that would be needed to increase confidence.",
				},
			},
			"required": []string{"short_summary", "root_cause", "immediate_fixes", "detailed_root_cause_analysis"},
		},
	}
}

func appendPropagationMapPrompt(b *strings.Builder, pm *model.PropagationMap) {
	if pm == nil || len(pm.Applications) == 0 {
		return
	}
	b.WriteString("\nPropagation map findings:\n")
	appLimit, edgeLimit, edges := 25, 50, 0
	for i, a := range pm.Applications {
		if i >= appLimit {
			b.WriteString("- additional applications omitted from prompt\n")
			break
		}
		issues := "none"
		if len(a.Issues) > 0 {
			issues = strings.Join(a.Issues, ", ")
		}
		b.WriteString(fmt.Sprintf("- app=%s status=%s issues=%s\n", promptSafeText(a.Id.String()), a.Status, promptSafeText(issues)))
		for _, u := range a.Upstreams {
			if edges >= edgeLimit {
				continue
			}
			stats := "none"
			if u.Stats != nil && u.Stats.Len() > 0 {
				stats = strings.Join(u.Stats.Items(), ", ")
			}
			b.WriteString(fmt.Sprintf("  edge=%s -> %s status=%s stats=%s\n", promptSafeText(a.Id.String()), promptSafeText(u.Id.String()), u.Status, promptSafeText(stats)))
			edges++
		}
	}
}

func appendWidgetsPrompt(b *strings.Builder, widgets []*model.Widget) {
	if len(widgets) == 0 {
		return
	}
	b.WriteString("\nRelevant chart/widget findings:\n")
	limit := len(widgets)
	if limit > 40 {
		limit = 40
	}
	for i := 0; i < limit; i++ {
		b.WriteString(fmt.Sprintf("- WIDGET-%d: %s\n", i, promptSafeText(widgetTitle(widgets[i], i))))
	}
	if len(widgets) > limit {
		b.WriteString("- additional widgets omitted from prompt\n")
	}
}

func appendEvidencePrompt(b *strings.Builder, evidence []model.RCAEvidence) {
	if len(evidence) == 0 {
		return
	}
	b.WriteString("\nEvidence registry:\n")
	limit := len(evidence)
	if limit > 60 {
		limit = 60
	}
	for i := 0; i < limit; i++ {
		e := evidence[i]
		b.WriteString(fmt.Sprintf("- id=%s type=%s title=%s component=%s summary=%s\n",
			promptSafeText(e.Id), promptSafeText(e.Type), promptSafeText(e.Title), promptSafeText(e.Component), promptSafeText(e.Summary)))
	}
	if len(evidence) > limit {
		b.WriteString("- additional evidence omitted from prompt\n")
	}
}

func appendTrajectoryPrompt(b *strings.Builder, trajectory []model.RCATrajectory) {
	if len(trajectory) == 0 {
		return
	}
	b.WriteString("\nInvestigation trajectory:\n")
	for _, t := range trajectory {
		b.WriteString(fmt.Sprintf("- step=%d tool=%s output=%s evidence=%s\n",
			t.Step, promptSafeText(t.Tool), promptSafeText(t.OutputSummary), promptSafeText(strings.Join(t.EvidenceRefs, "; "))))
	}
}

func promptSafeText(s string) string {
	return truncateRunes(sanitizeText(s), 800)
}

func validateAISummary(out aiSummary) error {
	switch {
	case strings.TrimSpace(out.ShortSummary) == "":
		return fmt.Errorf("short_summary is required")
	case strings.TrimSpace(out.RootCause) == "":
		return fmt.Errorf("root_cause is required")
	case strings.TrimSpace(out.DetailedRootCause) == "":
		return fmt.Errorf("detailed_root_cause_analysis is required")
	case strings.TrimSpace(out.ImmediateFixes) == "":
		return fmt.Errorf("immediate_fixes is required")
	}
	return nil
}

func sanitizeAISummary(out *aiSummary, widgetCount int) []string {
	out.ShortSummary = truncateRunes(sanitizeText(out.ShortSummary), 240)
	out.RootCause = truncateRunes(sanitizeText(out.RootCause), 1400)
	out.DetailedRootCause = truncateRunes(sanitizeText(out.DetailedRootCause), 6000)
	out.ImmediateFixes = truncateRunes(sanitizeText(out.ImmediateFixes), 1200)
	var removed []string
	out.RootCause, removed = sanitizeWidgetReferences(out.RootCause, widgetCount, removed)
	out.DetailedRootCause, removed = sanitizeWidgetReferences(out.DetailedRootCause, widgetCount, removed)
	out.ImmediateFixes, removed = sanitizeWidgetReferences(out.ImmediateFixes, widgetCount, removed)
	out.MissingEvidence = sanitizeMissingEvidence(out.MissingEvidence)
	return removed
}

func sanitizeMissingEvidence(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	res := make([]string, 0, len(items))
	seen := map[string]bool{}
	for _, item := range items {
		clean := truncateRunes(sanitizeText(item), 180)
		if clean == "" || seen[clean] {
			continue
		}
		seen[clean] = true
		res = append(res, clean)
	}
	return res
}

func sanitizeWidgetReferences(s string, widgetCount int, removed []string) (string, []string) {
	if s == "" {
		return s, removed
	}
	seen := map[string]bool{}
	for _, r := range removed {
		seen[r] = true
	}
	clean := aiWidgetRefRe.ReplaceAllStringFunc(s, func(ref string) string {
		raw := strings.TrimPrefix(ref, "WIDGET-")
		if n, err := strconv.Atoi(raw); err == nil && n >= 0 && n < widgetCount {
			return ref
		}
		if !seen[ref] {
			removed = append(removed, ref)
			seen[ref] = true
		}
		if widgetCount > 0 {
			return "available evidence charts"
		}
		return "available evidence"
	})
	return clean, removed
}

func truncateRunes(s string, max int) string {
	rs := []rune(strings.TrimSpace(s))
	if len(rs) <= max {
		return string(rs)
	}
	return string(rs[:max]) + "..."
}

func extractJSONObject(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "```") {
		s = strings.TrimPrefix(s, "```json")
		s = strings.TrimPrefix(s, "```")
		s = strings.TrimSuffix(s, "```")
		s = strings.TrimSpace(s)
	}
	start := strings.Index(s, "{")
	end := strings.LastIndex(s, "}")
	if start >= 0 && end >= start {
		return s[start : end+1]
	}
	return s
}

func estimateTokens(s string) int {
	return len([]rune(s)) / 4
}
