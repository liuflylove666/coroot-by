package rca

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	aiintegration "github.com/coroot/coroot/ai"
	"github.com/coroot/coroot/model"
)

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
		MaxTokens: 2200,
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
	sanitizeAISummary(&out)
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
	system := `You are Coroot's AI RCA renderer.
Coroot has already performed the root-cause investigation using dependency graph analysis, ML scoring, checks, traces, logs, events, and charts.
You receive only Coroot findings, not raw telemetry. Your task is explanation and summarization only.
Do not invent services, namespaces, deployments, nodes, widgets, commands, or root causes. Return strict JSON only.`
	var b strings.Builder
	b.WriteString("Render the following built-in RCA findings as a concise official-style incident RCA.\n")
	b.WriteString("This package is the compact Coroot findings set; do not request or assume raw telemetry outside it.\n\n")
	b.WriteString("Required JSON fields: short_summary, root_cause, detailed_root_cause_analysis, immediate_fixes, confidence, missing_evidence.\n\n")
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
	b.WriteString("- detailed_root_cause_analysis: Markdown with these sections in order: Anomaly summary, Issue propagation paths, Key findings and Root Cause Analysis, Remediation, Relevant charts.\n")
	b.WriteString("- Issue propagation paths must come from the propagation map or candidate graph_paths only.\n")
	b.WriteString("- Relevant charts must reference available widget ids as WIDGET-N and must not invent chart names.\n")
	b.WriteString("- immediate_fixes: separate mitigation from permanent fix; include commands only when exact resources are present in evidence.\n")
	b.WriteString("- If evidence is missing or weak, say what is missing instead of overstating certainty.\n")
	return system, b.String()
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

func sanitizeAISummary(out *aiSummary) {
	out.ShortSummary = truncateRunes(sanitizeText(out.ShortSummary), 240)
	out.RootCause = truncateRunes(sanitizeText(out.RootCause), 1400)
	out.DetailedRootCause = truncateRunes(sanitizeText(out.DetailedRootCause), 6000)
	out.ImmediateFixes = truncateRunes(sanitizeText(out.ImmediateFixes), 1200)
	for i := range out.MissingEvidence {
		out.MissingEvidence[i] = truncateRunes(sanitizeText(out.MissingEvidence[i]), 160)
	}
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
