package rca

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/coroot/coroot/model"
	"github.com/coroot/coroot/utils"
)

var destructiveKubectl = regexp.MustCompile(`(?i)\bkubectl\s+(delete|apply|patch|scale|rollout\s+undo|replace|cordon|drain)\b`)

func PostProcess(result *model.RCA) {
	if result == nil {
		return
	}
	result.Grounding = ValidateGrounding(result)
	result.Remediation = BuildRemediation(result)
	if result.Grounding != nil {
		switch result.Grounding.Status {
		case "unsafe":
			result.ValidatorResult = "unsafe_needs_human_review"
		case "suspicious":
			if result.ValidatorResult == "" || result.ValidatorResult == "grounded" || result.ValidatorResult == "built_in_grounded" {
				result.ValidatorResult = "grounded_with_warnings"
			}
		case "grounded":
			if result.ValidatorResult == "" {
				result.ValidatorResult = "grounded"
			}
		}
	}
}

func ValidateGrounding(result *model.RCA) *model.RCAGrounding {
	g := &model.RCAGrounding{
		Status:            "grounded",
		HallucinationRisk: "low",
	}
	allowed := evidenceTerms(result)
	top := topCandidate(result)
	evidenceCount := 0
	for _, c := range result.Candidates {
		evidenceCount += len(c.EvidenceRefs)
	}
	if evidenceCount == 0 {
		g.Issues = append(g.Issues, "no evidence refs attached to RCA candidates")
	}
	g.EvidenceCoverage = coverageScore(evidenceCount, len(result.MissingEvidence))

	text := strings.ToLower(result.RootCause + "\n" + result.DetailedRootCause + "\n" + result.ImmediateFixes)
	if top != nil && top.Component != "" && !mentionsAny(text, allowed.Items()) {
		g.Issues = append(g.Issues, "RCA text does not reference known evidence terms from candidates or propagation map")
	}
	for _, m := range destructiveKubectl.FindAllString(result.ImmediateFixes, -1) {
		g.UnsafeFixes = append(g.UnsafeFixes, sanitizeText(m))
	}
	if len(g.UnsafeFixes) > 0 {
		g.Issues = append(g.Issues, "destructive kubectl command requires human approval")
	}

	switch {
	case len(g.UnsafeFixes) > 0:
		g.Status = "unsafe"
		g.HallucinationRisk = "medium"
	case len(g.Issues) > 0 || g.EvidenceCoverage < 0.50:
		g.Status = "suspicious"
		g.HallucinationRisk = "medium"
		if g.EvidenceCoverage < 0.25 {
			g.HallucinationRisk = "high"
		}
	default:
		g.Status = "grounded"
		g.HallucinationRisk = "low"
	}
	return g
}

func BuildRemediation(result *model.RCA) []model.RCARemediationAction {
	top := topCandidate(result)
	if top == nil {
		return nil
	}
	evidence := append([]string{}, top.EvidenceRefs...)
	actions := []model.RCARemediationAction{
		{
			Id:           "verify-evidence",
			Title:        "Verify RCA evidence",
			Description:  "Review the listed charts, traces, events, candidate score, and missing evidence before changing production resources.",
			Risk:         "low",
			Status:       "recommended",
			EvidenceRefs: evidence,
			Verification: "Confirm SLO burn rate, latency, errors, and root-candidate evidence move in the same recovery window.",
		},
	}
	add := func(id, title, desc, risk, verification string, approval bool) {
		actions = append(actions, model.RCARemediationAction{
			Id:               id,
			Title:            title,
			Description:      desc,
			Risk:             risk,
			Status:           "recommended",
			RequiresApproval: approval,
			EvidenceRefs:     evidence,
			Verification:     verification,
		})
	}

	switch top.Scenario {
	case "network_chaos_delay":
		add("pause-chaos-resource", "Pause or remove verified chaos resource", "If evidence names an active NetworkChaos or fault-injection resource on the dependency path, pause it through the normal change process.", "high", "Network RTT/retransmission and service SLO must recover after the resource is paused.", true)
	case "bad_deployment", "deployment_change", "bad_deployment_db_query_amplification":
		add("rollback-rollout", "Rollback the suspected rollout", "Compare the suspected deployment with the previous stable revision and roll back only after confirming the deployment is the earliest trigger.", "high", "Application errors, latency, and downstream DB pressure should return to baseline.", true)
	case "cronjob_node_cpu_starvation":
		add("isolate-periodic-job", "Isolate the periodic job", "Move the periodic job away from latency-sensitive workloads and add CPU requests, limits, or node affinity controls.", "medium", "Node CPU delay, throttling, and impacted service latency should fall together.", true)
	case "recommendation_memory_leak", "resource_exhaustion":
		add("restore-workload-capacity", "Restore workload capacity", "Restart or scale the affected workload only as a stopgap, then fix the memory or CPU growth path before closing the incident.", "medium", "Restarts stop increasing and memory or CPU usage remains stable after traffic returns.", true)
	case "database_bottleneck":
		add("reduce-db-pressure", "Reduce database pressure", "Identify the client/query source and reduce the offending traffic, query amplification, or recently introduced load.", "medium", "DB latency, query total time, and dependent service SLO should recover.", false)
	default:
		add("continue-investigation", "Continue bounded investigation", "Use missing evidence and candidate evidence refs to collect the next trace, log pattern, event, or deployment proof.", "low", "A follow-up RCA should improve evidence coverage and candidate confidence.", false)
	}
	return actions
}

func appendRemediationSummary(result *model.RCA) {
	if result == nil || len(result.Remediation) == 0 || strings.Contains(result.DetailedRootCause, "## Recommended Actions") {
		return
	}
	var b strings.Builder
	if strings.TrimSpace(result.DetailedRootCause) != "" {
		b.WriteString(strings.TrimRight(result.DetailedRootCause, "\n"))
		b.WriteString("\n\n")
	}
	b.WriteString("## Recommended Actions\n\n")
	for _, a := range result.Remediation {
		b.WriteString(fmt.Sprintf("- **%s**", sanitizeText(a.Title)))
		if a.Risk != "" {
			b.WriteString(fmt.Sprintf(" (`%s` risk)", sanitizeText(a.Risk)))
		}
		if a.RequiresApproval {
			b.WriteString(" (review required)")
		}
		if a.Description != "" {
			b.WriteString(": " + sanitizeText(a.Description))
		}
		if len(a.EvidenceRefs) > 0 {
			b.WriteString(" Evidence: `" + strings.Join(a.EvidenceRefs, "`, `") + "`.")
		}
		if a.Verification != "" {
			b.WriteString(" Verify: " + sanitizeText(a.Verification))
		}
		b.WriteString("\n")
	}
	result.DetailedRootCause = b.String()
}

func evidenceTerms(result *model.RCA) *utils.StringSet {
	terms := utils.NewStringSet()
	for _, c := range result.Candidates {
		addEvidenceTerm(terms, c.Component)
		addEvidenceTerm(terms, c.RootCauseReason)
		addEvidenceTerm(terms, c.Scenario)
		for _, ref := range c.EvidenceRefs {
			addEvidenceTerm(terms, ref)
		}
	}
	if result.PropagationMap != nil {
		for _, app := range result.PropagationMap.Applications {
			addEvidenceTerm(terms, app.Id.String())
			addEvidenceTerm(terms, app.Id.Name)
			addEvidenceTerm(terms, string(app.Id.Kind))
			addEvidenceTerm(terms, app.Id.Namespace)
		}
	}
	return terms
}

func addEvidenceTerm(terms *utils.StringSet, s string) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" || s == "_" {
		return
	}
	terms.Add(s)
	for _, p := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ':' || r == '/' || r == ',' || r == ';' || r == '|'
	}) {
		p = strings.TrimSpace(p)
		if len(p) >= 3 {
			terms.Add(p)
		}
	}
}

func mentionsAny(text string, terms []string) bool {
	for _, term := range terms {
		if len(term) >= 3 && strings.Contains(text, term) {
			return true
		}
	}
	return false
}

func coverageScore(evidenceCount, missingCount int) float32 {
	total := evidenceCount + missingCount
	if total == 0 {
		return 0
	}
	score := float32(evidenceCount) / float32(total)
	if score > 1 {
		return 1
	}
	return score
}

func topCandidate(result *model.RCA) *model.RCACandidate {
	if result == nil || len(result.Candidates) == 0 {
		return nil
	}
	return result.Candidates[0]
}

func AppendHistoricalContextPrompt(b *strings.Builder, cases []model.RCAHistoricalContext) {
	if len(cases) == 0 {
		return
	}
	b.WriteString("\nHistorical context (supplemental only; realtime evidence wins on conflicts):\n")
	for _, c := range cases {
		b.WriteString(fmt.Sprintf("- incident=%s scenario=%s component=%s similarity=%.2f fix=%s outcome=%s\n",
			c.IncidentKey, c.Scenario, c.Component, c.Similarity, sanitizeText(c.FixSummary), sanitizeText(c.Outcome)))
	}
}
