package rca

import (
	"fmt"
	"sort"
	"strings"

	"github.com/coroot/coroot/model"
)

const aiopsDetector = "statistical_red_fallback"

func BuildAnomalySignals(result *model.RCA) []model.RCAAnomalySignal {
	if result == nil {
		return nil
	}
	var signals []model.RCAAnomalySignal
	seen := map[string]struct{}{}
	for _, c := range result.Candidates {
		if c == nil {
			continue
		}
		if !candidateHasActionableAIOpsSignal(c) {
			continue
		}
		metric := anomalyMetric(c)
		key := c.Component + "|" + metric
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		score := anomalySignalScore(c)
		signals = append(signals, model.RCAAnomalySignal{
			Service:          componentDisplayName(c.Component),
			Component:        c.Component,
			Metric:           metric,
			Score:            roundFloat32(score, 2),
			Severity:         anomalySeverity(score),
			Detector:         aiopsDetector,
			AnomalousMetrics: anomalousMetrics(c),
			EvidenceRefs:     limitAIOpsStrings(c.EvidenceRefs, 6),
		})
	}
	sort.SliceStable(signals, func(i, j int) bool {
		if signals[i].Score == signals[j].Score {
			return signals[i].Service < signals[j].Service
		}
		return signals[i].Score > signals[j].Score
	})
	if len(signals) > 5 {
		signals = signals[:5]
	}
	return signals
}

func candidateHasActionableAIOpsSignal(c *model.RCACandidate) bool {
	if c == nil {
		return false
	}
	if c.RootCauseReason == "insufficient_evidence" || c.Scenario == "" {
		return false
	}
	if len(c.EvidenceRefs) == 0 {
		return false
	}
	if c.ScoreBreakdown == nil {
		return c.Score >= 0.45
	}
	return c.ScoreBreakdown.AnomalyStrength >= 0.35 || c.ScoreBreakdown.Propagation >= 0.35 || c.ScoreBreakdown.Final >= 0.45
}

func BuildSLOForecasts(result *model.RCA) []model.RCASLOForecast {
	if result == nil || len(result.Anomalies) == 0 {
		return nil
	}
	top := topCandidate(result)
	var forecasts []model.RCASLOForecast
	for _, signal := range limitAnomalySignals(result.Anomalies, 3) {
		sli, target, direction := sloTarget(signal.Metric)
		probability := 0.12 + clampFloat32(signal.Score/6, 0, 1)*0.62
		if top != nil {
			probability += clampFloat32(top.Score, 0, 1) * 0.16
		}
		switch signal.Severity {
		case "critical":
			probability += 0.12
		case "high":
			probability += 0.08
		case "medium":
			probability += 0.04
		}
		probability = clampFloat32(probability, 0.01, 0.99)
		timeToBreach := int(60 - probability*50)
		if timeToBreach < 5 {
			timeToBreach = 5
		}
		forecast := model.RCASLOForecast{
			Service:             signal.Service,
			SLI:                 sli,
			BreachProbability:   roundFloat32(probability, 2),
			TimeToBreachMinutes: timeToBreach,
			Target:              target,
			Direction:           direction,
			IsAtRisk:            probability >= 0.60 && timeToBreach <= 60,
			EvidenceRefs:        limitAIOpsStrings(signal.EvidenceRefs, 6),
		}
		if direction == "below" {
			forecast.ForecastValueAtHorizon = roundFloat32(target*(0.75+probability), 2)
		} else {
			forecast.ForecastValueAtHorizon = roundFloat32(target-(probability*0.02), 4)
		}
		forecasts = append(forecasts, forecast)
	}
	sort.SliceStable(forecasts, func(i, j int) bool {
		return forecasts[i].BreachProbability > forecasts[j].BreachProbability
	})
	return forecasts
}

func BuildRunbook(result *model.RCA) *model.RCARunbook {
	if result == nil {
		return nil
	}
	top := topCandidate(result)
	if top == nil {
		return nil
	}
	affected := affectedServices(result)
	severity := runbookSeverity(result)
	refs := limitAIOpsStrings(mergeStrings(top.EvidenceRefs, runbookEvidenceRefs(result)...), 10)
	runbook := &model.RCARunbook{
		Title:             fmt.Sprintf("%s on %s", scenarioTitle(top.Scenario, top.RootCauseReason), componentDisplayName(top.Component)),
		Severity:          severity,
		Summary:           firstNonEmpty(result.ShortSummary, result.RootCause, "Coroot detected an incident requiring RCA follow-up."),
		ImpactAssessment:  runbookImpact(result, affected),
		DetectionTimeline: runbookDetectionTimeline(result, top),
		DiagnosisSteps:    runbookDiagnosisSteps(result, top),
		RemediationSteps:  runbookRemediationSteps(result),
		EscalationPath:    runbookEscalationPath(severity),
		FollowUpActions:   runbookFollowUpActions(top),
		AffectedServices:  affected,
		EvidenceRefs:      refs,
		GeneratedBy:       "built_in_rca_aiops",
	}
	validateRunbook(runbook)
	return runbook
}

func annotateAIOpsEnhancements(result *model.RCA) {
	if result == nil || hasTrajectoryTool(result, "aiops_signal_enrichment") {
		return
	}
	var evidence []string
	for _, a := range result.Anomalies {
		evidence = mergeStrings(evidence, a.EvidenceRefs...)
	}
	for _, f := range result.SLOForecasts {
		evidence = mergeStrings(evidence, f.EvidenceRefs...)
	}
	if len(evidence) == 0 && result.Runbook != nil {
		evidence = mergeStrings(evidence, result.Runbook.EvidenceRefs...)
	}
	result.Trajectory = append(result.Trajectory, model.RCATrajectory{
		Step:          len(result.Trajectory) + 1,
		Tool:          "aiops_signal_enrichment",
		InputSummary:  "candidate score breakdown, propagation map, evidence refs, remediation catalog",
		OutputSummary: fmt.Sprintf("Generated %d anomaly signals, %d SLO risk forecasts, and a validated seven-section runbook from deterministic RCA evidence.", len(result.Anomalies), len(result.SLOForecasts)),
		EvidenceRefs:  evidence,
		EvidenceChain: evidence,
	})
}

func anomalySignalScore(c *model.RCACandidate) float32 {
	if c == nil {
		return 0
	}
	score := clampFloat32(c.Score, 0, 1)
	if c.ScoreBreakdown != nil {
		score = 0.45*c.ScoreBreakdown.AnomalyStrength +
			0.25*c.ScoreBreakdown.Propagation +
			0.20*c.ScoreBreakdown.Final +
			0.10*c.ScoreBreakdown.EvidenceCoverage
	}
	return clampFloat32(1+score*4.5, 0, 6)
}

func anomalySeverity(score float32) string {
	switch {
	case score >= 5:
		return "critical"
	case score >= 3:
		return "high"
	case score >= 2:
		return "medium"
	default:
		return "low"
	}
}

func anomalyMetric(c *model.RCACandidate) string {
	text := strings.ToLower(strings.Join(append(append([]string{c.Scenario, c.RootCauseReason, c.Component}, c.ReasonCodes...), c.EvidenceRefs...), " "))
	switch {
	case strings.Contains(text, "network") || strings.Contains(text, "tcp") || strings.Contains(text, "chaos"):
		return "network_latency"
	case strings.Contains(text, "db") || strings.Contains(text, "postgres") || strings.Contains(text, "query") || strings.Contains(text, "database"):
		return "db_query_load"
	case strings.Contains(text, "cpu") || strings.Contains(text, "cronjob") || strings.Contains(text, "node"):
		return "node_cpu_saturation"
	case strings.Contains(text, "memory") || strings.Contains(text, "oom") || strings.Contains(text, "leak"):
		return "memory_pressure"
	case strings.Contains(text, "storage") || strings.Contains(text, "evict") || strings.Contains(text, "restart"):
		return "stateful_dependency_health"
	case strings.Contains(text, "error"):
		return "error_rate"
	default:
		return "latency"
	}
}

func anomalousMetrics(c *model.RCACandidate) []string {
	switch anomalyMetric(c) {
	case "network_latency":
		return []string{"latency", "tcp_retransmissions", "connection_time"}
	case "db_query_load":
		return []string{"query_latency", "query_total_time", "db_cpu"}
	case "node_cpu_saturation":
		return []string{"cpu_delay", "cpu_throttling", "latency"}
	case "memory_pressure":
		return []string{"memory_usage", "restarts", "availability"}
	case "stateful_dependency_health":
		return []string{"failed_connections", "restarts", "storage_latency"}
	case "error_rate":
		return []string{"error_rate", "availability"}
	default:
		return []string{"latency"}
	}
}

func sloTarget(metric string) (string, float32, string) {
	switch metric {
	case "error_rate", "memory_pressure":
		return "availability", 0.999, "above"
	case "db_query_load":
		return "p99_latency_ms", 500, "below"
	case "network_latency", "node_cpu_saturation", "stateful_dependency_health":
		return "p95_latency_ms", 200, "below"
	default:
		return "p95_latency_ms", 200, "below"
	}
}

func limitAnomalySignals(items []model.RCAAnomalySignal, n int) []model.RCAAnomalySignal {
	if len(items) <= n {
		return items
	}
	return items[:n]
}

func runbookSeverity(result *model.RCA) string {
	maxScore := float32(0)
	for _, a := range result.Anomalies {
		if a.Score > maxScore {
			maxScore = a.Score
		}
	}
	criticalSLO := false
	for _, f := range result.SLOForecasts {
		if f.BreachProbability >= 0.80 && f.TimeToBreachMinutes > 0 && f.TimeToBreachMinutes <= 15 {
			criticalSLO = true
			break
		}
	}
	switch {
	case criticalSLO || maxScore >= 5:
		return "P1 - Critical"
	case maxScore >= 3:
		return "P2 - High"
	case maxScore >= 2:
		return "P3 - Medium"
	default:
		return "P4 - Low"
	}
}

func affectedServices(result *model.RCA) []string {
	seen := map[string]struct{}{}
	var services []string
	if result.PropagationMap != nil {
		for _, app := range result.PropagationMap.Applications {
			if app == nil || app.Id.Name == "" {
				continue
			}
			name := componentDisplayName(app.Id.String())
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			services = append(services, name)
		}
	}
	if len(services) == 0 {
		for _, a := range result.Anomalies {
			if a.Service == "" {
				continue
			}
			if _, ok := seen[a.Service]; ok {
				continue
			}
			seen[a.Service] = struct{}{}
			services = append(services, a.Service)
		}
	}
	sort.Strings(services)
	if len(services) > 8 {
		return services[:8]
	}
	return services
}

func runbookImpact(result *model.RCA, affected []string) string {
	var parts []string
	if len(affected) > 0 {
		parts = append(parts, "Affected services: "+strings.Join(affected, ", ")+".")
	}
	for _, f := range result.SLOForecasts {
		if f.IsAtRisk {
			parts = append(parts, fmt.Sprintf("%s %s has %.0f%% projected breach risk within %d minutes.", f.Service, f.SLI, f.BreachProbability*100, f.TimeToBreachMinutes))
			break
		}
	}
	if len(parts) == 0 {
		return "Impact is bounded by the current incident evidence and should be verified against SLO burn rate, latency, and error widgets."
	}
	return strings.Join(parts, " ")
}

func runbookDetectionTimeline(result *model.RCA, top *model.RCACandidate) string {
	var lines []string
	if top.RootCauseOccurrenceTime != "" {
		lines = append(lines, "- Root-cause occurrence window: "+top.RootCauseOccurrenceTime)
	}
	if len(result.Anomalies) > 0 {
		lines = append(lines, fmt.Sprintf("- Detector: %s flagged %s on %s with score %.2f.", result.Anomalies[0].Detector, result.Anomalies[0].Metric, result.Anomalies[0].Service, result.Anomalies[0].Score))
	}
	if len(lines) == 0 {
		lines = append(lines, "- Detection source: Coroot incident RCA evidence.")
	}
	return strings.Join(lines, "\n")
}

func runbookDiagnosisSteps(result *model.RCA, top *model.RCACandidate) string {
	refs := limitAIOpsStrings(top.EvidenceRefs, 6)
	if len(refs) == 0 {
		refs = limitAIOpsStrings(result.MissingEvidence, 6)
	}
	lines := []string{
		fmt.Sprintf("1. Confirm top RCA candidate `%s` on `%s` and compare it with competing candidates.", top.RootCauseReason, componentDisplayName(top.Component)),
		"2. Review propagation map nodes and edge issue labels for the affected dependency path.",
	}
	if len(refs) > 0 {
		lines = append(lines, "3. Verify evidence refs: `"+strings.Join(refs, "`, `")+"`.")
	} else {
		lines = append(lines, "3. Collect the missing metric, trace, log, or Kubernetes event evidence before changing production resources.")
	}
	return strings.Join(lines, "\n")
}

func runbookRemediationSteps(result *model.RCA) string {
	if len(result.Remediation) == 0 {
		return "1. Keep the incident in investigation mode until Coroot evidence identifies a bounded remediation."
	}
	var lines []string
	for i, action := range result.Remediation {
		line := fmt.Sprintf("%d. %s", i+1, sanitizeText(action.Title))
		if action.Description != "" {
			line += ": " + sanitizeText(action.Description)
		}
		if action.RequiresApproval {
			line += " Review required before execution."
		}
		if action.Verification != "" {
			line += " Verify: " + sanitizeText(action.Verification)
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func runbookEscalationPath(severity string) string {
	if strings.HasPrefix(severity, "P1") || strings.HasPrefix(severity, "P2") {
		return "- Page the on-call SRE and service owner.\n- Require human approval for high-risk Kubernetes or rollout changes.\n- Escalate to platform/database/network owners when evidence points outside the application."
	}
	return "- Assign to the owning service team.\n- Escalate if SLO risk increases, evidence coverage drops, or remediation verification fails."
}

func runbookFollowUpActions(top *model.RCACandidate) string {
	switch top.Scenario {
	case "network_chaos_delay":
		return "- Add guardrails around chaos schedules and target selectors.\n- Alert on network RTT, TCP retransmissions, and dependency latency for the affected path.\n- Add a post-test verification checklist before re-enabling traffic."
	case "bad_deployment", "deployment_change", "bad_deployment_db_query_amplification":
		return "- Add deployment canary checks for DB query amplification.\n- Add query shape and slow-query dashboards to release verification.\n- Record the known-bad version in incident history."
	case "cronjob_node_cpu_starvation":
		return "- Add CPU requests, limits, and scheduling isolation for periodic jobs.\n- Alert when batch jobs share nodes with latency-sensitive services.\n- Review node capacity and priority classes."
	case "stateful_dependency_eviction_restart":
		return "- Add storage and restart budget alerts for stateful dependencies.\n- Review eviction thresholds and resource requests.\n- Keep a dependency recovery playbook for failed client connections."
	case "recommendation_memory_leak", "resource_exhaustion":
		return "- Add memory growth and restart-loop alerts.\n- Capture heap/profile evidence for the leaking code path.\n- Add regression tests for the memory growth scenario."
	default:
		return "- Add missing evidence to Coroot collection.\n- Update this runbook with verified remediation results.\n- Re-run RCA after recovery to compare candidate scores."
	}
}

func validateRunbook(runbook *model.RCARunbook) {
	if runbook == nil {
		return
	}
	checks := []struct {
		name  string
		value string
	}{
		{"Summary", runbook.Summary},
		{"Impact Assessment", runbook.ImpactAssessment},
		{"Detection & Timeline", runbook.DetectionTimeline},
		{"Diagnosis Steps", runbook.DiagnosisSteps},
		{"Remediation Steps", runbook.RemediationSteps},
		{"Escalation Path", runbook.EscalationPath},
		{"Follow-Up Actions", runbook.FollowUpActions},
	}
	for _, c := range checks {
		if strings.TrimSpace(c.value) == "" {
			runbook.MissingSections = append(runbook.MissingSections, c.name)
		}
	}
	runbook.SectionsComplete = len(runbook.MissingSections) == 0
}

func runbookEvidenceRefs(result *model.RCA) []string {
	var refs []string
	for _, a := range result.Anomalies {
		refs = mergeStrings(refs, a.EvidenceRefs...)
	}
	for _, f := range result.SLOForecasts {
		refs = mergeStrings(refs, f.EvidenceRefs...)
	}
	for _, a := range result.Remediation {
		refs = mergeStrings(refs, a.EvidenceRefs...)
	}
	return refs
}

func scenarioTitle(scenario, reason string) string {
	switch scenario {
	case "network_chaos_delay":
		return "Network latency incident"
	case "bad_deployment", "deployment_change", "bad_deployment_db_query_amplification":
		return "Deployment-induced degradation"
	case "cronjob_node_cpu_starvation":
		return "Node CPU saturation incident"
	case "stateful_dependency_eviction_restart":
		return "Stateful dependency restart incident"
	case "recommendation_memory_leak", "resource_exhaustion":
		return "Resource exhaustion incident"
	case "database_bottleneck":
		return "Database bottleneck incident"
	default:
		if reason != "" {
			return strings.ReplaceAll(reason, "_", " ")
		}
		return "Service degradation incident"
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func limitAIOpsStrings(items []string, n int) []string {
	var res []string
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		res = mergeStrings(res, item)
		if len(res) >= n {
			break
		}
	}
	return res
}

func clampFloat32(v, lo, hi float32) float32 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func roundFloat32(v float32, digits int) float32 {
	if digits <= 0 {
		return float32(int(v + 0.5))
	}
	scale := float32(1)
	for i := 0; i < digits; i++ {
		scale *= 10
	}
	if v >= 0 {
		return float32(int(v*scale+0.5)) / scale
	}
	return float32(int(v*scale-0.5)) / scale
}
