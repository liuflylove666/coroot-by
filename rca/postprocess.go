package rca

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/coroot/coroot/model"
	"github.com/coroot/coroot/utils"
)

var (
	destructiveKubectl = regexp.MustCompile(`(?i)\bkubectl\s+(delete|apply|patch|scale|rollout\s+undo|replace|cordon|drain)\b`)
	inlineCodeToken    = regexp.MustCompile("`([^`\n]{3,160})`")
	resourcePathToken  = regexp.MustCompile(`(?i)\b(?:deployment|statefulset|daemonset|replicaset|cronjob|job|pod|service|svc|node|namespace|networkchaos|schedule|configmap|secret|ingress|database|postgres|postgresql|kafka|redis|mysql|mongodb)/[a-z0-9][a-z0-9._:-]{1,100}\b`)
)

func PostProcess(result *model.RCA) {
	if result == nil {
		return
	}
	annotateCandidateConfidence(result)
	annotateCompetingHypotheses(result)
	result.Remediation = BuildRemediation(result)
	result.Anomalies = BuildAnomalySignals(result)
	result.SLOForecasts = BuildSLOForecasts(result)
	result.Runbook = BuildRunbook(result)
	annotateAIOpsEnhancements(result)
	result.Grounding = ValidateGrounding(result)
	cleanFaultLabDisplayNames(result)
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

func annotateCandidateConfidence(result *model.RCA) {
	top := topCandidate(result)
	if top == nil || hasTrajectoryTool(result, "audit_candidate_confidence") {
		return
	}
	alt := nextCompetingCandidate(result, top)
	evidence := append([]string{}, top.EvidenceRefs...)
	output := fmt.Sprintf("Top candidate %s on %s has score %.2f and confidence %s.", top.Scenario, componentDisplayName(top.Component), top.Score, top.Confidence)
	if alt == nil {
		top.SupportingEvidence = mergeStrings(top.SupportingEvidence, "candidate_audit:single_candidate")
		output += " No competing candidate survived deterministic scenario filtering."
	} else {
		delta := top.Score - alt.Score
		if delta < 0 {
			delta = 0
		}
		top.SupportingEvidence = mergeStrings(top.SupportingEvidence, fmt.Sprintf("winner_margin:%.2f", delta))
		evidence = mergeStrings(evidence, alt.EvidenceRefs...)
		output += fmt.Sprintf(" Nearest alternative %s on %s scored %.2f, delta %.2f.", alt.Scenario, componentDisplayName(alt.Component), alt.Score, delta)
	}
	result.Trajectory = append(result.Trajectory, model.RCATrajectory{
		Step:          len(result.Trajectory) + 1,
		Tool:          "audit_candidate_confidence",
		InputSummary:  "candidate ranking, score breakdown, evidence refs, and scenario filters",
		OutputSummary: output,
		EvidenceRefs:  evidence,
		EvidenceChain: evidence,
	})
}

func annotateCompetingHypotheses(result *model.RCA) {
	top := topCandidate(result)
	if top == nil || len(result.Candidates) < 2 || hasTrajectoryTool(result, "compare_competing_hypotheses") {
		return
	}
	alt := nextCompetingCandidate(result, top)
	if alt == nil {
		return
	}
	delta := top.Score - alt.Score
	if delta < 0 {
		delta = 0
	}
	closeRace := delta <= 0.08
	strongAlternative := alt.Score >= 0.80
	if !closeRace && !strongAlternative {
		top.SupportingEvidence = mergeStrings(top.SupportingEvidence, fmt.Sprintf("winner_margin:%.2f", delta))
		return
	}

	top.SupportingEvidence = mergeStrings(top.SupportingEvidence, fmt.Sprintf("winner_margin:%.2f", delta))
	top.ContradictingEvidence = mergeStrings(top.ContradictingEvidence, fmt.Sprintf(
		"alternative:%s:component=%s:score=%.2f:delta=%.2f",
		evidenceSlug(alt.Scenario),
		evidenceSlug(componentDisplayName(alt.Component)),
		alt.Score,
		delta,
	))
	evidence := mergeStrings(top.EvidenceRefs, alt.EvidenceRefs...)
	result.Trajectory = append(result.Trajectory, model.RCATrajectory{
		Step:          len(result.Trajectory) + 1,
		Tool:          "compare_competing_hypotheses",
		InputSummary:  fmt.Sprintf("primary %s on %s vs alternative %s on %s", top.Scenario, componentDisplayName(top.Component), alt.Scenario, componentDisplayName(alt.Component)),
		OutputSummary: fmt.Sprintf("Primary %s kept because score %.2f exceeds alternative %s %.2f by %.2f; both evidence sets are retained for audit.", top.Scenario, top.Score, alt.Scenario, alt.Score, delta),
		EvidenceRefs:  evidence,
		EvidenceChain: evidence,
	})
}

func nextCompetingCandidate(result *model.RCA, top *model.RCACandidate) *model.RCACandidate {
	if result == nil || top == nil {
		return nil
	}
	for _, c := range result.Candidates[1:] {
		if c == nil {
			continue
		}
		if c.Scenario != top.Scenario || c.Component != top.Component || c.RootCauseReason != top.RootCauseReason {
			return c
		}
	}
	return nil
}

func hasTrajectoryTool(result *model.RCA, tool string) bool {
	if result == nil || tool == "" {
		return false
	}
	for _, step := range result.Trajectory {
		if step.Tool == tool {
			return true
		}
	}
	return false
}

func cleanFaultLabDisplayNames(result *model.RCA) {
	result.ShortSummary = cleanFaultLabDisplayText(result.ShortSummary)
	result.RootCause = cleanFaultLabDisplayText(result.RootCause)
	result.DetailedRootCause = cleanFaultLabDisplayText(result.DetailedRootCause)
	result.ImmediateFixes = cleanFaultLabDisplayText(result.ImmediateFixes)
	for i := range result.Remediation {
		result.Remediation[i].Title = cleanFaultLabDisplayText(result.Remediation[i].Title)
		result.Remediation[i].Description = cleanFaultLabDisplayText(result.Remediation[i].Description)
		result.Remediation[i].Verification = cleanFaultLabDisplayText(result.Remediation[i].Verification)
		result.Remediation[i].VerificationNote = cleanFaultLabDisplayText(result.Remediation[i].VerificationNote)
	}
	for i := range result.Anomalies {
		result.Anomalies[i].Service = cleanFaultLabDisplayText(result.Anomalies[i].Service)
	}
	for i := range result.SLOForecasts {
		result.SLOForecasts[i].Service = cleanFaultLabDisplayText(result.SLOForecasts[i].Service)
	}
	if result.Runbook != nil {
		result.Runbook.Title = cleanFaultLabDisplayText(result.Runbook.Title)
		result.Runbook.Summary = cleanFaultLabDisplayText(result.Runbook.Summary)
		result.Runbook.ImpactAssessment = cleanFaultLabDisplayText(result.Runbook.ImpactAssessment)
		result.Runbook.DetectionTimeline = cleanFaultLabDisplayText(result.Runbook.DetectionTimeline)
		result.Runbook.DiagnosisSteps = cleanFaultLabDisplayText(result.Runbook.DiagnosisSteps)
		result.Runbook.RemediationSteps = cleanFaultLabDisplayText(result.Runbook.RemediationSteps)
		for i := range result.Runbook.AffectedServices {
			result.Runbook.AffectedServices[i] = cleanFaultLabDisplayText(result.Runbook.AffectedServices[i])
		}
	}
}

func cleanFaultLabDisplayText(s string) string {
	if s == "" {
		return ""
	}
	replacer := strings.NewReplacer(
		"coroot-rca-db-query-", "",
		"coroot-rca-network-chaos-", "",
		"coroot-rca-cpu-saturation-", "",
		"db-query-", "",
		"network-chaos-", "",
		"cpu-saturation-", "",
	)
	return replacer.Replace(s)
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

	text := strings.ToLower(groundingReferenceText(result))
	if top != nil && top.Component != "" && !mentionsAny(text, allowed.Items()) {
		g.Issues = append(g.Issues, "RCA text does not reference known evidence terms from candidates or propagation map")
	}
	g.HallucinatedResources = unknownResourceMentions(groundingReferenceText(result), allowed)
	if len(g.HallucinatedResources) > 0 {
		g.Issues = append(g.Issues, "RCA text references resources not present in evidence: "+strings.Join(g.HallucinatedResources, ", "))
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
		if g.EvidenceCoverage < 0.25 || len(g.HallucinatedResources) > 2 {
			g.HallucinationRisk = "high"
		}
	default:
		g.Status = "grounded"
		g.HallucinationRisk = "low"
	}
	return g
}

func groundingReferenceText(result *model.RCA) string {
	if result == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString(result.RootCause)
	b.WriteString("\n")
	b.WriteString(result.DetailedRootCause)
	b.WriteString("\n")
	b.WriteString(result.ImmediateFixes)
	for _, a := range result.Remediation {
		b.WriteString("\n")
		b.WriteString(a.Title)
		b.WriteString("\n")
		b.WriteString(a.Description)
		b.WriteString("\n")
		b.WriteString(a.Verification)
		b.WriteString("\n")
		b.WriteString(a.VerificationNote)
	}
	if result.Runbook != nil {
		b.WriteString("\n")
		b.WriteString(result.Runbook.Title)
		b.WriteString("\n")
		b.WriteString(result.Runbook.Summary)
		b.WriteString("\n")
		b.WriteString(result.Runbook.ImpactAssessment)
		b.WriteString("\n")
		b.WriteString(result.Runbook.DetectionTimeline)
		b.WriteString("\n")
		b.WriteString(result.Runbook.DiagnosisSteps)
		b.WriteString("\n")
		b.WriteString(result.Runbook.RemediationSteps)
		b.WriteString("\n")
		b.WriteString(result.Runbook.FollowUpActions)
	}
	return b.String()
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
		add("pause-chaos-resource", "Pause or remove verified chaos resource", remediationDescriptionWithCommand(top, "If evidence names an active NetworkChaos or fault-injection resource on the dependency path, pause it through the normal change process."), "high", "Network RTT/retransmission and service SLO must recover after the resource is paused.", true)
	case "bad_deployment", "deployment_change", "bad_deployment_db_query_amplification":
		add("rollback-rollout", "Rollback the suspected rollout", remediationDescriptionWithCommand(top, "Compare the suspected deployment with the previous stable revision and roll back only after confirming the deployment is the earliest trigger."), "high", "Application errors, latency, and downstream DB pressure should return to baseline.", true)
	case "cronjob_node_cpu_starvation":
		add("isolate-periodic-job", "Isolate the periodic job", remediationDescriptionWithCommand(top, "Move the periodic job away from latency-sensitive workloads and add CPU requests, limits, or node affinity controls."), "medium", "Node CPU delay, throttling, and impacted service latency should fall together.", true)
	case "stateful_dependency_eviction_restart":
		add("stabilize-stateful-dependency", "Stabilize the stateful dependency", remediationDescriptionWithCommand(top, "Inspect the restarted or evicted stateful dependency, fix the resource pressure that caused it, and verify failed client connections recover."), "high", "Dependency restarts and failed TCP connections should stop, and the impacted service p95/p99 latency should return to baseline.", true)
	case "recommendation_memory_leak", "resource_exhaustion":
		add("restore-workload-capacity", "Restore workload capacity", "Restart or scale the affected workload only as a stopgap, then fix the memory or CPU growth path before closing the incident.", "medium", "Restarts stop increasing and memory or CPU usage remains stable after traffic returns.", true)
	case "database_bottleneck":
		add("reduce-db-pressure", "Reduce database pressure", "Identify the client/query source and reduce the offending traffic, query amplification, or recently introduced load.", "medium", "DB latency, query total time, and dependent service SLO should recover.", false)
	default:
		add("continue-investigation", "Continue bounded investigation", "Use missing evidence and candidate evidence refs to collect the next trace, log pattern, event, or deployment proof.", "low", "A follow-up RCA should improve evidence coverage and candidate confidence.", false)
	}
	return actions
}

func remediationDescriptionWithCommand(top *model.RCACandidate, desc string) string {
	cmd := remediationCommandHint(top)
	if cmd == "" {
		return desc
	}
	return strings.TrimSpace(desc + "\n\nSuggested command from evidence:\n```bash\n" + cmd + "\n```")
}

func remediationCommandHint(top *model.RCACandidate) string {
	if top == nil {
		return ""
	}
	switch top.Scenario {
	case "network_chaos_delay":
		ns, name, schedule := "default", "", ""
		if strings.HasPrefix(strings.ToLower(top.Component), "networkchaos/") {
			parts := strings.Split(top.Component, "/")
			if len(parts) >= 3 {
				ns, name = parts[1], parts[2]
			}
		}
		for _, ref := range top.EvidenceRefs {
			lower := strings.ToLower(ref)
			if strings.Contains(lower, "networkchaos/") {
				parts := strings.Split(ref, "/")
				if len(parts) >= 2 {
					name = strings.Trim(parts[len(parts)-1], ".,;")
				}
				if len(parts) >= 3 {
					ns = strings.Trim(parts[len(parts)-2], ".,;")
				}
			}
			if strings.Contains(lower, "schedule/") || strings.Contains(lower, "schedule:") {
				parts := strings.FieldsFunc(ref, func(r rune) bool {
					return r == '/' || r == ':' || r == ' '
				})
				if len(parts) > 0 {
					schedule = strings.Trim(parts[len(parts)-1], ".,;")
				}
			}
		}
		if name == "" {
			return ""
		}
		cmd := fmt.Sprintf("kubectl delete networkchaos %s -n %s", name, ns)
		if schedule != "" && schedule != name {
			cmd += fmt.Sprintf("\nkubectl delete schedule %s -n %s", schedule, ns)
		}
		return cmd
	case "bad_deployment", "deployment_change", "bad_deployment_db_query_amplification":
		ns, name := "default", componentDisplayName(top.Component)
		if id, err := model.NewApplicationIdFromString(top.Component, ""); err == nil {
			if !id.NamespaceIsEmpty() {
				ns = id.Namespace
			}
			if id.Name != "" {
				name = id.Name
			}
		}
		if name == "" {
			return ""
		}
		return fmt.Sprintf("kubectl -n %s rollout undo deployment/%s\nkubectl -n %s rollout status deployment/%s", ns, name, ns, name)
	case "cronjob_node_cpu_starvation":
		ns, name := "default", componentDisplayName(top.Component)
		if id, err := model.NewApplicationIdFromString(top.Component, ""); err == nil {
			if !id.NamespaceIsEmpty() {
				ns = id.Namespace
			}
			if id.Name != "" {
				name = id.Name
			}
		}
		if name == "" {
			return ""
		}
		return fmt.Sprintf("kubectl -n %s patch cronjob/%s -p '{\"spec\":{\"suspend\":true}}'", ns, name)
	case "stateful_dependency_eviction_restart":
		ns, name := "default", ""
		parts := strings.Split(top.Component, "->")
		if len(parts) == 2 {
			if id, err := model.NewApplicationIdFromString(parts[1], ""); err == nil {
				if !id.NamespaceIsEmpty() {
					ns = id.Namespace
				}
				name = id.Name
			}
		}
		for _, ref := range top.EvidenceRefs {
			if pod := statefulDependencyPodNameFromText(ref); pod != "" {
				name = statefulSetNameFromPod(pod)
				break
			}
		}
		if name == "" {
			return ""
		}
		return fmt.Sprintf("kubectl -n %s rollout status statefulset/%s\nkubectl -n %s get pods -l app=%s", ns, name, ns, name)
	}
	return ""
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
	for _, e := range result.Evidence {
		addEvidenceTerm(terms, e.Id)
		addEvidenceTerm(terms, e.Type)
		addEvidenceTerm(terms, e.Title)
		addEvidenceTerm(terms, e.Component)
		addEvidenceTerm(terms, e.Summary)
		addEvidenceTerm(terms, e.Source)
		for k, v := range e.Attributes {
			addEvidenceTerm(terms, k)
			addEvidenceTerm(terms, v)
		}
		for _, ref := range e.Refs {
			addEvidenceTerm(terms, ref)
		}
	}
	for _, step := range result.Trajectory {
		addEvidenceTerm(terms, step.Tool)
		addEvidenceTerm(terms, step.InputSummary)
		addEvidenceTerm(terms, step.OutputSummary)
		for _, ref := range step.EvidenceRefs {
			addEvidenceTerm(terms, ref)
		}
		for _, ref := range step.EvidenceChain {
			addEvidenceTerm(terms, ref)
		}
	}
	for _, a := range result.Remediation {
		addEvidenceTerm(terms, a.Id)
		for _, ref := range a.EvidenceRefs {
			addEvidenceTerm(terms, ref)
		}
	}
	for _, a := range result.Anomalies {
		addEvidenceTerm(terms, a.Service)
		addEvidenceTerm(terms, a.Component)
		addEvidenceTerm(terms, a.Metric)
		for _, ref := range a.EvidenceRefs {
			addEvidenceTerm(terms, ref)
		}
	}
	for _, f := range result.SLOForecasts {
		addEvidenceTerm(terms, f.Service)
		addEvidenceTerm(terms, f.SLI)
		for _, ref := range f.EvidenceRefs {
			addEvidenceTerm(terms, ref)
		}
	}
	if result.Runbook != nil {
		addEvidenceTerm(terms, result.Runbook.Title)
		for _, service := range result.Runbook.AffectedServices {
			addEvidenceTerm(terms, service)
		}
		for _, ref := range result.Runbook.EvidenceRefs {
			addEvidenceTerm(terms, ref)
		}
	}
	for i, w := range result.Widgets {
		addEvidenceTerm(terms, fmt.Sprintf("WIDGET-%d", i))
		addEvidenceTerm(terms, widgetTitle(w, i))
	}
	if result.PropagationMap != nil {
		for _, app := range result.PropagationMap.Applications {
			addEvidenceTerm(terms, app.Id.String())
			addEvidenceTerm(terms, app.Id.StringWithoutClusterId())
			addEvidenceTerm(terms, app.Id.Name)
			addEvidenceTerm(terms, string(app.Id.Kind))
			addEvidenceTerm(terms, app.Id.Namespace)
			for _, issue := range app.Issues {
				addEvidenceTerm(terms, issue)
			}
			for _, link := range app.Upstreams {
				addEvidenceTerm(terms, link.Id.String())
				addEvidenceTerm(terms, link.Id.StringWithoutClusterId())
				addEvidenceTerm(terms, link.Id.Name)
				for _, stat := range link.Stats.Items() {
					addEvidenceTerm(terms, stat)
				}
			}
			for _, link := range app.Downstreams {
				addEvidenceTerm(terms, link.Id.String())
				addEvidenceTerm(terms, link.Id.StringWithoutClusterId())
				addEvidenceTerm(terms, link.Id.Name)
				for _, stat := range link.Stats.Items() {
					addEvidenceTerm(terms, stat)
				}
			}
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

func unknownResourceMentions(text string, allowed *utils.StringSet) []string {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	seen := utils.NewStringSet()
	for _, match := range inlineCodeToken.FindAllStringSubmatch(text, -1) {
		if len(match) < 2 {
			continue
		}
		addUnknownResourceCandidate(seen, match[1], allowed)
		for _, resource := range resourcePathToken.FindAllString(match[1], -1) {
			addUnknownResourceCandidate(seen, resource, allowed)
		}
	}
	for _, resource := range resourcePathToken.FindAllString(text, -1) {
		addUnknownResourceCandidate(seen, resource, allowed)
	}
	items := seen.Items()
	sort.Strings(items)
	return items
}

func addUnknownResourceCandidate(dst *utils.StringSet, raw string, allowed *utils.StringSet) {
	token := normalizeResourceMention(raw)
	if !resourceLikeToken(token) || isAllowedResourceToken(token, allowed) {
		return
	}
	dst.Add(token)
}

func normalizeResourceMention(raw string) string {
	s := strings.TrimSpace(strings.ToLower(raw))
	s = strings.Trim(s, " \t\r\n`'\".,;()[]{}<>")
	s = strings.TrimPrefix(s, "kind/")
	return strings.TrimSpace(s)
}

func resourceLikeToken(token string) bool {
	if token == "" || strings.ContainsAny(token, " \t\r\n") {
		return false
	}
	if strings.HasPrefix(token, "widget-") || strings.HasPrefix(token, "http://") || strings.HasPrefix(token, "https://") {
		return false
	}
	if genericEvidenceTerm(token) {
		return false
	}
	hasLetter := false
	for _, r := range token {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			hasLetter = true
			break
		}
	}
	if !hasLetter || len(token) < 3 || len(token) > 128 {
		return false
	}
	if resourceKindPrefix(token) {
		return true
	}
	return strings.ContainsAny(token, "-/:_.")
}

func resourceKindPrefix(token string) bool {
	prefixes := []string{
		"deployment/", "statefulset/", "daemonset/", "replicaset/", "cronjob/", "job/", "pod/",
		"service/", "svc/", "node/", "namespace/", "networkchaos/", "schedule/", "configmap/",
		"secret/", "ingress/", "database/", "postgres/", "postgresql/", "kafka/", "redis/", "mysql/", "mongodb/",
	}
	for _, prefix := range prefixes {
		if strings.HasPrefix(token, prefix) {
			return true
		}
	}
	return false
}

func isAllowedResourceToken(token string, allowed *utils.StringSet) bool {
	if allowed == nil {
		return false
	}
	if allowed.Has(token) {
		return true
	}
	for _, part := range resourceTokenParts(token) {
		if len(part) >= 3 && !genericEvidenceTerm(part) && allowed.Has(part) {
			return true
		}
	}
	for _, term := range allowed.Items() {
		if len(term) < 3 || genericEvidenceTerm(term) {
			continue
		}
		if token == term || strings.Contains(token, term) || strings.Contains(term, token) {
			return true
		}
	}
	return false
}

func resourceTokenParts(token string) []string {
	parts := strings.FieldsFunc(token, func(r rune) bool {
		return r == ':' || r == '/' || r == ',' || r == ';' || r == '|' || r == '(' || r == ')'
	})
	var res []string
	for _, p := range parts {
		p = normalizeResourceMention(p)
		if p != "" {
			res = append(res, p)
		}
	}
	return res
}

func genericEvidenceTerm(term string) bool {
	switch term {
	case "_", "app", "apps", "application", "availability", "cache", "candidate", "cluster", "component", "container", "cpu",
		"critical", "database", "db", "default", "dependency", "deployment", "downstream", "error", "errors", "evidence",
		"high", "http", "incident", "job", "kafka", "latency", "log", "logs", "low", "medium", "memory", "metric",
		"metrics", "namespace", "network", "node", "ok", "pod", "postgres", "query", "redis", "request", "requests",
		"service", "slo", "storage", "trace", "traces", "upstream", "warning":
		return true
	default:
		return false
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
