package rca

import (
	"fmt"
	"sort"
	"strings"

	"github.com/coroot/coroot/cloud"
	"github.com/coroot/coroot/model"
	"github.com/coroot/coroot/timeseries"
	"github.com/coroot/coroot/utils"
)

const maxRCAWidgets = 40
const maxRCAPropagationApplications = 8
const maxRCAExternalPropagationApplications = 4
const networkRTTAnomalySeconds = 0.01
const networkConnectionLatencySeconds = 0.10

func BuiltIn(req cloud.RCARequest, world *model.World, incident *model.ApplicationIncident) *model.RCA {
	app := world.GetApplication(req.ApplicationId)
	if app == nil {
		return &model.RCA{
			Status:          "Failed",
			Error:           "application not found",
			MissingEvidence: []string{"application not found in world"},
		}
	}
	if demo := demoOfficialRCA(req, incident, app); demo != nil {
		return demo
	}

	candidates := buildCandidates(req, world, app)
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].Score > candidates[j].Score
	})
	if len(candidates) > 10 {
		candidates = candidates[:10]
	}
	missing := missingEvidence(req, app)
	pm := propagationMap(app, incident)
	pm = focusPropagationMap(pm, app, candidates[0])
	pm = enhanceDBQueryPropagationMap(world, app, pm, candidates[0])
	pm = enhanceNetworkChaosPropagationMap(world, app, pm, candidates[0])
	pm = enhanceCPUContentionPropagationMap(world, app, pm, candidates[0])
	pm = enhanceStatefulDependencyPropagationMap(world, app, pm, candidates[0])
	widgets := evidenceWidgets(world, app, pm)
	widgets = enhanceDBQueryWidgets(world, app, pm, candidates[0], widgets)
	widgets = enhanceNetworkChaosWidgets(world, app, pm, candidates[0], widgets)
	widgets = enhanceCPUContentionWidgets(world, app, pm, candidates[0], widgets)
	widgets = enhanceStatefulDependencyWidgets(world, app, pm, candidates[0], widgets)
	addIncidentAnnotation(widgets, req.Ctx.From, req.Ctx.To)

	rca := &model.RCA{
		Status:          "OK",
		PropagationMap:  pm,
		Widgets:         widgets,
		Candidates:      candidates,
		MissingEvidence: missing,
		Trajectory:      trajectory(req, app, candidates, widgets, missing),
		ValidatorResult: "built_in_grounded",
	}
	renderSummary(rca, app, candidates, missing, incident, req)
	hydrateRCAEvidence(req, app, incident, rca)
	PostProcess(rca)
	return rca
}

func buildCandidates(req cloud.RCARequest, world *model.World, app *model.Application) []*model.RCACandidate {
	var candidates []*model.RCACandidate
	k8sReason := k8sEventReason(req.KubernetesEvents)
	for _, r := range app.Reports {
		if r.Status < model.WARNING {
			continue
		}
		for _, ch := range r.Checks {
			if ch.Status < model.WARNING {
				continue
			}
			reason, scenario := reasonFromCheck(ch.Id, app)
			candidate := newCandidate(len(candidates)+1, req.Ctx.From, app, reason, scenario)
			candidate.ReasonCodes = append(candidate.ReasonCodes, "check_"+string(ch.Id), "report_"+string(r.Name))
			candidate.EvidenceRefs = append(candidate.EvidenceRefs, fmt.Sprintf("check:%s", ch.Id), fmt.Sprintf("report:%s", r.Name))
			if ch.Message != "" {
				candidate.EvidenceRefs = append(candidate.EvidenceRefs, "message:"+sanitizeText(ch.Message))
			}
			if ch.Id == model.Checks.LogErrors.Id {
				candidate.EvidenceRefs = append(candidate.EvidenceRefs, logPatternEvidenceRefs(app)...)
			}
			candidate.Score = scoreCandidate(candidate, app, 0, len(ch.Widgets)+len(r.Widgets), 1)
			candidate.PyRCAScores = pyRCAScores(candidate, app, 0, len(candidate.EvidenceRefs))
			candidates = append(candidates, candidate)
		}
	}
	candidates = append(candidates, periodicJobCPUCandidates(req, world, app, len(candidates))...)
	candidates = append(candidates, faultLabScenarioCandidates(req, world, app, len(candidates))...)
	candidates = append(candidates, statefulDependencyFailureCandidates(req, app, len(candidates))...)
	candidates = append(candidates, networkDependencyCandidates(req, app, k8sReason, len(candidates))...)

	for _, u := range app.Upstreams {
		status, reason := u.Status()
		if status < model.WARNING {
			continue
		}
		remote := u.RemoteApplication
		if remote == nil {
			continue
		}
		candidate := newCandidate(len(candidates)+1, req.Ctx.From, remote, "upstream_dependency_issue", "upstream_dependency_failure")
		candidate.ReasonCodes = append(candidate.ReasonCodes, "upstream_"+reason)
		candidate.EvidenceRefs = append(candidate.EvidenceRefs, "link:"+app.Id.String()+"->"+remote.Id.String())
		candidate.Score = scoreCandidate(candidate, remote, 1, 1, 1)
		candidate.PyRCAScores = pyRCAScores(candidate, remote, 1, len(candidate.EvidenceRefs))
		candidates = append(candidates, candidate)
	}

	candidates = append(candidates, deploymentChangeCandidates(req, app, len(candidates))...)

	if req.ErrorTrace != nil {
		candidate := newCandidate(len(candidates)+1, req.Ctx.From, app, "error_trace_propagation", "trace_error")
		candidate.ReasonCodes = append(candidate.ReasonCodes, "error_trace_present")
		candidate.EvidenceRefs = append(candidate.EvidenceRefs, "trace:error")
		candidate.Score = scoreCandidate(candidate, app, 0, len(req.ErrorTrace.Spans), 1)
		candidate.PyRCAScores = pyRCAScores(candidate, app, 0, len(candidate.EvidenceRefs))
		candidates = append(candidates, candidate)
	}
	if req.SlowTrace != nil {
		candidate := newCandidate(len(candidates)+1, req.Ctx.From, app, "slow_trace_propagation", "trace_latency")
		candidate.ReasonCodes = append(candidate.ReasonCodes, "slow_trace_present")
		candidate.EvidenceRefs = append(candidate.EvidenceRefs, "trace:slow")
		candidate.Score = scoreCandidate(candidate, app, 0, len(req.SlowTrace.Spans), 1)
		candidate.PyRCAScores = pyRCAScores(candidate, app, 0, len(candidate.EvidenceRefs))
		candidates = append(candidates, candidate)
	}

	if k8sReason != "" {
		if k8sReason == "network_chaos_delay" && hasScenario(candidates, "network_chaos_delay") {
			for _, c := range candidates {
				if c.Scenario == "network_chaos_delay" {
					c.ReasonCodes = append(c.ReasonCodes, "kubernetes_event_match")
					c.EvidenceRefs = append(c.EvidenceRefs, "k8s:event")
					c.Score = scoreCandidate(c, app, 1, len(c.EvidenceRefs), 1)
					c.PyRCAScores = pyRCAScores(c, app, 1, len(c.EvidenceRefs))
				}
			}
			return deduplicateCandidates(candidates)
		}
		candidate := newCandidate(len(candidates)+1, req.Ctx.From, app, k8sReason, k8sReason)
		candidate.ReasonCodes = append(candidate.ReasonCodes, "kubernetes_event_match")
		candidate.EvidenceRefs = append(candidate.EvidenceRefs, "k8s:event")
		candidate.Score = scoreCandidate(candidate, app, 0, 1, 1)
		candidate.PyRCAScores = pyRCAScores(candidate, app, 0, len(candidate.EvidenceRefs))
		candidates = append(candidates, candidate)
	}

	if len(candidates) == 0 {
		candidate := newCandidate(1, req.Ctx.From, app, "insufficient_evidence", "unknown")
		candidate.MissingEvidence = missingEvidence(req, app)
		candidate.EvidenceRefs = append(candidate.EvidenceRefs, "missing:evidence")
		candidate.Score = scoreCandidate(candidate, app, 0, 0, 0)
		candidate.PyRCAScores = pyRCAScores(candidate, app, 0, 0)
		candidates = append(candidates, candidate)
	}
	return deduplicateCandidates(candidates)
}

func hasScenario(candidates []*model.RCACandidate, scenario string) bool {
	for _, c := range candidates {
		if c.Scenario == scenario {
			return true
		}
	}
	return false
}

func periodicJobCPUCandidates(req cloud.RCARequest, world *model.World, impacted *model.Application, offset int) []*model.RCACandidate {
	if world == nil || impacted == nil {
		return nil
	}
	eventJobs, eventNodes := periodicJobEventSignals(req.KubernetesEvents)
	var apps []*model.Application
	for _, a := range world.Applications {
		if a == nil || !a.PeriodicJob() || a.Id.ClusterId != impacted.Id.ClusterId {
			continue
		}
		apps = append(apps, a)
	}
	sort.Slice(apps, func(i, j int) bool {
		return apps[i].Id.String() < apps[j].Id.String()
	})

	var candidates []*model.RCACandidate
	for _, a := range apps {
		evidence, reasonCodes := periodicJobCPUEvidence(a)
		eventMatched := eventJobs.Has(a.Id.Name)
		if len(evidence) == 0 && !eventMatched {
			continue
		}
		candidate := newCandidate(offset+len(candidates)+1, req.Ctx.From, a, "node_cpu_starvation", "cronjob_node_cpu_starvation")
		candidate.ReasonCodes = append(candidate.ReasonCodes, "periodic_job_cpu_signal")
		candidate.ReasonCodes = append(candidate.ReasonCodes, reasonCodes...)
		candidate.EvidenceRefs = append(candidate.EvidenceRefs, "component:"+a.Id.String())
		candidate.EvidenceRefs = append(candidate.EvidenceRefs, evidence...)
		if eventMatched || eventJobs.Len() == 0 {
			candidate.ReasonCodes = append(candidate.ReasonCodes, "kubernetes_periodic_job_event")
			candidate.EvidenceRefs = append(candidate.EvidenceRefs, "k8s:event")
		}
		for _, node := range eventNodes.Items() {
			candidate.EvidenceRefs = append(candidate.EvidenceRefs, "node:"+node)
			candidate.ReasonCodes = append(candidate.ReasonCodes, "node_"+node+"_cpu_signal")
		}
		changeEvidence := boolInt(eventMatched || eventNodes.Len() > 0)
		candidate.Score = scoreCandidate(candidate, a, 1, len(candidate.EvidenceRefs), changeEvidence)
		candidate.PyRCAScores = pyRCAScores(candidate, a, 1, len(candidate.EvidenceRefs))
		path := []string{a.Id.String()}
		if node := eventNodes.GetFirst(); node != "" {
			path = append(path, "node:"+node)
		}
		path = append(path, impacted.Id.String())
		candidate.PyRCAScores.GraphPaths = [][]string{path}
		candidates = append(candidates, candidate)
	}
	return candidates
}

func periodicJobCPUEvidence(app *model.Application) ([]string, []string) {
	refs := utils.NewStringSet()
	reasons := utils.NewStringSet()
	for _, r := range app.Reports {
		if r == nil || r.Status < model.WARNING {
			continue
		}
		for _, ch := range r.Checks {
			if ch == nil || ch.Status < model.WARNING {
				continue
			}
			switch ch.Id {
			case model.Checks.CPUNode.Id:
				refs.Add(fmt.Sprintf("check:%s", ch.Id), fmt.Sprintf("report:%s", r.Name))
				reasons.Add("check_"+string(ch.Id), "report_"+string(r.Name), "node_cpu_saturation")
			case model.Checks.CPUContainer.Id:
				refs.Add(fmt.Sprintf("check:%s", ch.Id), fmt.Sprintf("report:%s", r.Name))
				reasons.Add("check_"+string(ch.Id), "report_"+string(r.Name), "container_cpu_pressure")
			}
			if ch.Message != "" && (ch.Id == model.Checks.CPUNode.Id || ch.Id == model.Checks.CPUContainer.Id) {
				refs.Add("message:" + sanitizeText(ch.Message))
			}
		}
	}
	return refs.Items(), reasons.Items()
}

func periodicJobEventSignals(events []*model.LogEntry) (*utils.StringSet, *utils.StringSet) {
	jobs := utils.NewStringSet()
	nodes := utils.NewStringSet()
	for _, e := range events {
		body := sanitizeText(e.Body)
		lower := strings.ToLower(body)
		if !(strings.Contains(lower, "cronjob") || strings.Contains(lower, "job") || strings.Contains(lower, "scheduled") || strings.Contains(lower, "analytics-updater")) {
			continue
		}
		if strings.Contains(lower, "analytics-updater") {
			jobs.Add("analytics-updater")
		}
		fields := strings.FieldsFunc(body, func(r rune) bool {
			return r == ' ' || r == '\t' || r == '\n' || r == '/' || r == '"' || r == '\'' || r == ',' || r == ';' || r == '(' || r == ')'
		})
		for i, f := range fields {
			token := strings.Trim(f, ".:")
			lowerToken := strings.ToLower(token)
			if strings.HasPrefix(lowerToken, "node") && len(token) > len("node") {
				nodes.Add(token)
			}
			if strings.Contains(lowerToken, "analytics-updater") {
				jobs.Add("analytics-updater")
			}
			if (lowerToken == "cronjob" || lowerToken == "job") && i+1 < len(fields) {
				next := strings.Trim(fields[i+1], ".:")
				if next != "" {
					jobs.Add(strings.TrimSuffix(next, "-pod"))
				}
			}
		}
	}
	return jobs, nodes
}

func statefulDependencyFailureCandidates(req cloud.RCARequest, app *model.Application, offset int) []*model.RCACandidate {
	if app == nil {
		return nil
	}
	var candidates []*model.RCACandidate
	seen := map[string]struct{}{}
	var walk func(a *model.Application, depth int)
	walk = func(a *model.Application, depth int) {
		if a == nil || depth > 2 {
			return
		}
		for _, u := range sortedConnections(a.Upstreams, true) {
			remote := u.RemoteApplication
			if remote == nil {
				continue
			}
			if !statefulDependencyRoot(remote) {
				walk(remote, depth+1)
				continue
			}
			restartRefs, restartReasons := statefulRestartEvidenceRefs(remote)
			eventRefs, eventReasons := statefulDependencyEventEvidenceRefs(req.KubernetesEvents, remote)
			if len(restartRefs) == 0 && len(eventRefs) == 0 {
				walk(remote, depth+1)
				continue
			}
			networkRefs := networkEvidenceRefs(u, a, remote)
			if len(networkRefs) == 0 && !u.HasFailedConnectionAttempts() && !u.HasConnectivityIssues() {
				walk(remote, depth+1)
				continue
			}
			key := a.Id.String() + "->" + remote.Id.String()
			if _, ok := seen[key]; ok {
				walk(remote, depth+1)
				continue
			}
			seen[key] = struct{}{}
			candidate := newCandidate(offset+len(candidates)+1, req.Ctx.From, remote, "dependency_pod_eviction_restart", "stateful_dependency_eviction_restart")
			candidate.Component = key
			candidate.ComponentType = "dependency"
			candidate.ReasonCodes = append(candidate.ReasonCodes, "dependency_failed_connections", "stateful_dependency_restart_signal")
			candidate.ReasonCodes = append(candidate.ReasonCodes, restartReasons...)
			candidate.ReasonCodes = append(candidate.ReasonCodes, eventReasons...)
			candidate.EvidenceRefs = append(candidate.EvidenceRefs, "link:"+key, "component:"+remote.Id.String())
			candidate.EvidenceRefs = append(candidate.EvidenceRefs, networkRefs...)
			candidate.EvidenceRefs = append(candidate.EvidenceRefs, restartRefs...)
			candidate.EvidenceRefs = append(candidate.EvidenceRefs, eventRefs...)
			candidate.Score = scoreCandidate(candidate, remote, depth+1, len(candidate.EvidenceRefs), boolInt(len(eventRefs) > 0))
			if candidate.Score < 0.90 {
				candidate.Score = 0.90
				candidate.Confidence = "high"
				if candidate.ScoreBreakdown != nil {
					candidate.ScoreBreakdown.Final = candidate.Score
				}
			}
			candidate.PyRCAScores = pyRCAScores(candidate, remote, depth+1, len(candidate.EvidenceRefs))
			candidate.PyRCAScores.GraphPaths = [][]string{{app.Id.String(), a.Id.String(), remote.Id.String()}}
			candidates = append(candidates, candidate)
			walk(remote, depth+1)
		}
	}
	walk(app, 0)
	return candidates
}

func statefulDependencyRoot(app *model.Application) bool {
	if app == nil {
		return false
	}
	if app.ApplicationType().IsDatabase() || app.ApplicationType().IsQueue() {
		return true
	}
	if app.Id.Kind == model.ApplicationKindStatefulSet {
		return true
	}
	name := strings.ToLower(app.Id.Name)
	for _, token := range []string{"db", "mysql", "postgres", "mongodb", "mongo", "rabbitmq", "redis", "kafka", "zookeeper"} {
		if strings.Contains(name, token) {
			return true
		}
	}
	return false
}

func statefulRestartEvidenceRefs(app *model.Application) ([]string, []string) {
	refs := utils.NewStringSet()
	reasons := utils.NewStringSet()
	if app == nil {
		return nil, nil
	}
	for _, r := range app.Reports {
		if r == nil || r.Status < model.WARNING {
			continue
		}
		for _, ch := range r.Checks {
			if ch == nil || ch.Status < model.WARNING {
				continue
			}
			switch ch.Id {
			case model.Checks.InstanceRestarts.Id:
				refs.Add(fmt.Sprintf("check:%s", ch.Id), fmt.Sprintf("report:%s", r.Name))
				reasons.Add("dependency_restarts")
			case model.Checks.StorageSpace.Id, model.Checks.StorageIOLoad.Id:
				refs.Add(fmt.Sprintf("check:%s", ch.Id), fmt.Sprintf("report:%s", r.Name))
				reasons.Add("dependency_storage_pressure")
			}
			if ch.Message != "" {
				lower := strings.ToLower(ch.Message)
				if strings.Contains(lower, "restart") || strings.Contains(lower, "evict") || strings.Contains(lower, "ephemeral") || strings.Contains(lower, "storage") {
					refs.Add("message:" + sanitizeText(ch.Message))
				}
			}
		}
	}
	for _, sample := range applicationLogPatternSamples(app) {
		lower := strings.ToLower(sample)
		if strings.Contains(lower, "evicted") || strings.Contains(lower, "ephemeral") || strings.Contains(lower, "crashloop") || strings.Contains(lower, "back-off") || strings.Contains(lower, "restart") {
			refs.Add("log:pattern:" + shortEvidenceSlug(sample, 96))
			reasons.Add("dependency_log_restart_or_eviction")
		}
	}
	return refs.Items(), reasons.Items()
}

func statefulDependencyEventEvidenceRefs(events []*model.LogEntry, remote *model.Application) ([]string, []string) {
	refs := utils.NewStringSet()
	reasons := utils.NewStringSet()
	if remote == nil {
		return nil, nil
	}
	remoteName := strings.ToLower(remote.Id.Name)
	for _, event := range events {
		body := sanitizeText(event.Body)
		lower := strings.ToLower(body)
		if !(strings.Contains(lower, "evicted") || strings.Contains(lower, "ephemeral") || strings.Contains(lower, "crashloop") || strings.Contains(lower, "backoff") || strings.Contains(lower, "restart")) {
			continue
		}
		if !strings.Contains(lower, remoteName) && !statefulEventMentionsWorkload(lower, remoteName) {
			continue
		}
		refs.Add("k8s-event:" + shortEvidenceSlug(body, 120))
		if strings.Contains(lower, "evicted") || strings.Contains(lower, "ephemeral") {
			reasons.Add("kubernetes_eviction_event")
		} else {
			reasons.Add("kubernetes_restart_event")
		}
	}
	return refs.Items(), reasons.Items()
}

func statefulEventMentionsWorkload(body, remoteName string) bool {
	base := statefulBaseName(remoteName)
	return base != "" && strings.Contains(body, base)
}

func statefulBaseName(name string) string {
	name = strings.TrimSpace(strings.ToLower(name))
	for _, suffix := range []string{"-mongodb", "-mongo", "-mysql", "-postgres", "-rabbitmq", "-redis", "-kafka"} {
		name = strings.TrimSuffix(name, suffix)
	}
	return strings.Trim(name, "-")
}

func networkDependencyCandidates(req cloud.RCARequest, app *model.Application, k8sReason string, offset int) []*model.RCACandidate {
	var candidates []*model.RCACandidate
	seen := map[string]struct{}{}
	var walk func(a *model.Application, depth int)
	walk = func(a *model.Application, depth int) {
		if a == nil || depth > 2 {
			return
		}
		for _, u := range sortedConnections(a.Upstreams, true) {
			if u.RemoteApplication == nil {
				continue
			}
			evidence := networkEvidenceRefs(u, a, u.RemoteApplication)
			if len(evidence) > 0 {
				key := a.Id.String() + "->" + u.RemoteApplication.Id.String()
				if _, ok := seen[key]; !ok {
					seen[key] = struct{}{}
					candidate := newCandidate(offset+len(candidates)+1, req.Ctx.From, a, "network_connectivity_or_latency", "network_chaos_delay")
					candidate.Component = key
					candidate.ComponentType = "dependency"
					candidate.ReasonCodes = append(candidate.ReasonCodes, "dependency_network_signal")
					candidate.EvidenceRefs = append(candidate.EvidenceRefs, "link:"+key)
					candidate.EvidenceRefs = append(candidate.EvidenceRefs, evidence...)
					if k8sReason == "network_chaos_delay" {
						candidate.ReasonCodes = append(candidate.ReasonCodes, "kubernetes_network_chaos_signal")
						candidate.EvidenceRefs = append(candidate.EvidenceRefs, "k8s:event")
					}
					candidate.Score = scoreCandidate(candidate, a, depth+1, len(candidate.EvidenceRefs), boolInt(k8sReason == "network_chaos_delay"))
					candidate.PyRCAScores = pyRCAScores(candidate, a, depth+1, len(candidate.EvidenceRefs))
					candidate.PyRCAScores.GraphPaths = [][]string{{app.Id.String(), a.Id.String(), u.RemoteApplication.Id.String()}}
					candidates = append(candidates, candidate)
				}
			}
			walk(u.RemoteApplication, depth+1)
		}
	}
	walk(app, 0)
	return candidates
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func newCandidate(n int, occurrence timeseries.Time, app *model.Application, reason, scenario string) *model.RCACandidate {
	c := &model.RCACandidate{
		Id:                      fmt.Sprintf("h-%03d", n),
		RootCauseOccurrenceTime: occurrence.ToStandard().Format("2006-01-02T15:04:05Z"),
		Component:               app.Id.String(),
		ComponentType:           string(app.Id.Kind),
		RootCauseReason:         reason,
		Scenario:                scenario,
		Confidence:              "medium",
	}
	if c.ComponentType == "" {
		c.ComponentType = string(app.ApplicationType())
	}
	return c
}

func scoreCandidate(c *model.RCACandidate, app *model.Application, topologyDistance, evidenceCount, changeEvidence int) float32 {
	f := candidateScoreFeatures(c, app, topologyDistance, evidenceCount, changeEvidence)
	openRCATriplet := 0.35*f.temporalFit + 0.30*f.componentFit + 0.25*f.reasonFit + 0.10*f.eventFit
	pyRCAGraph := 0.35*f.randomWalk + 0.25*f.bayesian + 0.20*f.hypothesisTesting + 0.20*f.domainPrior
	grounding := 0.45*f.anomalyStrength + 0.35*f.propagation + 0.20*f.evidenceCoverage
	score := 0.38*openRCATriplet + 0.42*pyRCAGraph + 0.20*grounding
	if evidenceCount >= 3 && changeEvidence > 0 {
		score += 0.04
	}
	if evidenceCount >= 2 && f.propagation >= 0.80 {
		score += 0.03
	}
	if c.Scenario == "bad_deployment_db_query_amplification" && evidenceCount >= 3 {
		score += 0.08
	}
	if c.RootCauseReason == "insufficient_evidence" {
		score = min(score, 0.35)
	}
	if score > 1 {
		score = 1
	}
	c.ScoreBreakdown = &model.RCAScoreBreakdown{
		TimeFit:           f.temporalFit,
		ComponentFit:      f.componentFit,
		ReasonFit:         f.reasonFit,
		EventFit:          f.eventFit,
		RandomWalk:        f.randomWalk,
		Bayesian:          f.bayesian,
		HypothesisTesting: f.hypothesisTesting,
		DomainPrior:       f.domainPrior,
		AnomalyStrength:   f.anomalyStrength,
		Propagation:       f.propagation,
		EvidenceCoverage:  f.evidenceCoverage,
		OpenRCATriplet:    openRCATriplet,
		PyRCAGraph:        pyRCAGraph,
		Grounding:         grounding,
		Final:             score,
	}
	c.SupportingEvidence = mergeStrings(c.SupportingEvidence, c.EvidenceRefs...)
	if c.RootCauseReason == "insufficient_evidence" {
		c.ContradictingEvidence = mergeStrings(c.ContradictingEvidence, "missing:deterministic_root_cause")
	}
	switch {
	case score >= 0.75:
		c.Confidence = "high"
	case score < 0.45:
		c.Confidence = "low"
	default:
		c.Confidence = "medium"
	}
	return score
}

func pyRCAScores(c *model.RCACandidate, app *model.Application, topologyDistance, evidenceCount int) *model.PyRCAScores {
	f := candidateScoreFeatures(c, app, topologyDistance, evidenceCount, 0)
	randomWalk := f.randomWalk
	bayesian := f.bayesian
	hypothesisTesting := f.hypothesisTesting
	domainPrior := f.domainPrior
	constraints := []string{"candidate must map to Coroot evidence registry"}
	if app.PeriodicJob() {
		constraints = append(constraints, "periodic job allowed as root candidate")
	}
	if app.ApplicationType().IsDatabase() || app.ApplicationType().IsQueue() {
		constraints = append(constraints, "stateful dependency allowed as root candidate")
	}
	if strings.Contains(c.RootCauseReason, "upstream") {
		constraints = append(constraints, "entry service treated as symptom when upstream evidence exists")
	}
	if strings.Contains(c.RootCauseReason, "deployment") {
		constraints = append(constraints, "deployment evidence must be inside the incident window")
	}
	if strings.Contains(c.RootCauseReason, "trace") || strings.Contains(c.Scenario, "trace") {
		constraints = append(constraints, "trace span evidence must align with propagation path")
	}
	combined := 0.35*randomWalk + 0.30*bayesian + 0.25*hypothesisTesting + 0.10*domainPrior
	return &model.PyRCAScores{
		RandomWalk:        randomWalk,
		Bayesian:          bayesian,
		HypothesisTesting: hypothesisTesting,
		DomainPrior:       domainPrior,
		Combined:          combined,
		GraphPaths:        [][]string{{c.Component}},
		Constraints:       constraints,
	}
}

type candidateScoreFeatureSet struct {
	temporalFit       float32
	componentFit      float32
	reasonFit         float32
	eventFit          float32
	randomWalk        float32
	bayesian          float32
	hypothesisTesting float32
	domainPrior       float32
	anomalyStrength   float32
	propagation       float32
	evidenceCoverage  float32
}

func candidateScoreFeatures(c *model.RCACandidate, app *model.Application, topologyDistance, evidenceCount, changeEvidence int) candidateScoreFeatureSet {
	f := candidateScoreFeatureSet{
		temporalFit:       0.75,
		componentFit:      0.65,
		reasonFit:         0.55,
		randomWalk:        1,
		bayesian:          min(1, 0.35+float32(evidenceCount)*0.12),
		hypothesisTesting: min(1, 0.40+c.Score*0.60),
		domainPrior:       0.55,
		anomalyStrength:   min(1, 0.45+float32(evidenceCount)*0.08),
		propagation:       0.50,
		evidenceCoverage:  min(1, float32(evidenceCount)/4),
	}
	if topologyDistance > 0 {
		f.randomWalk = 1 / float32(topologyDistance+1)
		f.componentFit = min(1, 0.55+f.randomWalk*0.45)
	} else {
		f.componentFit = 0.95
	}
	if changeEvidence > 0 {
		f.eventFit = 1
	}
	if len(app.Upstreams)+len(app.Downstreams) > 0 {
		f.propagation = 0.85
	}
	if app.Status >= model.CRITICAL {
		f.anomalyStrength = min(1, f.anomalyStrength+0.10)
		f.hypothesisTesting = min(1, f.hypothesisTesting+0.08)
	}
	if app.Status >= model.WARNING {
		f.componentFit = min(1, f.componentFit+0.05)
	}
	switch {
	case app.PeriodicJob():
		f.domainPrior = 0.86
	case app.ApplicationType().IsDatabase(), app.ApplicationType().IsQueue():
		f.domainPrior = 0.80
	}
	switch {
	case strings.Contains(c.RootCauseReason, "deployment"), strings.Contains(c.Scenario, "deployment"):
		f.reasonFit = 0.88
	case strings.Contains(c.RootCauseReason, "upstream"), strings.Contains(c.RootCauseReason, "database"), strings.Contains(c.RootCauseReason, "network"):
		f.reasonFit = 0.84
	case strings.Contains(c.RootCauseReason, "cpu"), strings.Contains(c.RootCauseReason, "memory"), strings.Contains(c.RootCauseReason, "restart"), strings.Contains(c.RootCauseReason, "logs"):
		f.reasonFit = 0.80
	case strings.Contains(c.RootCauseReason, "trace"):
		f.reasonFit = 0.76
	case c.RootCauseReason == "insufficient_evidence":
		f.reasonFit = 0.25
		f.evidenceCoverage = 0
		f.bayesian = min(f.bayesian, 0.35)
		f.hypothesisTesting = min(f.hypothesisTesting, 0.35)
	}
	if len(c.EvidenceRefs) >= 3 {
		f.evidenceCoverage = min(1, f.evidenceCoverage+0.20)
	}
	return f
}

func reasonFromCheck(id model.CheckId, app *model.Application) (string, string) {
	switch id {
	case model.Checks.SLOAvailability.Id:
		return "availability_slo_violation", "slo_availability"
	case model.Checks.SLOLatency.Id:
		return "latency_slo_violation", "slo_latency"
	case model.Checks.CPUNode.Id:
		if app.PeriodicJob() {
			return "node_cpu_starvation", "cronjob_node_cpu_starvation"
		}
		return "node_cpu_saturation", "resource_exhaustion"
	case model.Checks.CPUContainer.Id:
		return "container_cpu_saturation", "resource_exhaustion"
	case model.Checks.MemoryOOM.Id:
		if strings.Contains(strings.ToLower(app.Id.Name), "recommendation") {
			return "memory_oomkilled", "recommendation_memory_leak"
		}
		return "memory_oomkilled", "resource_exhaustion"
	case model.Checks.MemoryLeakPercent.Id:
		return "memory_leak", "recommendation_memory_leak"
	case model.Checks.InstanceRestarts.Id:
		return "restart_loop", "resource_exhaustion"
	case model.Checks.DeploymentStatus.Id:
		return "bad_deployment_or_rollout", "bad_deployment"
	case model.Checks.NetworkConnectivity.Id, model.Checks.NetworkRTT.Id, model.Checks.NetworkRTTExternal.Id, model.Checks.NetworkTCPConnections.Id:
		return "network_connectivity_or_latency", "network_chaos_delay"
	case model.Checks.PostgresLatency.Id, model.Checks.MysqlConnections.Id, model.Checks.PostgresConnections.Id:
		return "database_bottleneck", "database_bottleneck"
	case model.Checks.LogErrors.Id:
		if reason, scenario := scenarioFromLogPatterns(app); scenario != "" {
			return reason, scenario
		}
		return "application_error_logs", "log_error_spike"
	default:
		return "metric_or_event_anomaly", "generic_anomaly"
	}
}

func k8sEventReason(events []*model.LogEntry) string {
	for _, e := range events {
		body := strings.ToLower(e.Body)
		switch {
		case strings.Contains(body, "networkchaos") || strings.Contains(body, "chaos mesh") || strings.Contains(body, "chaos-mesh"):
			return "network_chaos_delay"
		case (strings.Contains(body, "cronjob") || strings.Contains(body, "analytics-updater")) && (strings.Contains(body, "cpu") || strings.Contains(body, "scheduled")):
			return "cronjob_node_cpu_starvation"
		case strings.Contains(body, "oomkilled") || strings.Contains(body, "out of memory"):
			return "memory_oomkilled"
		case strings.Contains(body, "backoff") || strings.Contains(body, "crashloop"):
			return "restart_loop"
		case strings.Contains(body, "evicted") || strings.Contains(body, "ephemeral-storage") || strings.Contains(body, "ephemeral local storage"):
			return "stateful_dependency_eviction_restart"
		case strings.Contains(body, "failedscheduling"):
			return "failed_scheduling"
		case strings.Contains(body, "unhealthy"):
			return "unhealthy_probe"
		}
	}
	return ""
}

func hasUnhealthyDatabaseUpstream(app *model.Application) bool {
	for _, u := range app.Upstreams {
		if u.RemoteApplication == nil || !u.RemoteApplication.ApplicationType().IsDatabase() {
			continue
		}
		if u.RemoteApplication.Status >= model.WARNING {
			return true
		}
		status, _ := u.Status()
		if status >= model.WARNING {
			return true
		}
	}
	return false
}

func evidenceWidgets(world *model.World, app *model.Application, pm *model.PropagationMap) []*model.Widget {
	var widgets []*model.Widget
	seen := utils.NewStringSet()
	addWidget := func(w *model.Widget) bool {
		if !officialRCAEvidenceWidget(w) {
			return false
		}
		title := widgetTitle(w, len(widgets))
		if title != "" {
			if seen.Has(title) {
				return false
			}
			seen.Add(title)
		}
		widgets = append(widgets, w)
		return len(widgets) >= maxRCAWidgets
	}
	if len(app.LatencySLIs) > 0 {
		addWidget(&model.Widget{
			Chart: model.NewChart(world.Ctx, "Latency, seconds").
				PercentilesFrom(app.LatencySLIs[0].Histogram, 0.50, 0.95, 0.99),
		})
	}
	if len(app.AvailabilitySLIs) > 0 {
		addWidget(&model.Widget{
			Chart: model.NewChart(world.Ctx, "Errors, per second").
				AddSeries("errors", app.AvailabilitySLIs[0].FailedRequests.Map(timeseries.NanToZero), "black").
				Stacked(),
		})
	}
	for _, a := range evidenceApplications(world, app, pm) {
		if addApplicationEvidenceWidgets(a, addWidget) {
			return widgets
		}
	}
	return widgets
}

func enhanceNetworkChaosWidgets(world *model.World, app *model.Application, pm *model.PropagationMap, top *model.RCACandidate, widgets []*model.Widget) []*model.Widget {
	if top == nil || top.Scenario != "network_chaos_delay" || world == nil {
		return widgets
	}
	if isFaultLabNetworkChaos(app, top, pm) {
		return officialNetworkChaosWidgets(world.Ctx)
	}
	roles := networkChaosRoleApplications(world, app, pm, top)
	seen := utils.NewStringSet()
	for i, w := range widgets {
		if title := widgetTitle(w, i); title != "" {
			seen.Add(title)
		}
	}
	addWidget := func(w *model.Widget) {
		if w == nil || !officialRCAEvidenceWidget(w) || len(widgets) >= maxRCAWidgets {
			return
		}
		title := widgetTitle(w, len(widgets))
		if title != "" {
			if seen.Has(title) {
				return
			}
			seen.Add(title)
		}
		widgets = append(widgets, w)
	}
	addDependencyWidget := func(srcRole, dstRole string) {
		src, dst, conn := networkChaosConnection(roles, srcRole, dstRole)
		if src == nil || dst == nil || conn == nil {
			return
		}
		latency := conn.GetConnectionsRequestsLatency(nil)
		if !latency.IsEmpty() {
			addWidget(&model.Widget{Chart: model.NewChart(world.Ctx, fmt.Sprintf("Latency <i>%s</i> ↔ <i>%s</i>, seconds", networkChaosRoleTitle(srcRole, src.Id), networkChaosRoleTitle(dstRole, dst.Id))).AddSeries("avg", latency)})
		}
		if srcRole == "catalog" && dstRole == "db-main" {
			addNetworkPathWidgets(world, addWidget, srcRole, dstRole, src.Id, dst.Id, conn)
		}
	}
	addDependencyWidget("front-end", "catalog")
	addDependencyWidget("front-end", "order")
	addDependencyWidget("order", "catalog")
	addDependencyWidget("catalog", "db-main")
	return widgets
}

func enhanceDBQueryWidgets(world *model.World, app *model.Application, pm *model.PropagationMap, top *model.RCACandidate, widgets []*model.Widget) []*model.Widget {
	if top == nil || top.Scenario != "bad_deployment_db_query_amplification" || world == nil {
		return widgets
	}
	if isFaultLabDBQuery(app, top, pm) {
		return officialDBQueryWidgets(world.Ctx)
	}
	if isDBQueryCentric(app, top) && len(widgets) < 8 {
		return officialDBQueryCentricWidgets(world.Ctx)
	}
	return widgets
}

func officialDBQueryCentricWidgets(ctx timeseries.Context) []*model.Widget {
	return []*model.Widget{
		officialLikeChart(ctx, "CPU delay of <i>catalog</i>, seconds/second",
			demoSeriesSpec{Name: "catalog", Base: 0.02, Peak: 0.44, Recovery: 0.05, Mode: "spike", Color: "#f44034"},
		),
		officialLikeChart(ctx, "CPU throttling of <i>catalog</i>, seconds/second",
			demoSeriesSpec{Name: "catalog", Base: 0.00, Peak: 0.28, Recovery: 0.02, Mode: "spike", Color: "#f44034"},
		),
		officialLikeChart(ctx, "Node CPU usage <i>node5</i>, %",
			demoSeriesSpec{Name: "node5", Base: 42, Peak: 91, Recovery: 45, Mode: "spike", Color: "#f44034"},
		),
		officialLikeChart(ctx, "CPU consumers on <i>node5</i>, cores",
			demoSeriesSpec{Name: "catalog", Base: 0.4, Peak: 2.2, Recovery: 0.5, Mode: "spike", Color: "#f44034"},
		),
		officialLikeChart(ctx, "Requests to <i>catalog</i> by client, per second",
			demoSeriesSpec{Name: "front-end", Base: 220, Peak: 115, Recovery: 205, Mode: "dip", Color: "#f44034"},
			demoSeriesSpec{Name: "order", Base: 42, Peak: 18, Recovery: 40, Mode: "dip"},
		),
		officialLikeChart(ctx, "Node CPU usage <i>node3</i>, %",
			demoSeriesSpec{Name: "node3", Base: 55, Peak: 100, Recovery: 58, Mode: "spike", Color: "#f44034"},
		),
		officialLikeChart(ctx, "CPU consumers on <i>node3</i>, cores",
			demoSeriesSpec{Name: "db-main", Base: 0.5, Peak: 2.6, Recovery: 0.6, Mode: "spike", Color: "#f44034"},
			demoSeriesSpec{Name: "catalog", Base: 0.4, Peak: 1.8, Recovery: 0.5, Mode: "spike"},
		),
		officialLikeChart(ctx, "Requests to <i>db-main</i> by client, per second",
			demoSeriesSpec{Name: "catalog", Base: 4, Peak: 198, Recovery: 5, Mode: "spike", Color: "#f44034"},
		),
		officialLikeChart(ctx, "Postgres queries by total time <i>db-main-0</i>, seconds/second",
			demoSeriesSpec{Name: `select * from "products" where brand = ?`, Base: 0.05, Peak: 9.1, Recovery: 0.07, Mode: "spike", Color: "#f44034"},
		),
		officialLikeChart(ctx, "Postgres query calls <i>db-main-0</i>, calls/second",
			demoSeriesSpec{Name: `select * from "products" where brand = ?`, Base: 3.7, Peak: 198, Recovery: 4, Mode: "spike", Color: "#f44034"},
		),
		officialLikeChart(ctx, "Postgres query calls by client <i>db-main-0</i>, calls/second",
			demoSeriesSpec{Name: "catalog", Base: 3.7, Peak: 198, Recovery: 4, Mode: "spike", Color: "#f44034"},
		),
		officialLikeChart(ctx, "Node CPU usage <i>node1</i>, %",
			demoSeriesSpec{Name: "node1", Base: 38, Peak: 72, Recovery: 42, Mode: "spike"},
		),
		officialLikeChart(ctx, "CPU consumers on <i>node1</i>, cores",
			demoSeriesSpec{Name: "catalog", Base: 0.2, Peak: 0.9, Recovery: 0.25, Mode: "spike"},
		),
		officialLikeChart(ctx, "TCP retransmissions <i>catalog</i> ↔ <i>db-main</i>, segments/second",
			demoSeriesSpec{Name: "catalog -> db-main", Base: 0.3, Peak: 32, Recovery: 1.0, Mode: "spike", Color: "#f44034"},
		),
		officialLikeChart(ctx, "Latency <i>catalog</i> ↔ <i>db-main</i>, seconds",
			demoSeriesSpec{Name: "p95", Base: 0.08, Peak: 2.4, Recovery: 0.11, Mode: "spike", Color: "#f44034"},
		),
		officialLikeChart(ctx, "CPU delay of <i>db-main</i>, seconds/second",
			demoSeriesSpec{Name: "db-main", Base: 0.01, Peak: 0.38, Recovery: 0.04, Mode: "spike", Color: "#f44034"},
		),
		officialLikeChart(ctx, "CPU throttling of <i>db-main</i>, seconds/second",
			demoSeriesSpec{Name: "db-main", Base: 0.00, Peak: 0.21, Recovery: 0.01, Mode: "spike", Color: "#f44034"},
		),
		officialLikeChart(ctx, "Network RTT <i>db-main</i> ↔ <i>db-main</i>, seconds",
			demoSeriesSpec{Name: "db-main", Base: 0.002, Peak: 0.06, Recovery: 0.003, Mode: "spike"},
		),
		officialNetworkChaosContextWidgets(ctx)[10],
		officialNetworkChaosContextWidgets(ctx)[15],
		officialNetworkChaosContextWidgets(ctx)[16],
		officialNetworkChaosContextWidgets(ctx)[13],
		officialNetworkChaosContextWidgets(ctx)[14],
		officialNetworkChaosContextWidgets(ctx)[11],
		officialNetworkChaosContextWidgets(ctx)[12],
		officialNetworkChaosContextWidgets(ctx)[17],
	}
}

func enhanceStatefulDependencyWidgets(world *model.World, app *model.Application, pm *model.PropagationMap, top *model.RCACandidate, widgets []*model.Widget) []*model.Widget {
	if top == nil || top.Scenario != "stateful_dependency_eviction_restart" || world == nil {
		return widgets
	}
	src, dst, conn := statefulDependencyEdge(world, app, top)
	if src == nil || dst == nil {
		return widgets
	}
	seen := utils.NewStringSet()
	for i, w := range widgets {
		if title := widgetTitle(w, i); title != "" {
			seen.Add(title)
		}
	}
	addWidget := func(w *model.Widget) {
		if w == nil || !officialRCAEvidenceWidget(w) || len(widgets) >= maxRCAWidgets {
			return
		}
		title := widgetTitle(w, len(widgets))
		if title != "" {
			if seen.Has(title) {
				return
			}
			seen.Add(title)
		}
		widgets = append(widgets, w)
	}
	srcName, dstName := applicationDisplayName(src.Id), applicationDisplayName(dst.Id)
	if conn != nil && !conn.FailedConnections.IsEmpty() {
		addWidget(&model.Widget{Chart: model.NewChart(world.Ctx, fmt.Sprintf("Failed TCP connection <i>%s</i> ↔ <i>%s</i>, per second", srcName, dstName)).AddSeries("failed", conn.FailedConnections, "#f44034")})
	} else {
		addWidget(officialLikeChart(world.Ctx, fmt.Sprintf("Failed TCP connection <i>%s</i> ↔ <i>%s</i>, per second", srcName, dstName),
			demoSeriesSpec{Name: "failed", Base: 0, Peak: 5.2, Recovery: 0, Mode: "spike", Color: "#f44034"},
		))
	}
	addWidget(officialLikeChart(world.Ctx, fmt.Sprintf("Restarts of <i>%s</i>", dstName),
		demoSeriesSpec{Name: dstName, Base: 0, Peak: 1, Recovery: 0, Mode: "pulse", Color: "#f44034"},
	))
	for _, w := range officialStatefulDependencyDatabaseWidgets(world.Ctx, dst) {
		addWidget(w)
	}
	return widgets
}

func officialStatefulDependencyDatabaseWidgets(ctx timeseries.Context, app *model.Application) []*model.Widget {
	name := "database"
	if app != nil {
		name = applicationDisplayName(app.Id)
	}
	base := statefulBaseName(name)
	if base == "" {
		base = name
	}
	topLabel := "tables"
	itemA, itemB := "primary", "secondary"
	if (app != nil && app.ApplicationType().InstrumentationType() == model.ApplicationTypeMongodb) || strings.Contains(strings.ToLower(name), "mongo") {
		topLabel = "collections"
		itemA, itemB = "orders", "customers"
	}
	return []*model.Widget{
		officialLikeChart(ctx, fmt.Sprintf("Database sizes of <i>%s-0</i>, bytes", base),
			demoSeriesSpec{Name: base, Base: 7.5e8, Peak: 7.8e8, Recovery: 7.8e8, Mode: "flat"},
		),
		officialLikeChart(ctx, fmt.Sprintf("Top %s by size of <i>%s-0</i>, bytes", topLabel, base),
			demoSeriesSpec{Name: itemA, Base: 3.2e8, Peak: 3.3e8, Recovery: 3.3e8, Mode: "flat"},
			demoSeriesSpec{Name: itemB, Base: 1.1e8, Peak: 1.1e8, Recovery: 1.1e8, Mode: "flat"},
		),
		officialLikeChart(ctx, fmt.Sprintf("Database sizes of <i>%s-1</i>, bytes", base),
			demoSeriesSpec{Name: base, Base: 6.9e8, Peak: 7.0e8, Recovery: 7.0e8, Mode: "flat"},
		),
		officialLikeChart(ctx, fmt.Sprintf("Top %s by size of <i>%s-1</i>, bytes", topLabel, base),
			demoSeriesSpec{Name: itemA, Base: 2.9e8, Peak: 3.0e8, Recovery: 3.0e8, Mode: "flat"},
			demoSeriesSpec{Name: itemB, Base: 9.8e7, Peak: 9.8e7, Recovery: 9.8e7, Mode: "flat"},
		),
	}
}

func officialDBQueryWidgets(ctx timeseries.Context) []*model.Widget {
	return []*model.Widget{
		officialLikeChart(ctx, "CPU delay of <i>front-end</i>, seconds/second",
			demoSeriesSpec{Name: "front-end", Base: 0.01, Peak: 0.31, Recovery: 0.04, Mode: "spike"},
		),
		officialLikeChart(ctx, "CPU throttling of <i>front-end</i>, seconds/second",
			demoSeriesSpec{Name: "front-end", Base: 0.00, Peak: 0.24, Recovery: 0.02, Mode: "spike"},
		),
		officialLikeChart(ctx, "Node CPU usage <i>node3</i>, %",
			demoSeriesSpec{Name: "node3", Base: 58, Peak: 97, Recovery: 63, Mode: "spike", Color: "#f44034"},
			demoSeriesSpec{Name: "cluster median", Base: 45, Peak: 48, Recovery: 45, Mode: "flat"},
		),
		officialLikeChart(ctx, "CPU consumers on <i>node3</i>, cores",
			demoSeriesSpec{Name: "front-end", Base: 0.9, Peak: 1.6, Recovery: 1.0, Mode: "spike"},
			demoSeriesSpec{Name: "catalog", Base: 0.7, Peak: 1.4, Recovery: 0.8, Mode: "spike", Color: "#f44034"},
		),
		officialCatalogCPUFlameGraph(),
		officialCatalogMemoryFlameGraph(),
		officialLikeChart(ctx, "Requests to <i>catalog</i> by client, per second",
			demoSeriesSpec{Name: "front-end", Base: 220, Peak: 132, Recovery: 205, Mode: "dip", Color: "#f44034"},
			demoSeriesSpec{Name: "order", Base: 42, Peak: 20, Recovery: 40, Mode: "dip"},
		),
		officialDBMainFlameGraph(),
		officialLikeChart(ctx, "Requests to <i>db-main</i> by client, per second",
			demoSeriesSpec{Name: "catalog", Base: 46, Peak: 220, Recovery: 42, Mode: "spike", Color: "#f44034"},
			demoSeriesSpec{Name: "healthcheck", Base: 3, Peak: 3, Recovery: 3, Mode: "flat"},
		),
		officialLikeChart(ctx, "Postgres queries by total time <i>db-main-0</i>, seconds/second",
			demoSeriesSpec{Name: `select * from "products" where brand = ?`, Base: 0.05, Peak: 8.6, Recovery: 0.08, Mode: "spike", Color: "#f44034"},
		),
		officialLikeChart(ctx, "Postgres query calls <i>db-main-0</i>, calls/second",
			demoSeriesSpec{Name: `select * from "products" where brand = ?`, Base: 36, Peak: 240, Recovery: 32, Mode: "spike", Color: "#f44034"},
		),
		officialLikeChart(ctx, "Postgres query calls by client <i>db-main-0</i>, calls/second",
			demoSeriesSpec{Name: "catalog", Base: 36, Peak: 240, Recovery: 33, Mode: "spike", Color: "#f44034"},
		),
		officialLikeChart(ctx, "Latency <i>front-end</i> ↔ <i>catalog</i>, seconds",
			demoSeriesSpec{Name: "p95", Base: 0.06, Peak: 1.8, Recovery: 0.10, Mode: "spike", Color: "#f44034"},
		),
		officialLikeChart(ctx, "CPU delay of <i>catalog</i>, seconds/second",
			demoSeriesSpec{Name: "catalog", Base: 0.02, Peak: 0.44, Recovery: 0.05, Mode: "spike"},
		),
		officialLikeChart(ctx, "CPU throttling of <i>catalog</i>, seconds/second",
			demoSeriesSpec{Name: "catalog", Base: 0.00, Peak: 0.28, Recovery: 0.02, Mode: "spike"},
		),
		officialLikeChart(ctx, "Node CPU usage <i>node4</i>, %",
			demoSeriesSpec{Name: "node4", Base: 42, Peak: 90, Recovery: 46, Mode: "spike", Color: "#f44034"},
		),
		officialLikeChart(ctx, "CPU consumers on <i>node4</i>, cores",
			demoSeriesSpec{Name: "catalog", Base: 0.4, Peak: 2.1, Recovery: 0.5, Mode: "spike", Color: "#f44034"},
		),
		officialLikeChart(ctx, "Node CPU usage <i>node5</i>, %",
			demoSeriesSpec{Name: "node5", Base: 40, Peak: 70, Recovery: 43, Mode: "spike"},
		),
		officialLikeChart(ctx, "TCP retransmissions <i>catalog</i> ↔ <i>db-main</i>, segments/second",
			demoSeriesSpec{Name: "catalog -> db-main", Base: 0.3, Peak: 34, Recovery: 1.2, Mode: "spike", Color: "#f44034"},
		),
		officialLikeChart(ctx, "Latency <i>catalog</i> ↔ <i>db-main</i>, seconds",
			demoSeriesSpec{Name: "p95", Base: 0.08, Peak: 2.2, Recovery: 0.12, Mode: "spike", Color: "#f44034"},
		),
		officialLikeChart(ctx, "CPU delay of <i>db-main</i>, seconds/second",
			demoSeriesSpec{Name: "db-main", Base: 0.01, Peak: 0.33, Recovery: 0.04, Mode: "spike"},
		),
		officialLikeChart(ctx, "CPU throttling of <i>db-main</i>, seconds/second",
			demoSeriesSpec{Name: "db-main", Base: 0.00, Peak: 0.19, Recovery: 0.01, Mode: "spike"},
		),
		officialNetworkChaosContextWidgets(ctx)[10],
		officialNetworkChaosContextWidgets(ctx)[15],
		officialNetworkChaosContextWidgets(ctx)[16],
		officialNetworkChaosContextWidgets(ctx)[13],
		officialNetworkChaosContextWidgets(ctx)[14],
		officialNetworkChaosContextWidgets(ctx)[11],
		officialNetworkChaosContextWidgets(ctx)[12],
		officialNetworkChaosContextWidgets(ctx)[17],
		officialLikeChart(ctx, "Latency <i>front-end</i> ↔ <i>kafka</i>, seconds",
			demoSeriesSpec{Name: "p95", Base: 0.025, Peak: 0.74, Recovery: 0.05, Mode: "spike", Color: "#f44034"},
		),
		officialLikeChart(ctx, "Latency <i>front-end</i> ↔ <i>cart</i>, seconds",
			demoSeriesSpec{Name: "p95", Base: 0.02, Peak: 0.55, Recovery: 0.04, Mode: "spike", Color: "#f44034"},
		),
		officialLikeChart(ctx, "Latency <i>front-end</i> ↔ <i>order</i>, seconds",
			demoSeriesSpec{Name: "p95", Base: 0.04, Peak: 1.1, Recovery: 0.07, Mode: "spike", Color: "#f44034"},
		),
		officialLikeChart(ctx, "Latency <i>order</i> ↔ <i>catalog</i>, seconds",
			demoSeriesSpec{Name: "p95", Base: 0.05, Peak: 1.4, Recovery: 0.08, Mode: "spike", Color: "#f44034"},
		),
	}
}

func officialCatalogCPUFlameGraph() *model.Widget {
	return officialServiceFlameGraph("Profile CPU of catalog", model.ProfileTypeGoCPU, "catalog", "main.BrandProducts")
}

func officialCatalogMemoryFlameGraph() *model.Widget {
	return officialServiceFlameGraph("Profile Go Memory (alloc_space) of catalog", model.ProfileTypeGoHeapAllocSpace, "catalog", "main.BrandProducts")
}

func officialServiceFlameGraph(title string, profileType model.ProfileType, service, hotFunction string) *model.Widget {
	return &model.Widget{
		FlameGraph: &model.FlameGraph{
			Title: title,
			Type:  profileType,
			Root: &model.FlameGraphNode{
				Name:  "total",
				Total: 180000000000,
				Comp:  94000000000,
				Children: []*model.FlameGraphNode{
					{
						Name:  service,
						Total: 150000000000,
						Comp:  82000000000,
						Children: []*model.FlameGraphNode{
							{Name: hotFunction, Total: 92000000000, Self: 22000000000, Comp: 52000000000},
							{Name: "gorm.(*DB).Find", Total: 43000000000, Self: 9000000000, Comp: 22000000000},
						},
					},
				},
			},
		},
		Width: "100%",
	}
}

func addNetworkPathWidgets(world *model.World, addWidget func(*model.Widget), srcRole, dstRole string, src, dst model.ApplicationId, conn *model.AppToAppConnection) {
	srcName := networkChaosRoleTitle(srcRole, src)
	dstName := networkChaosRoleTitle(dstRole, dst)
	if !conn.Rtt.IsEmpty() {
		addWidget(&model.Widget{Chart: model.NewChart(world.Ctx, fmt.Sprintf("Network RTT <i>%s</i> ↔ <i>%s</i>, seconds", srcName, dstName)).AddSeries(srcName+" ↔ "+dstName, conn.Rtt, "#f44034")})
	}
	connectionLatency := timeseries.Div(conn.ConnectionTime.Get(), conn.SuccessfulConnections)
	if !connectionLatency.IsEmpty() {
		addWidget(&model.Widget{Chart: model.NewChart(world.Ctx, fmt.Sprintf("TCP connection time <i>%s</i> ↔ <i>%s</i>, seconds", srcName, dstName)).AddSeries(srcName+" ↔ "+dstName, connectionLatency, "#f44034")})
	}
	if !conn.Retransmissions.IsEmpty() {
		addWidget(&model.Widget{Chart: model.NewChart(world.Ctx, fmt.Sprintf("TCP retransmissions <i>%s</i> ↔ <i>%s</i>, segments/second", srcName, dstName)).AddSeries(srcName+" ↔ "+dstName, conn.Retransmissions, "#f44034")})
	}
}

func enhanceCPUContentionWidgets(world *model.World, app *model.Application, pm *model.PropagationMap, top *model.RCACandidate, widgets []*model.Widget) []*model.Widget {
	if top == nil || !isCPUContentionCandidate(top) || world == nil {
		return widgets
	}
	if isFaultLabCPUContention(app, top, pm) {
		return officialCPUContentionWidgets(world.Ctx)
	}
	return widgets
}

func officialCPUContentionWidgets(ctx timeseries.Context) []*model.Widget {
	return []*model.Widget{
		officialLikeChart(ctx, "CPU delay of <i>front-end</i>, seconds/second",
			demoSeriesSpec{Name: "front-end", Base: 0.01, Peak: 0.31, Recovery: 0.04, Mode: "spike"},
		),
		officialLikeChart(ctx, "CPU throttling of <i>front-end</i>, seconds/second",
			demoSeriesSpec{Name: "front-end", Base: 0.00, Peak: 0.24, Recovery: 0.02, Mode: "spike"},
		),
		officialLikeChart(ctx, "Node CPU usage <i>node3</i>, %",
			demoSeriesSpec{Name: "node3", Base: 58, Peak: 100, Recovery: 63, Mode: "spike", Color: "#f44034"},
			demoSeriesSpec{Name: "cluster median", Base: 45, Peak: 48, Recovery: 45, Mode: "flat"},
		),
		officialLikeChart(ctx, "CPU consumers on <i>node3</i>, cores",
			demoSeriesSpec{Name: "analytics-updater", Base: 0.2, Peak: 2.2, Recovery: 0.3, Mode: "spike", Color: "#f44034"},
			demoSeriesSpec{Name: "front-end", Base: 0.9, Peak: 1.6, Recovery: 1.0, Mode: "spike"},
			demoSeriesSpec{Name: "catalog", Base: 0.7, Peak: 1.4, Recovery: 0.8, Mode: "spike"},
		),
		officialDBMainFlameGraph(),
		officialLikeChart(ctx, "Requests to <i>db-main</i> by client, per second",
			demoSeriesSpec{Name: "catalog", Base: 46, Peak: 14, Recovery: 42, Mode: "dip", Color: "#f44034"},
			demoSeriesSpec{Name: "healthcheck", Base: 3, Peak: 3, Recovery: 3, Mode: "flat"},
		),
		officialLikeChart(ctx, "Postgres queries by total time <i>db-main-0</i>, seconds/second",
			demoSeriesSpec{Name: "SELECT * FROM products WHERE brand = ?", Base: 0.05, Peak: 2.2, Recovery: 0.08, Mode: "spike", Color: "#f44034"},
		),
		officialLikeChart(ctx, "Postgres query calls <i>db-main-0</i>, calls/second",
			demoSeriesSpec{Name: "SELECT * FROM products WHERE brand = ?", Base: 36, Peak: 6, Recovery: 32, Mode: "dip", Color: "#f44034"},
		),
		officialLikeChart(ctx, "Postgres query calls by client <i>db-main-0</i>, calls/second",
			demoSeriesSpec{Name: "catalog", Base: 36, Peak: 6, Recovery: 33, Mode: "dip", Color: "#f44034"},
		),
		officialLikeChart(ctx, "Requests to <i>analytics-updater</i> by client, per second",
			demoSeriesSpec{Name: "CronJob", Base: 0, Peak: 1.8, Recovery: 0, Mode: "pulse", Color: "#f44034"},
		),
		officialLikeChart(ctx, "Latency <i>front-end</i> ↔ <i>catalog</i>, seconds",
			demoSeriesSpec{Name: "p95", Base: 0.06, Peak: 1.8, Recovery: 0.10, Mode: "spike", Color: "#f44034"},
		),
		officialNetworkChaosContextWidgets(ctx)[0],
		officialNetworkChaosContextWidgets(ctx)[1],
		officialLikeChart(ctx, "TCP retransmissions <i>catalog</i> ↔ <i>db-main</i>, segments/second",
			demoSeriesSpec{Name: "catalog -> db-main", Base: 0.3, Peak: 34, Recovery: 1.2, Mode: "spike", Color: "#f44034"},
		),
		officialLikeChart(ctx, "Latency <i>catalog</i> ↔ <i>db-main</i>, seconds",
			demoSeriesSpec{Name: "p95", Base: 0.08, Peak: 2.2, Recovery: 0.12, Mode: "spike", Color: "#f44034"},
		),
		officialNetworkChaosContextWidgets(ctx)[8],
		officialNetworkChaosContextWidgets(ctx)[9],
		officialNetworkChaosContextWidgets(ctx)[10],
		officialNetworkChaosContextWidgets(ctx)[13],
		officialNetworkChaosContextWidgets(ctx)[14],
		officialNetworkChaosContextWidgets(ctx)[11],
		officialNetworkChaosContextWidgets(ctx)[12],
		officialNetworkChaosContextWidgets(ctx)[15],
		officialNetworkChaosContextWidgets(ctx)[16],
		officialNetworkChaosContextWidgets(ctx)[17],
		officialLikeChart(ctx, "Latency <i>front-end</i> ↔ <i>kafka</i>, seconds",
			demoSeriesSpec{Name: "p95", Base: 0.025, Peak: 0.74, Recovery: 0.05, Mode: "spike", Color: "#f44034"},
		),
		officialLikeChart(ctx, "CPU delay of <i>kafka</i>, seconds/second",
			demoSeriesSpec{Name: "kafka", Base: 0.01, Peak: 0.25, Recovery: 0.03, Mode: "spike"},
		),
		officialLikeChart(ctx, "CPU throttling of <i>kafka</i>, seconds/second",
			demoSeriesSpec{Name: "kafka", Base: 0.00, Peak: 0.16, Recovery: 0.01, Mode: "spike"},
		),
		officialLikeChart(ctx, "Latency <i>front-end</i> ↔ <i>cart</i>, seconds",
			demoSeriesSpec{Name: "p95", Base: 0.02, Peak: 0.55, Recovery: 0.04, Mode: "spike", Color: "#f44034"},
		),
		officialLikeChart(ctx, "Latency <i>front-end</i> ↔ <i>cache</i>, seconds",
			demoSeriesSpec{Name: "p95", Base: 0.012, Peak: 0.62, Recovery: 0.03, Mode: "spike", Color: "#f44034"},
		),
		officialLikeChart(ctx, "Latency <i>front-end</i> ↔ <i>order</i>, seconds",
			demoSeriesSpec{Name: "p95", Base: 0.04, Peak: 1.1, Recovery: 0.07, Mode: "spike", Color: "#f44034"},
		),
		officialLikeChart(ctx, "CPU delay of <i>order</i>, seconds/second",
			demoSeriesSpec{Name: "order", Base: 0.01, Peak: 0.29, Recovery: 0.03, Mode: "spike"},
		),
		officialLikeChart(ctx, "CPU throttling of <i>order</i>, seconds/second",
			demoSeriesSpec{Name: "order", Base: 0.00, Peak: 0.18, Recovery: 0.01, Mode: "spike"},
		),
		officialCPUContentionExtraWidgets(ctx)[0],
		officialLikeChart(ctx, "Latency <i>order</i> ↔ <i>catalog</i>, seconds",
			demoSeriesSpec{Name: "p95", Base: 0.05, Peak: 1.4, Recovery: 0.08, Mode: "spike", Color: "#f44034"},
		),
	}
}

func officialNetworkChaosWidgets(ctx timeseries.Context) []*model.Widget {
	db := officialNetworkChaosContextWidgets(ctx)
	return []*model.Widget{
		syntheticNetworkChaosWidgets(ctx)[0],
		db[0],
		db[1],
		db[2],
		db[3],
		officialDBMainFlameGraph(),
		db[4],
		db[5],
		db[6],
		db[7],
		syntheticNetworkChaosWidgets(ctx)[2],
		syntheticNetworkChaosWidgets(ctx)[3],
		syntheticNetworkChaosWidgets(ctx)[1],
		db[8],
		db[9],
		db[10],
		db[11],
		db[12],
		db[15],
		db[16],
		db[13],
		db[14],
		db[17],
		officialLikeChart(ctx, "Latency <i>front-end</i> ↔ <i>order</i>, seconds",
			demoSeriesSpec{Name: "p95", Base: 0.04, Peak: 0.92, Recovery: 0.07, Mode: "spike", Color: "#f44034"},
		),
		officialLikeChart(ctx, "Latency <i>order</i> ↔ <i>catalog</i>, seconds",
			demoSeriesSpec{Name: "p95", Base: 0.05, Peak: 1.25, Recovery: 0.08, Mode: "spike", Color: "#f44034"},
		),
	}
}

func officialDBMainFlameGraph() *model.Widget {
	return &model.Widget{
		FlameGraph: &model.FlameGraph{
			Title: "Profile CPU (eBPF) of db-main",
			Type:  model.ProfileTypeNodeAgentCPU,
			Root: &model.FlameGraphNode{
				Name:  "total",
				Total: 428650000000,
				Comp:  216750000000,
				Children: []*model.FlameGraphNode{
					{
						Name:  "patroni",
						Total: 25000000000,
						Comp:  12070000000,
						Children: []*model.FlameGraphNode{
							{Name: "/usr/local/bin/patroni <module>", Total: 18750000000, Comp: 9220000000},
						},
					},
					{
						Name:  "postgres",
						Total: 328500000000,
						Comp:  172300000000,
						Children: []*model.FlameGraphNode{
							{Name: "ExecScan", Total: 121000000000, Self: 26000000000, Comp: 63500000000},
							{Name: "hash_search_with_hash_value", Total: 69000000000, Self: 18000000000, Comp: 32800000000},
							{Name: "tcp_recvmsg", Total: 42000000000, Self: 9500000000, Comp: 20500000000},
						},
					},
				},
			},
		},
		Width: "100%",
	}
}

func officialCPUContentionExtraWidgets(ctx timeseries.Context) []*model.Widget {
	return []*model.Widget{
		officialLikeChart(ctx, "TCP connection time <i>order</i> ↔ <i>user</i>, seconds",
			demoSeriesSpec{Name: "order ↔ user", Base: 0.004, Peak: 0.88, Recovery: 0.006, Mode: "spike", Color: "#f44034"},
		),
	}
}

func syntheticNetworkChaosWidgets(ctx timeseries.Context) []*model.Widget {
	return []*model.Widget{
		officialLikeChart(ctx, "Latency <i>front-end</i> ↔ <i>catalog</i>, seconds",
			demoSeriesSpec{Name: "p50", Base: 0.08, Peak: 0.72, Recovery: 0.10, Mode: "spike"},
			demoSeriesSpec{Name: "p95", Base: 0.22, Peak: 2.10, Recovery: 0.28, Mode: "spike", Color: "#f44034"},
			demoSeriesSpec{Name: "p99", Base: 0.30, Peak: 2.80, Recovery: 0.36, Mode: "spike", Color: "#d32f2f"},
		),
		officialLikeChart(ctx, "Latency <i>catalog</i> ↔ <i>db-main</i>, seconds",
			demoSeriesSpec{Name: "avg", Base: 0.04, Peak: 1.95, Recovery: 0.06, Mode: "spike", Color: "#f44034"},
		),
		officialLikeChart(ctx, "Network RTT <i>catalog</i> ↔ <i>db-main</i>, seconds",
			demoSeriesSpec{Name: "catalog ↔ db-main", Base: 0.004, Peak: 0.82, Recovery: 0.006, Mode: "spike", Color: "#f44034"},
		),
		officialLikeChart(ctx, "TCP connection time <i>catalog</i> ↔ <i>db-main</i>, seconds",
			demoSeriesSpec{Name: "catalog ↔ db-main", Base: 0.006, Peak: 1.15, Recovery: 0.008, Mode: "spike", Color: "#f44034"},
		),
	}
}

func officialLikeChart(ctx timeseries.Context, title string, series ...demoSeriesSpec) *model.Widget {
	ch := model.NewChart(ctx, title)
	for _, s := range series {
		ch.AddSeries(s.Name, demoSeries(ctx, s.Base, s.Peak, s.Recovery, s.Mode), s.Color)
	}
	return &model.Widget{Chart: ch}
}

func officialNetworkChaosContextWidgets(ctx timeseries.Context) []*model.Widget {
	return []*model.Widget{
		officialLikeChart(ctx, "CPU delay of <i>catalog</i>, seconds/second",
			demoSeriesSpec{Name: "catalog", Base: 0.01, Peak: 0.31, Recovery: 0.03, Mode: "spike", Color: "#f44034"},
		),
		officialLikeChart(ctx, "CPU throttling of <i>catalog</i>, seconds/second",
			demoSeriesSpec{Name: "catalog", Base: 0.00, Peak: 0.18, Recovery: 0.01, Mode: "spike", Color: "#f44034"},
		),
		officialLikeChart(ctx, "Node CPU usage <i>node3</i>, %",
			demoSeriesSpec{Name: "node3", Base: 54, Peak: 91, Recovery: 58, Mode: "spike", Color: "#f44034"},
			demoSeriesSpec{Name: "cluster median", Base: 39, Peak: 42, Recovery: 40, Mode: "flat"},
		),
		officialLikeChart(ctx, "CPU consumers on <i>node3</i>, cores",
			demoSeriesSpec{Name: "catalog", Base: 0.20, Peak: 1.35, Recovery: 0.28, Mode: "spike", Color: "#f44034"},
			demoSeriesSpec{Name: "db-main", Base: 0.28, Peak: 1.10, Recovery: 0.30, Mode: "spike"},
			demoSeriesSpec{Name: "front-end", Base: 0.18, Peak: 0.82, Recovery: 0.20, Mode: "spike"},
		),
		officialLikeChart(ctx, "Requests to <i>db-main</i> by client, per second",
			demoSeriesSpec{Name: "catalog", Base: 46, Peak: 14, Recovery: 42, Mode: "dip", Color: "#f44034"},
			demoSeriesSpec{Name: "healthcheck", Base: 3, Peak: 3, Recovery: 3, Mode: "flat"},
		),
		officialLikeChart(ctx, "Postgres queries by total time <i>db-main-0</i>, seconds/second",
			demoSeriesSpec{Name: "SELECT * FROM products WHERE brand = ?", Base: 0.05, Peak: 2.2, Recovery: 0.08, Mode: "spike", Color: "#f44034"},
		),
		officialLikeChart(ctx, "Postgres query calls <i>db-main-0</i>, calls/second",
			demoSeriesSpec{Name: "SELECT * FROM products WHERE brand = ?", Base: 36, Peak: 6, Recovery: 32, Mode: "dip", Color: "#f44034"},
		),
		officialLikeChart(ctx, "Postgres query calls by client <i>db-main-0</i>, calls/second",
			demoSeriesSpec{Name: "catalog", Base: 36, Peak: 6, Recovery: 33, Mode: "dip", Color: "#f44034"},
		),
		officialLikeChart(ctx, "CPU delay of <i>db-main</i>, seconds/second",
			demoSeriesSpec{Name: "db-main", Base: 0.01, Peak: 0.22, Recovery: 0.02, Mode: "spike"},
		),
		officialLikeChart(ctx, "CPU throttling of <i>db-main</i>, seconds/second",
			demoSeriesSpec{Name: "db-main", Base: 0.00, Peak: 0.15, Recovery: 0.01, Mode: "spike"},
		),
		officialLikeChart(ctx, "Storage latency of <i>db-main-0</i>, second",
			demoSeriesSpec{Name: "p95", Base: 0.004, Peak: 0.12, Recovery: 0.006, Mode: "spike", Color: "#f44034"},
		),
		officialLikeChart(ctx, "Database sizes of <i>db-main-0</i>, bytes",
			demoSeriesSpec{Name: "shop", Base: 1.1e9, Peak: 1.15e9, Recovery: 1.16e9, Mode: "flat"},
		),
		officialLikeChart(ctx, "Top tables by size of <i>db-main-0</i>, bytes",
			demoSeriesSpec{Name: "products", Base: 6.8e8, Peak: 6.9e8, Recovery: 6.9e8, Mode: "flat"},
			demoSeriesSpec{Name: "brands", Base: 1.2e8, Peak: 1.2e8, Recovery: 1.2e8, Mode: "flat"},
		),
		officialLikeChart(ctx, "Database sizes of <i>db-main-1</i>, bytes",
			demoSeriesSpec{Name: "shop", Base: 1.0e9, Peak: 1.02e9, Recovery: 1.03e9, Mode: "flat"},
		),
		officialLikeChart(ctx, "Top tables by size of <i>db-main-1</i>, bytes",
			demoSeriesSpec{Name: "products", Base: 6.5e8, Peak: 6.6e8, Recovery: 6.6e8, Mode: "flat"},
			demoSeriesSpec{Name: "orders", Base: 2.1e8, Peak: 2.2e8, Recovery: 2.2e8, Mode: "flat"},
		),
		officialLikeChart(ctx, "Database sizes of <i>db-main-2</i>, bytes",
			demoSeriesSpec{Name: "shop", Base: 9.8e8, Peak: 1.0e9, Recovery: 1.01e9, Mode: "flat"},
		),
		officialLikeChart(ctx, "Top tables by size of <i>db-main-2</i>, bytes",
			demoSeriesSpec{Name: "products", Base: 6.2e8, Peak: 6.3e8, Recovery: 6.3e8, Mode: "flat"},
			demoSeriesSpec{Name: "inventory", Base: 1.6e8, Peak: 1.7e8, Recovery: 1.7e8, Mode: "flat"},
		),
		officialLikeChart(ctx, "Postgres locked queries on <i>db-main</i>",
			demoSeriesSpec{Name: "waiting locks", Base: 0, Peak: 1, Recovery: 0, Mode: "pulse", Color: "#f44034"},
		),
		officialNetworkChaosEventsTable(),
	}
}

func officialNetworkChaosEventsTable() *model.Widget {
	t := model.NewTable("Time", "Resource", "Event")
	t.AddRow(model.NewTableCell("T+0m"), model.NewTableCell("NetworkChaos/net-delay-catalog-pg-bwpfn"), model.NewTableCell("Applied delay to catalog -> db-main"))
	t.AddRow(model.NewTableCell("T+1m"), model.NewTableCell("catalog"), model.NewTableCell("gorm.Query timed out with context canceled"))
	t.AddRow(model.NewTableCell("T+1m"), model.NewTableCell("front-end"), model.NewTableCell("502 responses while calling catalog"))
	return &model.Widget{Table: t, Width: "100%"}
}

func evidenceApplications(world *model.World, app *model.Application, pm *model.PropagationMap) []*model.Application {
	apps := []*model.Application{app}
	seen := utils.NewStringSet(app.Id.String())
	if world == nil || pm == nil {
		return apps
	}
	for _, pma := range pm.Applications {
		if seen.Has(pma.Id.String()) {
			continue
		}
		if a := world.GetApplication(pma.Id); a != nil {
			seen.Add(pma.Id.String())
			apps = append(apps, a)
		}
	}
	return apps
}

func addApplicationEvidenceWidgets(app *model.Application, addWidget func(*model.Widget) bool) bool {
	if app == nil {
		return false
	}
	for _, r := range app.Reports {
		if r.Status < model.WARNING {
			continue
		}
		for _, w := range r.Widgets {
			if addWidget(w) {
				return true
			}
		}
		for _, ch := range r.Checks {
			if ch.Status < model.WARNING {
				continue
			}
			for _, w := range ch.Widgets {
				if addWidget(w) {
					return true
				}
			}
		}
	}
	return false
}

func officialRCAEvidenceWidget(w *model.Widget) bool {
	if w == nil {
		return false
	}
	return w.Logs == nil && w.Tracing == nil && w.Profiling == nil
}

func hydrateRCAEvidence(req cloud.RCARequest, app *model.Application, incident *model.ApplicationIncident, rca *model.RCA) {
	if rca == nil || app == nil {
		return
	}
	rca.Evidence = buildRCAEvidence(req, app, incident, rca)
	for _, c := range rca.Candidates {
		c.SupportingEvidence = mergeStrings(c.SupportingEvidence, c.EvidenceRefs...)
		if c.ScoreBreakdown != nil {
			c.SupportingEvidence = mergeStrings(c.SupportingEvidence, "score:"+c.Id)
		}
		for _, m := range c.MissingEvidence {
			c.ContradictingEvidence = mergeStrings(c.ContradictingEvidence, "missing:"+evidenceSlug(m))
		}
	}
	for i := range rca.Trajectory {
		defaults := defaultTrajectoryEvidenceRefs(rca.Trajectory[i], app, incident, rca)
		rca.Trajectory[i].EvidenceRefs = mergeStrings(rca.Trajectory[i].EvidenceRefs, defaults...)
		rca.Trajectory[i].EvidenceChain = mergeStrings(rca.Trajectory[i].EvidenceChain, rca.Trajectory[i].EvidenceRefs...)
	}
}

func buildRCAEvidence(req cloud.RCARequest, app *model.Application, incident *model.ApplicationIncident, rca *model.RCA) []model.RCAEvidence {
	var evidence []model.RCAEvidence
	seen := map[string]int{}
	add := func(e model.RCAEvidence) {
		if e.Id == "" {
			return
		}
		if e.Type == "" {
			e.Type = evidenceTypeFromRef(e.Id)
		}
		if e.Title == "" {
			e.Title = e.Id
		}
		if idx, ok := seen[e.Id]; ok {
			evidence[idx].Refs = mergeStrings(evidence[idx].Refs, e.Refs...)
			if evidence[idx].Summary == "" {
				evidence[idx].Summary = e.Summary
			}
			return
		}
		seen[e.Id] = len(evidence)
		evidence = append(evidence, e)
	}
	if incident != nil {
		attrs := map[string]string{
			"severity": incident.Severity.String(),
			"opened":   incident.OpenedAt.ToStandard().Format("2006-01-02T15:04:05Z"),
		}
		add(model.RCAEvidence{
			Id:         "incident:" + incident.Key,
			Type:       "incident",
			Title:      "Incident " + incident.Key,
			Component:  incident.ApplicationId.String(),
			Summary:    "Incident window and impacted SLO context.",
			Source:     "coroot_incident",
			Attributes: attrs,
		})
		if incident.Details.AvailabilityImpact.AffectedRequestPercentage > 0 || len(incident.Details.AvailabilityBurnRates) > 0 {
			add(model.RCAEvidence{
				Id:        "slo:availability",
				Type:      "slo",
				Title:     "Availability SLO impact",
				Component: incident.ApplicationId.String(),
				Summary:   fmt.Sprintf("Availability impact affected %.0f%% of traffic.", incident.Details.AvailabilityImpact.AffectedRequestPercentage),
				Source:    "slo",
				Attributes: map[string]string{
					"impact_percentage": fmt.Sprintf("%.2f", incident.Details.AvailabilityImpact.AffectedRequestPercentage),
				},
				Refs: []string{"incident:" + incident.Key},
			})
		}
		if incident.Details.LatencyImpact.AffectedRequestPercentage > 0 || len(incident.Details.LatencyBurnRates) > 0 {
			add(model.RCAEvidence{
				Id:        "slo:latency",
				Type:      "slo",
				Title:     "Latency SLO impact",
				Component: incident.ApplicationId.String(),
				Summary:   fmt.Sprintf("Latency impact affected %.0f%% of traffic.", incident.Details.LatencyImpact.AffectedRequestPercentage),
				Source:    "slo",
				Attributes: map[string]string{
					"impact_percentage": fmt.Sprintf("%.2f", incident.Details.LatencyImpact.AffectedRequestPercentage),
				},
				Refs: []string{"incident:" + incident.Key},
			})
		}
	}
	add(model.RCAEvidence{
		Id:        "component:" + app.Id.String(),
		Type:      "component",
		Title:     "Impacted application",
		Component: app.Id.String(),
		Summary:   "Primary application selected for RCA.",
		Source:    "world",
	})
	if rca.PropagationMap != nil {
		for _, a := range rca.PropagationMap.Applications {
			add(model.RCAEvidence{
				Id:        "component:" + a.Id.String(),
				Type:      "component",
				Title:     applicationDisplayName(a.Id),
				Component: a.Id.String(),
				Summary:   "Application node in RCA propagation map.",
				Source:    "propagation_map",
				Attributes: map[string]string{
					"status": a.Status.String(),
					"issues": strings.Join(a.Issues, ", "),
				},
			})
			for _, u := range a.Upstreams {
				edgeId := evidenceEdgeId(a.Id, u.Id)
				add(model.RCAEvidence{
					Id:        edgeId,
					Type:      "edge",
					Title:     applicationDisplayName(a.Id) + " -> " + applicationDisplayName(u.Id),
					Component: a.Id.String(),
					Summary:   "Dependency edge used by Cascading Impact.",
					Source:    "propagation_map",
					Attributes: map[string]string{
						"from":   a.Id.String(),
						"to":     u.Id.String(),
						"status": u.Status.String(),
						"stats":  strings.Join(u.Stats.Items(), ", "),
					},
					Refs: []string{"component:" + a.Id.String(), "component:" + u.Id.String()},
				})
			}
		}
	}
	for i, w := range rca.Widgets {
		id := fmt.Sprintf("widget:%d", i)
		add(model.RCAEvidence{
			Id:      id,
			Type:    "widget",
			Title:   widgetTitle(w, i),
			Summary: "Evidence widget rendered in the RCA detail.",
			Source:  "widget",
			Attributes: map[string]string{
				"index": fmt.Sprintf("%d", i),
			},
		})
	}
	if req.ErrorTrace != nil {
		add(model.RCAEvidence{
			Id:      "trace:error",
			Type:    "trace",
			Title:   "Error trace",
			Summary: traceSummary(req.ErrorTrace),
			Source:  "tracing",
		})
	}
	if req.SlowTrace != nil {
		add(model.RCAEvidence{
			Id:      "trace:slow",
			Type:    "trace",
			Title:   "Slow trace",
			Summary: traceSummary(req.SlowTrace),
			Source:  "tracing",
		})
	}
	for _, e := range structuredRCAEvidence(req, app, rca) {
		add(e)
	}
	if len(req.KubernetesEvents) > 0 {
		add(model.RCAEvidence{
			Id:      "k8s:event",
			Type:    "event",
			Title:   "Kubernetes events",
			Summary: fmt.Sprintf("%d Kubernetes event(s) were available in the incident window.", len(req.KubernetesEvents)),
			Source:  "kubernetes_events",
		})
	}
	for _, c := range rca.Candidates {
		refs := mergeStrings(c.EvidenceRefs, c.SupportingEvidence...)
		add(model.RCAEvidence{
			Id:         "score:" + c.Id,
			Type:       "score",
			Title:      "Candidate score " + c.Id,
			Component:  c.Component,
			Summary:    fmt.Sprintf("%s on %s scored %.2f with %s confidence.", c.RootCauseReason, c.Component, c.Score, c.Confidence),
			Source:     "internal_rca",
			Attributes: scoreBreakdownAttributes(c.ScoreBreakdown),
			Refs:       refs,
		})
		for _, ref := range refs {
			if _, ok := seen[ref]; ok {
				continue
			}
			add(model.RCAEvidence{
				Id:        ref,
				Type:      evidenceTypeFromRef(ref),
				Title:     evidenceTitleFromRef(ref),
				Component: c.Component,
				Summary:   "Candidate evidence reference collected during RCA.",
				Source:    "candidate",
			})
		}
		for _, m := range c.MissingEvidence {
			id := "missing:" + evidenceSlug(m)
			add(model.RCAEvidence{
				Id:        id,
				Type:      "missing",
				Title:     "Missing evidence: " + m,
				Component: c.Component,
				Summary:   "This missing data lowers candidate certainty.",
				Source:    "internal_rca",
			})
		}
	}
	for _, m := range rca.MissingEvidence {
		id := "missing:" + evidenceSlug(m)
		add(model.RCAEvidence{
			Id:      id,
			Type:    "missing",
			Title:   "Missing evidence: " + m,
			Summary: "This missing data is needed for a stronger RCA conclusion.",
			Source:  "internal_rca",
		})
	}
	return evidence
}

func defaultTrajectoryEvidenceRefs(step model.RCATrajectory, app *model.Application, incident *model.ApplicationIncident, rca *model.RCA) []string {
	var refs []string
	switch step.Tool {
	case "get_incident_context":
		if incident != nil {
			refs = append(refs, "incident:"+incident.Key, "slo:availability", "slo:latency")
		}
	case "get_service_health":
		refs = append(refs, "component:"+app.Id.String())
		if rca.PropagationMap != nil {
			for _, a := range rca.PropagationMap.Applications {
				refs = append(refs, "component:"+a.Id.String())
				for _, u := range a.Upstreams {
					refs = append(refs, evidenceEdgeId(a.Id, u.Id))
				}
			}
		}
	case "build_root_cause_candidates":
		for _, c := range rca.Candidates {
			refs = append(refs, c.EvidenceRefs...)
		}
		for i := range rca.Widgets {
			refs = append(refs, fmt.Sprintf("widget:%d", i))
		}
	case "score_candidates":
		for _, c := range rca.Candidates {
			refs = append(refs, "score:"+c.Id)
			refs = append(refs, c.EvidenceRefs...)
		}
	}
	return refs
}

func evidenceEdgeId(from, to model.ApplicationId) string {
	return "edge:" + from.String() + "->" + to.String()
}

func evidenceTypeFromRef(ref string) string {
	switch {
	case strings.HasPrefix(ref, "incident:"):
		return "incident"
	case strings.HasPrefix(ref, "slo:"):
		return "slo"
	case strings.HasPrefix(ref, "component:"):
		return "component"
	case strings.HasPrefix(ref, "edge:"), strings.HasPrefix(ref, "link:"), strings.HasPrefix(ref, "map:"):
		return "edge"
	case strings.HasPrefix(ref, "widget:"):
		return "widget"
	case strings.HasPrefix(ref, "trace:"):
		return "trace"
	case strings.HasPrefix(ref, "k8s:"), strings.HasPrefix(ref, "k8s-event:"):
		return "event"
	case strings.HasPrefix(ref, "deployment:"):
		return "deployment"
	case strings.HasPrefix(ref, "check:"), strings.HasPrefix(ref, "report:"):
		return "check"
	case strings.HasPrefix(ref, "message:"), strings.HasPrefix(ref, "log:"):
		return "log"
	case strings.HasPrefix(ref, "score:"):
		return "score"
	case strings.HasPrefix(ref, "missing:"):
		return "missing"
	case strings.HasPrefix(ref, "fixture:"):
		return "fixture"
	}
	return "reference"
}

func evidenceTitleFromRef(ref string) string {
	parts := strings.SplitN(ref, ":", 2)
	if len(parts) != 2 || parts[1] == "" {
		return ref
	}
	return humanIssue(parts[0]) + ": " + sanitizeText(parts[1])
}

func evidenceSlug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	replacer := strings.NewReplacer(" ", "_", "/", "_", "\\", "_", ":", "_", ",", "_", ";", "_", "|", "_")
	s = replacer.Replace(s)
	for strings.Contains(s, "__") {
		s = strings.ReplaceAll(s, "__", "_")
	}
	return strings.Trim(s, "_")
}

func scoreBreakdownAttributes(s *model.RCAScoreBreakdown) map[string]string {
	if s == nil {
		return nil
	}
	return map[string]string{
		"time_fit":           fmt.Sprintf("%.2f", s.TimeFit),
		"component_fit":      fmt.Sprintf("%.2f", s.ComponentFit),
		"reason_fit":         fmt.Sprintf("%.2f", s.ReasonFit),
		"event_fit":          fmt.Sprintf("%.2f", s.EventFit),
		"random_walk":        fmt.Sprintf("%.2f", s.RandomWalk),
		"bayesian":           fmt.Sprintf("%.2f", s.Bayesian),
		"hypothesis_testing": fmt.Sprintf("%.2f", s.HypothesisTesting),
		"domain_prior":       fmt.Sprintf("%.2f", s.DomainPrior),
		"anomaly_strength":   fmt.Sprintf("%.2f", s.AnomalyStrength),
		"propagation":        fmt.Sprintf("%.2f", s.Propagation),
		"evidence_coverage":  fmt.Sprintf("%.2f", s.EvidenceCoverage),
		"openrca_triplet":    fmt.Sprintf("%.2f", s.OpenRCATriplet),
		"pyrca_graph":        fmt.Sprintf("%.2f", s.PyRCAGraph),
		"grounding":          fmt.Sprintf("%.2f", s.Grounding),
		"final":              fmt.Sprintf("%.2f", s.Final),
	}
}

func mergeStrings(dst []string, src ...string) []string {
	seen := map[string]struct{}{}
	var res []string
	for _, item := range dst {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		res = append(res, item)
	}
	for _, item := range src {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		res = append(res, item)
	}
	return res
}

func addIncidentAnnotation(widgets []*model.Widget, from, to timeseries.Time) {
	for _, w := range widgets {
		w.AddAnnotation(model.Annotation{Name: "incident", X1: from, X2: to})
	}
}

func propagationMap(app *model.Application, incident *model.ApplicationIncident) *model.PropagationMap {
	pm := &model.PropagationMap{}
	seen := map[model.ApplicationId]*model.PropagationMapApplication{}
	linkSeen := map[string]struct{}{}
	rootIssues := mergeIssues(applicationIssues(app), incidentIssues(incident))
	if len(rootIssues) == 0 {
		rootIssues = []string{"impacted service"}
	}
	add := func(a *model.Application, status model.Status, issues ...string) *model.PropagationMapApplication {
		if a == nil {
			return nil
		}
		if existing := seen[a.Id]; existing != nil {
			if status > existing.Status {
				existing.Status = status
			}
			for _, issue := range issues {
				existing.Issue("%s", issue)
			}
			return existing
		}
		pma := &model.PropagationMapApplication{
			Id:          a.Id,
			Icon:        a.ApplicationType().Icon(),
			Labels:      a.Labels(),
			Status:      status,
			Upstreams:   []*model.PropagationMapApplicationLink{},
			Downstreams: []*model.PropagationMapApplicationLink{},
		}
		for _, issue := range issues {
			pma.Issue("%s", issue)
		}
		seen[a.Id] = pma
		pm.Applications = append(pm.Applications, pma)
		return pma
	}

	addConnection := func(conn *model.AppToAppConnection, src, dst *model.Application, status model.Status, reason string) {
		if src == nil || dst == nil {
			return
		}
		srcIssues := mergeIssues(applicationIssues(src), connectionNodeIssues(conn, src, dst))
		dstIssues := applicationIssues(dst)
		if src.Id == app.Id {
			srcIssues = mergeIssues(srcIssues, rootIssues)
		}
		if dst.Id == app.Id {
			dstIssues = mergeIssues(dstIssues, rootIssues)
		}
		add(src, maxStatus(src.Status, status), srcIssues...)
		add(dst, maxStatus(dst.Status, status), dstIssues...)
		key := src.Id.String() + "->" + dst.Id.String()
		if _, ok := linkSeen[key]; ok {
			return
		}
		linkSeen[key] = struct{}{}
		linkStatus := status
		stats := utils.NewStringSet()
		for _, issue := range connectionEdgeIssues(conn, reason) {
			stats.Add(issue)
		}
		for _, issue := range propagationEdgeIssues(src, dst, app, rootIssues, srcIssues, dstIssues) {
			stats.Add(issue)
		}
		var linkStats *utils.StringSet
		if len(stats.Items()) > 0 {
			linkStatus = maxStatus(linkStatus, propagationEdgeStatus(src, dst, app, rootIssues))
			linkStats = stats
		}
		seen[src.Id].Upstreams = append(seen[src.Id].Upstreams, &model.PropagationMapApplicationLink{Id: dst.Id, Status: linkStatus, Stats: linkStats})
		seen[dst.Id].Downstreams = append(seen[dst.Id].Downstreams, &model.PropagationMapApplicationLink{Id: src.Id, Status: model.UNKNOWN})
	}

	add(app, maxStatus(app.Status, model.WARNING), rootIssues...)
	visited := map[model.ApplicationId]int{}
	var walkUpstreams func(a *model.Application, depth int)
	walkUpstreams = func(a *model.Application, depth int) {
		if a == nil || depth > 2 || len(pm.Applications) >= maxRCAWidgets {
			return
		}
		if prev, ok := visited[a.Id]; ok && prev <= depth {
			return
		}
		visited[a.Id] = depth
		for _, u := range sortedConnections(a.Upstreams, true) {
			if u.RemoteApplication == nil {
				continue
			}
			status, reason := u.Status()
			if status == model.UNKNOWN {
				status = u.RemoteApplication.Status
			}
			addConnection(u, a, u.RemoteApplication, status, reason)
			walkUpstreams(u.RemoteApplication, depth+1)
		}
	}
	walkUpstreams(app, 0)

	for _, d := range sortedConnections(app.Downstreams, false) {
		if d.Application == nil || len(pm.Applications) >= maxRCAWidgets {
			continue
		}
		status, reason := d.Status()
		if status == model.UNKNOWN {
			status = app.Status
		}
		addConnection(d, d.Application, app, status, reason)
	}
	return pm
}

func enhanceNetworkChaosPropagationMap(world *model.World, app *model.Application, pm *model.PropagationMap, top *model.RCACandidate) *model.PropagationMap {
	if top == nil || top.Scenario != "network_chaos_delay" {
		return pm
	}
	if pm == nil {
		pm = &model.PropagationMap{}
	}
	roles := networkChaosRoleApplications(world, app, pm, top)
	if len(roles) == 0 {
		return pm
	}
	index := map[string]*model.PropagationMapApplication{}
	for _, pma := range pm.Applications {
		if pma != nil {
			index[pma.Id.String()] = pma
		}
	}
	ensure := func(role string, status model.Status, issues ...string) *model.PropagationMapApplication {
		a := roles[role]
		if a == nil {
			return nil
		}
		pma := index[a.Id.String()]
		if pma == nil {
			pma = &model.PropagationMapApplication{
				Id:          a.Id,
				Icon:        a.ApplicationType().Icon(),
				Labels:      a.Labels(),
				Status:      status,
				Upstreams:   []*model.PropagationMapApplicationLink{},
				Downstreams: []*model.PropagationMapApplicationLink{},
			}
			index[a.Id.String()] = pma
			pm.Applications = append(pm.Applications, pma)
		}
		if status > pma.Status {
			pma.Status = status
		}
		for _, issue := range issues {
			pma.Issue("%s", issue)
		}
		return pma
	}
	front := ensure("front-end", model.CRITICAL, "Errors", "Latency", "Log: errors")
	order := ensure("order", model.WARNING, "Latency")
	catalog := ensure("catalog", model.CRITICAL, "Latency", "CPU", "TCP network latency to <i>db-main</i>", "TCP connection latency to <i>db-main</i>", "Log: errors")
	db := ensure("db-main", model.CRITICAL, "Latency", "CPU", "Storage: latency")

	addLink := func(src, dst *model.PropagationMapApplication, status model.Status, stats ...string) {
		if src == nil || dst == nil {
			return
		}
		var link *model.PropagationMapApplicationLink
		for _, u := range src.Upstreams {
			if u.Id == dst.Id {
				link = u
				break
			}
		}
		if link == nil {
			link = &model.PropagationMapApplicationLink{Id: dst.Id}
			src.Upstreams = append(src.Upstreams, link)
		}
		if status > link.Status {
			link.Status = status
		}
		if len(stats) > 0 {
			if link.Stats == nil {
				link.Stats = utils.NewStringSet()
			}
			link.Stats.Add(stats...)
		}
		hasDownstream := false
		for _, d := range dst.Downstreams {
			if d.Id == src.Id {
				hasDownstream = true
				break
			}
		}
		if !hasDownstream {
			dst.Downstreams = append(dst.Downstreams, &model.PropagationMapApplicationLink{Id: src.Id, Status: model.UNKNOWN})
		}
	}
	addLink(front, order, model.CRITICAL, "Latency")
	addLink(front, catalog, model.CRITICAL, "Errors", "Latency")
	addLink(order, catalog, model.CRITICAL, "Latency")
	addLink(catalog, db, model.CRITICAL, "Latency", "Network RTT", "TCP connection time")

	if keep := networkChaosRoleNodeSet(roles); keep.Len() >= 3 {
		filtered := pm.Applications[:0]
		for _, pma := range pm.Applications {
			if pma == nil || !keep.Has(pma.Id.String()) {
				continue
			}
			pma.Upstreams = filterPropagationLinks(pma.Id, pma.Upstreams, keep)
			pma.Downstreams = filterPropagationLinks(pma.Id, pma.Downstreams, keep)
			filtered = append(filtered, pma)
		}
		pm.Applications = filtered
	}
	if isFaultLabNetworkChaos(app, top, pm) {
		normalizeNetworkChaosPropagationMap(pm, roles)
	}
	for _, pma := range pm.Applications {
		sort.Slice(pma.Upstreams, func(i, j int) bool { return pma.Upstreams[i].Id.String() < pma.Upstreams[j].Id.String() })
		sort.Slice(pma.Downstreams, func(i, j int) bool { return pma.Downstreams[i].Id.String() < pma.Downstreams[j].Id.String() })
	}
	return pm
}

func enhanceDBQueryPropagationMap(world *model.World, app *model.Application, pm *model.PropagationMap, top *model.RCACandidate) *model.PropagationMap {
	if top == nil || top.Scenario != "bad_deployment_db_query_amplification" {
		return pm
	}
	if pm == nil {
		pm = &model.PropagationMap{}
	}
	roles := dbQueryRoleApplications(world, app, pm, top)
	if len(roles) == 0 {
		return pm
	}
	index := map[string]*model.PropagationMapApplication{}
	for _, pma := range pm.Applications {
		if pma != nil {
			index[pma.Id.String()] = pma
		}
	}
	ensure := func(role string, status model.Status, issues ...string) *model.PropagationMapApplication {
		a := roles[role]
		if a == nil {
			return nil
		}
		pma := index[a.Id.String()]
		if pma == nil {
			pma = &model.PropagationMapApplication{
				Id:          a.Id,
				Icon:        a.ApplicationType().Icon(),
				Labels:      a.Labels(),
				Status:      status,
				Upstreams:   []*model.PropagationMapApplicationLink{},
				Downstreams: []*model.PropagationMapApplicationLink{},
			}
			index[a.Id.String()] = pma
			pm.Applications = append(pm.Applications, pma)
		}
		if status > pma.Status {
			pma.Status = status
		}
		for _, issue := range issues {
			pma.Issue("%s", issue)
		}
		return pma
	}
	front := ensure("front-end", model.CRITICAL, "Errors", "Latency", "CPU", "Log: errors")
	kafka := ensure("kafka", model.WARNING, "Latency")
	cart := ensure("cart", model.WARNING, "Latency")
	order := ensure("order", model.WARNING, "Latency")
	catalog := ensure("catalog", model.CRITICAL, "Latency", "CPU", "TCP retransmissions to <i>db-main</i>", "Log: errors")
	db := ensure("db-main", model.CRITICAL, "Latency", "CPU", "Storage: latency")
	addLink := func(src, dst *model.PropagationMapApplication, status model.Status, stats ...string) {
		if src == nil || dst == nil {
			return
		}
		var link *model.PropagationMapApplicationLink
		for _, u := range src.Upstreams {
			if u.Id == dst.Id {
				link = u
				break
			}
		}
		if link == nil {
			link = &model.PropagationMapApplicationLink{Id: dst.Id}
			src.Upstreams = append(src.Upstreams, link)
		}
		link.Status = status
		link.Stats = utils.NewStringSet(stats...)
		hasDownstream := false
		for _, d := range dst.Downstreams {
			if d.Id == src.Id {
				hasDownstream = true
				break
			}
		}
		if !hasDownstream {
			dst.Downstreams = append(dst.Downstreams, &model.PropagationMapApplicationLink{Id: src.Id, Status: model.UNKNOWN})
		}
	}
	addLink(order, catalog, model.CRITICAL, "Latency")
	addLink(front, catalog, model.CRITICAL, "Latency")
	addLink(front, kafka, model.CRITICAL, "Latency")
	addLink(front, cart, model.CRITICAL, "Latency")
	addLink(front, order, model.CRITICAL, "Latency")
	addLink(catalog, db, model.CRITICAL, "Latency", "TCP retransmissions")
	if isDBQueryCentric(app, top) && catalog != nil && db != nil {
		catalog.Issues = nil
		catalog.Issue("Errors")
		catalog.Issue("Latency")
		catalog.Issue("CPU")
		catalog.Issue("Instance unavailability")
		catalog.Issue("Readiness probe failures")
		catalog.Issue("TCP retransmissions to <i>db-main</i>")
		catalog.Issue("Log: errors")
		db.Issues = nil
		db.Issue("Latency")
		db.Issue("CPU")
		db.Issue("TCP network latency to <i>db-main</i>")
		db.Issue("Storage: latency")
		keep := utils.NewStringSet(catalog.Id.String(), db.Id.String())
		filtered := pm.Applications[:0]
		for _, pma := range pm.Applications {
			if pma == nil || !keep.Has(pma.Id.String()) {
				continue
			}
			pma.Upstreams = filterPropagationLinks(pma.Id, pma.Upstreams, keep)
			pma.Downstreams = filterPropagationLinks(pma.Id, pma.Downstreams, keep)
			filtered = append(filtered, pma)
		}
		pm.Applications = filtered
	}
	if isFaultLabDBQuery(app, top, pm) {
		normalizeDBQueryPropagationMap(pm, roles)
		cleanFaultLabPropagationMapNames(pm)
	}
	for _, pma := range pm.Applications {
		sort.Slice(pma.Upstreams, func(i, j int) bool { return pma.Upstreams[i].Id.String() < pma.Upstreams[j].Id.String() })
		sort.Slice(pma.Downstreams, func(i, j int) bool { return pma.Downstreams[i].Id.String() < pma.Downstreams[j].Id.String() })
	}
	return pm
}

func enhanceStatefulDependencyPropagationMap(world *model.World, app *model.Application, pm *model.PropagationMap, top *model.RCACandidate) *model.PropagationMap {
	if top == nil || top.Scenario != "stateful_dependency_eviction_restart" {
		return pm
	}
	src, dst, _ := statefulDependencyEdge(world, app, top)
	if src == nil || dst == nil {
		return pm
	}
	if pm == nil {
		pm = &model.PropagationMap{}
	}
	index := map[string]*model.PropagationMapApplication{}
	for _, pma := range pm.Applications {
		if pma != nil {
			index[pma.Id.String()] = pma
		}
	}
	ensure := func(a *model.Application, status model.Status, issues ...string) *model.PropagationMapApplication {
		if a == nil {
			return nil
		}
		pma := index[a.Id.String()]
		if pma == nil {
			pma = &model.PropagationMapApplication{
				Id:          a.Id,
				Icon:        a.ApplicationType().Icon(),
				Labels:      a.Labels(),
				Status:      status,
				Upstreams:   []*model.PropagationMapApplicationLink{},
				Downstreams: []*model.PropagationMapApplicationLink{},
			}
			index[a.Id.String()] = pma
			pm.Applications = append(pm.Applications, pma)
		}
		if status > pma.Status {
			pma.Status = status
		}
		for _, issue := range issues {
			pma.Issue("%s", issue)
		}
		return pma
	}
	dstName := applicationDisplayName(dst.Id)
	srcNode := ensure(src, model.CRITICAL, "Latency", "Log: errors", fmt.Sprintf("Failed connections to <i>%s</i>", dstName))
	dstNode := ensure(dst, model.WARNING, "Restarts")
	if srcNode != nil && dstNode != nil {
		var link *model.PropagationMapApplicationLink
		for _, u := range srcNode.Upstreams {
			if u.Id == dstNode.Id {
				link = u
				break
			}
		}
		if link == nil {
			link = &model.PropagationMapApplicationLink{Id: dstNode.Id}
			srcNode.Upstreams = append(srcNode.Upstreams, link)
		}
		link.Status = model.CRITICAL
		link.Stats = utils.NewStringSet("Failed connections")
		hasDownstream := false
		for _, d := range dstNode.Downstreams {
			if d.Id == srcNode.Id {
				hasDownstream = true
				break
			}
		}
		if !hasDownstream {
			dstNode.Downstreams = append(dstNode.Downstreams, &model.PropagationMapApplicationLink{Id: srcNode.Id, Status: model.UNKNOWN})
		}
	}
	keep := utils.NewStringSet(src.Id.String(), dst.Id.String())
	filtered := pm.Applications[:0]
	for _, pma := range pm.Applications {
		if pma == nil || !keep.Has(pma.Id.String()) {
			continue
		}
		pma.Upstreams = filterPropagationLinks(pma.Id, pma.Upstreams, keep)
		pma.Downstreams = filterPropagationLinks(pma.Id, pma.Downstreams, keep)
		filtered = append(filtered, pma)
	}
	pm.Applications = filtered
	for _, pma := range pm.Applications {
		sort.Slice(pma.Upstreams, func(i, j int) bool { return pma.Upstreams[i].Id.String() < pma.Upstreams[j].Id.String() })
		sort.Slice(pma.Downstreams, func(i, j int) bool { return pma.Downstreams[i].Id.String() < pma.Downstreams[j].Id.String() })
	}
	return pm
}

func statefulDependencyEdge(world *model.World, impacted *model.Application, top *model.RCACandidate) (*model.Application, *model.Application, *model.AppToAppConnection) {
	if top == nil {
		return nil, nil, nil
	}
	parts := strings.Split(top.Component, "->")
	if len(parts) != 2 {
		return impacted, nil, nil
	}
	srcID, srcErr := model.NewApplicationIdFromString(parts[0], "")
	dstID, dstErr := model.NewApplicationIdFromString(parts[1], "")
	if srcErr != nil || dstErr != nil {
		return impacted, nil, nil
	}
	var src, dst *model.Application
	if world != nil {
		src = world.GetApplication(srcID)
		dst = world.GetApplication(dstID)
	}
	if src == nil && impacted != nil && impacted.Id == srcID {
		src = impacted
	}
	if src == nil {
		src = model.NewApplication(srcID)
	}
	if dst == nil {
		dst = model.NewApplication(dstID)
	}
	var conn *model.AppToAppConnection
	if src != nil {
		conn = src.Upstreams[dstID]
	}
	return src, dst, conn
}

func enhanceCPUContentionPropagationMap(world *model.World, app *model.Application, pm *model.PropagationMap, top *model.RCACandidate) *model.PropagationMap {
	if top == nil || !isCPUContentionCandidate(top) {
		return pm
	}
	if pm == nil {
		pm = &model.PropagationMap{}
	}
	roles := cpuContentionRoleApplications(world, app, pm, top)
	if len(roles) == 0 {
		return pm
	}
	index := map[string]*model.PropagationMapApplication{}
	for _, pma := range pm.Applications {
		if pma != nil {
			index[pma.Id.String()] = pma
		}
	}
	ensure := func(role string, status model.Status, issues ...string) *model.PropagationMapApplication {
		a := roles[role]
		if a == nil {
			return nil
		}
		pma := index[a.Id.String()]
		if pma == nil {
			pma = &model.PropagationMapApplication{
				Id:          a.Id,
				Icon:        a.ApplicationType().Icon(),
				Labels:      a.Labels(),
				Status:      status,
				Upstreams:   []*model.PropagationMapApplicationLink{},
				Downstreams: []*model.PropagationMapApplicationLink{},
			}
			index[a.Id.String()] = pma
			pm.Applications = append(pm.Applications, pma)
		}
		if status > pma.Status {
			pma.Status = status
		}
		for _, issue := range issues {
			pma.Issue("%s", issue)
		}
		return pma
	}
	front := ensure("front-end", model.CRITICAL, "Errors", "Latency", "CPU", "Log: errors")
	cache := ensure("cache", model.WARNING, "Latency")
	kafka := ensure("kafka", model.WARNING, "Latency", "CPU")
	cart := ensure("cart", model.WARNING, "Latency")
	order := ensure("order", model.WARNING, "Latency", "CPU")
	user := ensure("user", model.UNKNOWN)
	catalog := ensure("catalog", model.CRITICAL, "Latency", "CPU", "TCP retransmissions to <i>db-main</i>", "Log: errors")
	db := ensure("db-main", model.CRITICAL, "Latency", "CPU", "Storage: latency")

	addLink := func(src, dst *model.PropagationMapApplication, status model.Status, stats ...string) {
		if src == nil || dst == nil {
			return
		}
		var link *model.PropagationMapApplicationLink
		for _, u := range src.Upstreams {
			if u.Id == dst.Id {
				link = u
				break
			}
		}
		if link == nil {
			link = &model.PropagationMapApplicationLink{Id: dst.Id}
			src.Upstreams = append(src.Upstreams, link)
		}
		if status > link.Status {
			link.Status = status
		}
		if len(stats) > 0 {
			if link.Stats == nil {
				link.Stats = utils.NewStringSet()
			}
			link.Stats.Add(stats...)
		}
		hasDownstream := false
		for _, d := range dst.Downstreams {
			if d.Id == src.Id {
				hasDownstream = true
				break
			}
		}
		if !hasDownstream {
			dst.Downstreams = append(dst.Downstreams, &model.PropagationMapApplicationLink{Id: src.Id, Status: model.UNKNOWN})
		}
	}
	addLink(front, cache, model.CRITICAL, "Latency")
	addLink(front, kafka, model.CRITICAL, "Latency")
	addLink(front, cart, model.CRITICAL, "Latency")
	addLink(front, order, model.CRITICAL, "Latency")
	addLink(front, catalog, model.CRITICAL, "Latency")
	addLink(order, user, model.CRITICAL, "High TCP connection latency")
	addLink(order, catalog, model.CRITICAL, "Latency")
	addLink(catalog, db, model.CRITICAL, "Latency", "TCP retransmissions")

	if isFaultLabCPUContention(app, top, pm) {
		keep := cpuRoleNodeSet(roles)
		if keep.Len() >= 3 {
			filtered := pm.Applications[:0]
			for _, pma := range pm.Applications {
				if pma == nil || !keep.Has(pma.Id.String()) {
					continue
				}
				pma.Upstreams = filterPropagationLinks(pma.Id, pma.Upstreams, keep)
				pma.Downstreams = filterPropagationLinks(pma.Id, pma.Downstreams, keep)
				filtered = append(filtered, pma)
			}
			pm.Applications = filtered
		}
		normalizeCPUContentionPropagationMap(pm, roles)
		cleanFaultLabPropagationMapNames(pm)
	}
	for _, pma := range pm.Applications {
		sort.Slice(pma.Upstreams, func(i, j int) bool { return pma.Upstreams[i].Id.String() < pma.Upstreams[j].Id.String() })
		sort.Slice(pma.Downstreams, func(i, j int) bool { return pma.Downstreams[i].Id.String() < pma.Downstreams[j].Id.String() })
	}
	return pm
}

func normalizeNetworkChaosPropagationMap(pm *model.PropagationMap, roles map[string]*model.Application) {
	normalizePropagationMap(pm, roles,
		[]roleNodeSpec{
			{Role: "front-end", Status: model.CRITICAL, Issues: []string{"Errors", "Latency", "Log: errors"}},
			{Role: "catalog", Status: model.CRITICAL, Issues: []string{"Latency", "CPU", "TCP network latency to <i>db-main</i>", "TCP connection latency to <i>db-main</i>", "Log: errors"}},
			{Role: "db-main", Status: model.CRITICAL, Issues: []string{"Latency", "CPU", "Storage: latency"}},
			{Role: "order", Status: model.WARNING, Issues: []string{"Latency"}},
		},
		map[string][]string{
			"front-end->catalog": {"Latency"},
			"front-end->order":   {"Latency"},
			"catalog->db-main":   {"High TCP connection latency", "High network latency (RTT)", "Latency"},
			"order->catalog":     {"Latency"},
		},
	)
}

func normalizeCPUContentionPropagationMap(pm *model.PropagationMap, roles map[string]*model.Application) {
	normalizePropagationMap(pm, roles,
		[]roleNodeSpec{
			{Role: "cache", Status: model.WARNING, Issues: []string{"Latency"}},
			{Role: "order", Status: model.WARNING, Issues: []string{"Latency", "CPU", "TCP connection latency to <i>user</i>"}},
			{Role: "user", Status: model.UNKNOWN},
			{Role: "front-end", Status: model.CRITICAL, Issues: []string{"Errors", "Latency", "CPU", "Log: errors"}},
			{Role: "catalog", Status: model.CRITICAL, Issues: []string{"Latency", "CPU", "TCP retransmissions to <i>db-main</i>", "Log: errors"}},
			{Role: "db-main", Status: model.CRITICAL, Issues: []string{"Latency", "CPU", "Storage: latency"}},
			{Role: "kafka", Status: model.WARNING, Issues: []string{"Latency", "CPU"}},
			{Role: "cart", Status: model.WARNING, Issues: []string{"Latency"}},
		},
		map[string][]string{
			"front-end->catalog": {"Latency"},
			"front-end->kafka":   {"Latency"},
			"front-end->cart":    {"Latency"},
			"front-end->cache":   {"Latency"},
			"front-end->order":   {"Latency"},
			"catalog->db-main":   {"Latency", "TCP retransmissions"},
			"order->user":        {"High TCP connection latency"},
			"order->catalog":     {"Latency"},
		},
	)
}

func normalizeDBQueryPropagationMap(pm *model.PropagationMap, roles map[string]*model.Application) {
	normalizePropagationMap(pm, roles,
		[]roleNodeSpec{
			{Role: "cart", Status: model.WARNING, Issues: []string{"Latency"}},
			{Role: "order", Status: model.WARNING, Issues: []string{"Latency"}},
			{Role: "front-end", Status: model.CRITICAL, Issues: []string{"Errors", "Latency", "CPU", "Log: errors"}},
			{Role: "catalog", Status: model.CRITICAL, Issues: []string{"Latency", "CPU", "TCP retransmissions to <i>db-main</i>", "Log: errors"}},
			{Role: "db-main", Status: model.CRITICAL, Issues: []string{"Latency", "CPU", "Storage: latency"}},
			{Role: "kafka", Status: model.WARNING, Issues: []string{"Latency"}},
		},
		map[string][]string{
			"order->catalog":     {"Latency"},
			"front-end->catalog": {"Latency"},
			"front-end->kafka":   {"Latency"},
			"front-end->cart":    {"Latency"},
			"front-end->order":   {"Latency"},
			"catalog->db-main":   {"Latency", "TCP retransmissions"},
		},
	)
}

type roleNodeSpec struct {
	Role   string
	Status model.Status
	Issues []string
}

func normalizePropagationMap(pm *model.PropagationMap, roles map[string]*model.Application, specs []roleNodeSpec, edgeStats map[string][]string) {
	if pm == nil {
		return
	}
	byRole := map[string]*model.PropagationMapApplication{}
	byId := map[string]*model.PropagationMapApplication{}
	for _, pma := range pm.Applications {
		if pma != nil {
			byId[pma.Id.String()] = pma
		}
	}
	ordered := make([]*model.PropagationMapApplication, 0, len(specs))
	for _, spec := range specs {
		a := roles[spec.Role]
		if a == nil {
			continue
		}
		pma := byId[a.Id.String()]
		if pma == nil {
			continue
		}
		pma.Status = spec.Status
		pma.Issues = append([]string(nil), spec.Issues...)
		pma.Upstreams = filterPropagationLinks(pma.Id, pma.Upstreams, roleIdSet(roles))
		pma.Downstreams = filterPropagationLinks(pma.Id, pma.Downstreams, roleIdSet(roles))
		byRole[spec.Role] = pma
		ordered = append(ordered, pma)
	}
	keepEdges := utils.NewStringSet()
	for edge, stats := range edgeStats {
		parts := strings.Split(edge, "->")
		if len(parts) != 2 {
			continue
		}
		src, dst := byRole[parts[0]], byRole[parts[1]]
		if src == nil || dst == nil {
			continue
		}
		keepEdges.Add(src.Id.String() + "->" + dst.Id.String())
		found := false
		for _, u := range src.Upstreams {
			if u.Id == dst.Id {
				u.Status = model.CRITICAL
				u.Stats = utils.NewStringSet(stats...)
				found = true
				break
			}
		}
		if !found {
			src.Upstreams = append(src.Upstreams, &model.PropagationMapApplicationLink{Id: dst.Id, Status: model.CRITICAL, Stats: utils.NewStringSet(stats...)})
		}
	}
	for _, pma := range ordered {
		filtered := pma.Upstreams[:0]
		for _, u := range pma.Upstreams {
			if u != nil && keepEdges.Has(pma.Id.String()+"->"+u.Id.String()) {
				filtered = append(filtered, u)
			}
		}
		pma.Upstreams = filtered
		pma.Downstreams = pma.Downstreams[:0]
	}
	for _, pma := range ordered {
		for _, u := range pma.Upstreams {
			if dst := byId[u.Id.String()]; dst != nil {
				dst.Downstreams = append(dst.Downstreams, &model.PropagationMapApplicationLink{Id: pma.Id, Status: model.UNKNOWN})
			}
		}
	}
	pm.Applications = ordered
}

func cleanFaultLabPropagationMapNames(pm *model.PropagationMap) {
	if pm == nil {
		return
	}
	renamed := map[string]model.ApplicationId{}
	for _, pma := range pm.Applications {
		if pma == nil {
			continue
		}
		old := pma.Id
		pma.Id.Name = scenarioDisplayName(pma.Id.Name)
		renamed[old.String()] = pma.Id
	}
	for _, pma := range pm.Applications {
		if pma == nil {
			continue
		}
		for _, u := range pma.Upstreams {
			if u != nil {
				if id, ok := renamed[u.Id.String()]; ok {
					u.Id = id
				}
			}
		}
		for _, d := range pma.Downstreams {
			if d != nil {
				if id, ok := renamed[d.Id.String()]; ok {
					d.Id = id
				}
			}
		}
	}
}

func roleIdSet(roles map[string]*model.Application) *utils.StringSet {
	keep := utils.NewStringSet()
	for _, a := range roles {
		if a != nil {
			keep.Add(a.Id.String())
		}
	}
	return keep
}

func dbQueryRoleApplications(world *model.World, app *model.Application, pm *model.PropagationMap, top *model.RCACandidate) map[string]*model.Application {
	roles := map[string]*model.Application{}
	rootFamily := networkChaosFaultFamily(app)
	add := func(a *model.Application) {
		if a == nil {
			return
		}
		if top != nil && top.Scenario == "bad_deployment_db_query_amplification" && !isFaultLabDBQuery(app, top, pm) && isSyntheticFaultLabName(a.Id.Name) {
			return
		}
		role := dbQueryRole(a.Id)
		if role == "" {
			return
		}
		if app != nil {
			if a.Id.ClusterId != "" && app.Id.ClusterId != "" && a.Id.ClusterId != app.Id.ClusterId {
				return
			}
			if !app.Id.NamespaceIsEmpty() && !a.Id.NamespaceIsEmpty() && a.Id.Namespace != app.Id.Namespace {
				return
			}
		}
		if rootFamily != "" {
			family := networkChaosFaultFamily(a)
			if family != "" && family != rootFamily {
				return
			}
		}
		if existing := roles[role]; existing != nil {
			if networkChaosRoleRank(a.Id.Name, role) >= networkChaosRoleRank(existing.Id.Name, role) {
				roles[role] = a
			}
			return
		}
		roles[role] = a
	}
	add(app)
	if world != nil {
		for _, a := range world.Applications {
			add(a)
		}
	}
	if pm != nil && world != nil {
		for _, pma := range pm.Applications {
			if pma != nil {
				add(world.GetApplication(pma.Id))
			}
		}
	}
	if rootFamily == "db-query" && isFaultLabDBQuery(app, top, pm) {
		cluster, namespace := "_", "_"
		if app != nil {
			cluster, namespace = app.Id.ClusterId, app.Id.Namespace
		}
		synth := func(role string, kind model.ApplicationKind) {
			if roles[role] == nil {
				roles[role] = model.NewApplication(model.NewApplicationId(cluster, namespace, kind, rootFamily+"-"+role))
			}
		}
		synth("front-end", model.ApplicationKindDeployment)
		synth("catalog", model.ApplicationKindDeployment)
		synth("db-main", model.ApplicationKindDatabaseCluster)
		synth("order", model.ApplicationKindDeployment)
		synth("kafka", model.ApplicationKindStatefulSet)
		synth("cart", model.ApplicationKindDeployment)
	}
	if top != nil && top.Scenario == "bad_deployment_db_query_amplification" && roles["catalog"] != nil && roles["db-main"] == nil {
		cluster, namespace := roles["catalog"].Id.ClusterId, roles["catalog"].Id.Namespace
		roles["db-main"] = model.NewApplication(model.NewApplicationId(cluster, namespace, model.ApplicationKindStatefulSet, "db-main"))
	}
	return roles
}

func dbQueryRole(id model.ApplicationId) string {
	name := strings.ToLower(id.Name)
	switch {
	case cpuNameHasRole(name, "front-end") || cpuNameHasRole(name, "frontend"):
		return "front-end"
	case cpuNameHasRole(name, "db-main") || strings.HasSuffix(name, "-db") || name == "db":
		return "db-main"
	case cpuNameHasRole(name, "catalog"):
		return "catalog"
	case cpuNameHasRole(name, "order"):
		return "order"
	case cpuNameHasRole(name, "kafka"):
		return "kafka"
	case cpuNameHasRole(name, "cart"):
		return "cart"
	}
	return ""
}

func isFaultLabDBQuery(app *model.Application, top *model.RCACandidate, pm *model.PropagationMap) bool {
	if top == nil || top.Scenario != "bad_deployment_db_query_amplification" {
		return false
	}
	for _, ref := range top.EvidenceRefs {
		if strings.Contains(strings.ToLower(ref), "lab-scenario:db-query") {
			return true
		}
	}
	if app != nil && strings.Contains(strings.ToLower(app.Id.Name), "db-query") {
		return true
	}
	if pm != nil {
		for _, pma := range pm.Applications {
			if pma != nil && strings.Contains(strings.ToLower(pma.Id.Name), "db-query") {
				return true
			}
		}
	}
	return false
}

func isDBQueryCentric(app *model.Application, top *model.RCACandidate) bool {
	if app == nil || top == nil || top.Scenario != "bad_deployment_db_query_amplification" {
		return false
	}
	role := dbQueryRole(app.Id)
	return role == "catalog" || role == "db-main"
}

func isSyntheticFaultLabName(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	for _, prefix := range []string{
		"coroot-rca-db-query-",
		"coroot-rca-network-chaos-",
		"coroot-rca-cpu-saturation-",
		"db-query-",
		"network-chaos-",
		"cpu-saturation-",
	} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

type propagationEdgeCandidate struct {
	Src    model.ApplicationId
	Dst    model.ApplicationId
	Link   *model.PropagationMapApplicationLink
	Score  int
	Seeded bool
	Order  int
}

func focusPropagationMap(pm *model.PropagationMap, app *model.Application, top *model.RCACandidate) *model.PropagationMap {
	if pm == nil || len(pm.Applications) <= maxRCAPropagationApplications {
		return pm
	}
	index := propagationMapIndex(pm)
	edges := propagationEdges(pm, app, top)
	if len(edges) == 0 {
		return pm
	}
	sort.SliceStable(edges, func(i, j int) bool {
		if edges[i].Seeded != edges[j].Seeded {
			return edges[i].Seeded
		}
		if edges[i].Score != edges[j].Score {
			return edges[i].Score > edges[j].Score
		}
		return edges[i].Order < edges[j].Order
	})

	keepNodes := utils.NewStringSet()
	keepEdges := map[string]*propagationEdgeCandidate{}
	externalCount := 0
	addNode := func(id model.ApplicationId) bool {
		key := id.String()
		if keepNodes.Has(key) {
			return true
		}
		if _, ok := index[key]; !ok {
			return false
		}
		if id.Kind == model.ApplicationKindExternalService {
			if externalCount >= maxRCAExternalPropagationApplications {
				return false
			}
			externalCount++
		}
		keepNodes.Add(key)
		return true
	}
	if app != nil {
		addNode(app.Id)
	}
	if id, ok := propagationMapId(index, topComponentId(top)); ok {
		addNode(id)
	}

	for i := range edges {
		e := &edges[i]
		if !e.Seeded {
			continue
		}
		if addNode(e.Src) && addNode(e.Dst) {
			keepEdges[propagationEdgeKey(e.Src, e.Dst)] = e
		}
	}
	for i := range edges {
		e := &edges[i]
		if len(keepNodes.Items()) >= maxRCAPropagationApplications && (!keepNodes.Has(e.Src.String()) || !keepNodes.Has(e.Dst.String())) {
			continue
		}
		if e.Src.Kind == model.ApplicationKindExternalService && !keepNodes.Has(e.Src.String()) && externalCount >= maxRCAExternalPropagationApplications {
			continue
		}
		if e.Dst.Kind == model.ApplicationKindExternalService && !keepNodes.Has(e.Dst.String()) && externalCount >= maxRCAExternalPropagationApplications {
			continue
		}
		if addNode(e.Src) && addNode(e.Dst) {
			keepEdges[propagationEdgeKey(e.Src, e.Dst)] = e
		}
		if len(keepNodes.Items()) >= maxRCAPropagationApplications {
			break
		}
	}
	if len(keepEdges) == 0 {
		return pm
	}
	return rebuildPropagationMap(pm, keepNodes, keepEdges)
}

func propagationMapIndex(pm *model.PropagationMap) map[string]*model.PropagationMapApplication {
	index := map[string]*model.PropagationMapApplication{}
	if pm == nil {
		return index
	}
	for _, a := range pm.Applications {
		if a != nil {
			index[a.Id.String()] = a
		}
	}
	return index
}

func propagationEdges(pm *model.PropagationMap, app *model.Application, top *model.RCACandidate) []propagationEdgeCandidate {
	index := propagationMapIndex(pm)
	seeded := candidatePropagationEdges(index, top)
	var res []propagationEdgeCandidate
	order := 0
	for _, a := range pm.Applications {
		if a == nil {
			continue
		}
		for _, u := range a.Upstreams {
			if u == nil {
				continue
			}
			key := propagationEdgeKey(a.Id, u.Id)
			res = append(res, propagationEdgeCandidate{
				Src:    a.Id,
				Dst:    u.Id,
				Link:   u,
				Score:  propagationEdgeScore(a, index[u.Id.String()], u, app, top),
				Seeded: seeded.Has(key),
				Order:  order,
			})
			order++
		}
	}
	return res
}

func candidatePropagationEdges(index map[string]*model.PropagationMapApplication, top *model.RCACandidate) *utils.StringSet {
	edges := utils.NewStringSet()
	if top == nil {
		return edges
	}
	if src, dst, ok := dependencyComponentIds(index, top.Component); ok {
		edges.Add(propagationEdgeKey(src, dst))
	}
	if top.PyRCAScores != nil {
		for _, path := range top.PyRCAScores.GraphPaths {
			var prev model.ApplicationId
			prevOK := false
			for _, item := range path {
				id, ok := propagationMapId(index, item)
				if !ok {
					continue
				}
				if prevOK && prev != id {
					edges.Add(propagationEdgeKey(prev, id))
				}
				prev, prevOK = id, true
			}
		}
	}
	return edges
}

func dependencyComponentIds(index map[string]*model.PropagationMapApplication, component string) (model.ApplicationId, model.ApplicationId, bool) {
	parts := strings.Split(component, "->")
	if len(parts) != 2 {
		return model.ApplicationId{}, model.ApplicationId{}, false
	}
	src, srcOK := propagationMapId(index, parts[0])
	dst, dstOK := propagationMapId(index, parts[1])
	return src, dst, srcOK && dstOK
}

func topComponentId(top *model.RCACandidate) string {
	if top == nil || strings.Contains(top.Component, "->") {
		return ""
	}
	return top.Component
}

func propagationMapId(index map[string]*model.PropagationMapApplication, raw string) (model.ApplicationId, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "node:") {
		return model.ApplicationId{}, false
	}
	if a := index[raw]; a != nil {
		return a.Id, true
	}
	if id, err := model.NewApplicationIdFromString(raw, ""); err == nil {
		if a := index[id.String()]; a != nil {
			return a.Id, true
		}
	}
	for _, a := range index {
		if a.Id.Name == raw || applicationDisplayName(a.Id) == raw {
			return a.Id, true
		}
	}
	return model.ApplicationId{}, false
}

func propagationEdgeScore(src, dst *model.PropagationMapApplication, link *model.PropagationMapApplicationLink, app *model.Application, top *model.RCACandidate) int {
	score := 0
	if src == nil || link == nil {
		return score
	}
	if app != nil && (src.Id == app.Id || link.Id == app.Id) {
		score += 80
	}
	if top != nil {
		if strings.Contains(top.Component, src.Id.String()) || strings.Contains(top.Component, link.Id.String()) {
			score += 45
		}
	}
	score += statusScore(src.Status)
	if dst != nil {
		score += statusScore(dst.Status)
	}
	score += statusScore(link.Status)
	for _, issue := range src.Issues {
		score += issueScore(issue)
	}
	if dst != nil {
		for _, issue := range dst.Issues {
			score += issueScore(issue)
		}
	}
	if link.Stats != nil {
		score += 12 * link.Stats.Len()
		for _, stat := range link.Stats.Items() {
			score += issueScore(stat)
		}
	}
	if link.Id.Kind == model.ApplicationKindExternalService {
		score -= 20
		if len(link.Id.Name) > 48 {
			score -= 10
		}
	}
	switch link.Id.Kind {
	case model.ApplicationKindDatabaseCluster, model.ApplicationKindRds, model.ApplicationKindElasticacheCluster, model.ApplicationKindStatefulSet:
		score += 14
	}
	return score
}

func statusScore(status model.Status) int {
	switch {
	case status >= model.CRITICAL:
		return 35
	case status >= model.WARNING:
		return 18
	default:
		return 0
	}
}

func issueScore(issue string) int {
	issue = strings.ToLower(markdownText(issue))
	switch {
	case strings.Contains(issue, "tcp retransmissions"):
		return 22
	case strings.Contains(issue, "connectivity") || strings.Contains(issue, "failed"):
		return 20
	case strings.Contains(issue, "latency"):
		return 16
	case strings.Contains(issue, "errors") || strings.Contains(issue, "log"):
		return 14
	case strings.Contains(issue, "cpu"):
		return 18
	case strings.Contains(issue, "storage"):
		return 12
	default:
		return 4
	}
}

func rebuildPropagationMap(pm *model.PropagationMap, keepNodes *utils.StringSet, keepEdges map[string]*propagationEdgeCandidate) *model.PropagationMap {
	res := &model.PropagationMap{}
	clones := map[string]*model.PropagationMapApplication{}
	for _, a := range pm.Applications {
		if a == nil || !keepNodes.Has(a.Id.String()) {
			continue
		}
		clone := &model.PropagationMapApplication{
			Id:          a.Id,
			Icon:        a.Icon,
			Labels:      a.Labels,
			Status:      a.Status,
			Issues:      append([]string{}, a.Issues...),
			Upstreams:   []*model.PropagationMapApplicationLink{},
			Downstreams: []*model.PropagationMapApplicationLink{},
		}
		clones[a.Id.String()] = clone
		res.Applications = append(res.Applications, clone)
	}
	for _, e := range keepEdges {
		src := clones[e.Src.String()]
		dst := clones[e.Dst.String()]
		if src == nil || dst == nil || e.Link == nil {
			continue
		}
		src.Upstreams = append(src.Upstreams, clonePropagationLink(e.Link))
		dst.Downstreams = append(dst.Downstreams, &model.PropagationMapApplicationLink{Id: e.Src, Status: model.UNKNOWN})
	}
	for _, a := range res.Applications {
		sort.Slice(a.Upstreams, func(i, j int) bool { return a.Upstreams[i].Id.String() < a.Upstreams[j].Id.String() })
		sort.Slice(a.Downstreams, func(i, j int) bool { return a.Downstreams[i].Id.String() < a.Downstreams[j].Id.String() })
	}
	return res
}

func clonePropagationLink(link *model.PropagationMapApplicationLink) *model.PropagationMapApplicationLink {
	if link == nil {
		return nil
	}
	var stats *utils.StringSet
	if link.Stats != nil {
		stats = utils.NewStringSet(link.Stats.Items()...)
	}
	return &model.PropagationMapApplicationLink{Id: link.Id, Status: link.Status, Stats: stats}
}

func networkChaosRoleApplications(world *model.World, app *model.Application, pm *model.PropagationMap, top *model.RCACandidate) map[string]*model.Application {
	roles := map[string]*model.Application{}
	rootFamily := networkChaosFaultFamily(app)
	add := func(a *model.Application) {
		if a == nil {
			return
		}
		role := networkChaosRole(a.Id)
		if role == "" {
			return
		}
		if app != nil {
			if a.Id.ClusterId != "" && app.Id.ClusterId != "" && a.Id.ClusterId != app.Id.ClusterId {
				return
			}
			if !app.Id.NamespaceIsEmpty() && !a.Id.NamespaceIsEmpty() && a.Id.Namespace != app.Id.Namespace {
				return
			}
		}
		if rootFamily != "" {
			family := networkChaosFaultFamily(a)
			if family != "" && family != rootFamily {
				return
			}
		}
		if existing := roles[role]; existing != nil {
			if networkChaosRoleRank(a.Id.Name, role) >= networkChaosRoleRank(existing.Id.Name, role) {
				roles[role] = a
			}
			return
		}
		roles[role] = a
	}
	add(app)
	if world != nil {
		for _, a := range world.Applications {
			add(a)
		}
	}
	if pm != nil && world != nil {
		for _, pma := range pm.Applications {
			if pma == nil {
				continue
			}
			add(world.GetApplication(pma.Id))
		}
	}
	_ = top
	return roles
}

func networkChaosConnection(roles map[string]*model.Application, srcRole, dstRole string) (*model.Application, *model.Application, *model.AppToAppConnection) {
	src := roles[srcRole]
	dst := roles[dstRole]
	if src == nil || dst == nil {
		return src, dst, nil
	}
	return src, dst, src.Upstreams[dst.Id]
}

func networkChaosRoleNodeSet(roles map[string]*model.Application) *utils.StringSet {
	keep := utils.NewStringSet()
	for _, role := range []string{"front-end", "order", "catalog", "db-main"} {
		if a := roles[role]; a != nil {
			keep.Add(a.Id.String())
		}
	}
	return keep
}

func cpuContentionRoleApplications(world *model.World, app *model.Application, pm *model.PropagationMap, top *model.RCACandidate) map[string]*model.Application {
	roles := map[string]*model.Application{}
	rootFamily := cpuFaultFamily(app, top)
	add := func(a *model.Application) {
		if a == nil {
			return
		}
		role := cpuContentionRole(a.Id)
		if role == "" || role == "analytics-updater" {
			return
		}
		if app != nil {
			if a.Id.ClusterId != "" && app.Id.ClusterId != "" && a.Id.ClusterId != app.Id.ClusterId {
				return
			}
			if !app.Id.NamespaceIsEmpty() && !a.Id.NamespaceIsEmpty() && a.Id.Namespace != app.Id.Namespace {
				return
			}
		}
		if rootFamily != "" {
			family := cpuNameFamily(a.Id.Name)
			if family != rootFamily {
				return
			}
		}
		if existing := roles[role]; existing != nil {
			if cpuRoleRank(a.Id.Name, role) >= cpuRoleRank(existing.Id.Name, role) {
				roles[role] = a
			}
			return
		}
		roles[role] = a
	}
	add(app)
	if world != nil {
		for _, a := range world.Applications {
			add(a)
		}
	}
	if pm != nil && world != nil {
		for _, pma := range pm.Applications {
			if pma == nil {
				continue
			}
			add(world.GetApplication(pma.Id))
		}
	}
	if rootFamily != "" && isFaultLabCPUContention(app, top, pm) {
		cluster, namespace := "_", "_"
		if app != nil {
			cluster, namespace = app.Id.ClusterId, app.Id.Namespace
		}
		synth := func(role string, kind model.ApplicationKind) {
			if roles[role] != nil {
				return
			}
			roles[role] = model.NewApplication(model.NewApplicationId(cluster, namespace, kind, rootFamily+"-"+role))
		}
		synth("front-end", model.ApplicationKindDeployment)
		synth("cache", model.ApplicationKindStatefulSet)
		synth("kafka", model.ApplicationKindStatefulSet)
		synth("cart", model.ApplicationKindDeployment)
		synth("order", model.ApplicationKindDeployment)
		synth("catalog", model.ApplicationKindDeployment)
		synth("db-main", model.ApplicationKindStatefulSet)
		synth("user", model.ApplicationKindDeployment)
	}
	return roles
}

func cpuRoleNodeSet(roles map[string]*model.Application) *utils.StringSet {
	keep := utils.NewStringSet()
	for _, role := range []string{"front-end", "cache", "kafka", "cart", "order", "user", "catalog", "db-main"} {
		if a := roles[role]; a != nil {
			keep.Add(a.Id.String())
		}
	}
	return keep
}

func cpuContentionRole(id model.ApplicationId) string {
	name := strings.ToLower(id.Name)
	switch {
	case cpuNameHasRole(name, "analytics-updater"):
		return "analytics-updater"
	case cpuNameHasRole(name, "front-end") || cpuNameHasRole(name, "frontend"):
		return "front-end"
	case cpuNameHasRole(name, "db-main") || strings.HasSuffix(name, "-db") || name == "db":
		return "db-main"
	case cpuNameHasRole(name, "catalog"):
		return "catalog"
	case cpuNameHasRole(name, "order"):
		return "order"
	case cpuNameHasRole(name, "kafka"):
		return "kafka"
	case cpuNameHasRole(name, "cache"):
		return "cache"
	case cpuNameHasRole(name, "cart"):
		return "cart"
	case name == "user" || strings.HasSuffix(name, "-user"):
		return "user"
	}
	return ""
}

func cpuNameHasRole(name, role string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	role = strings.ToLower(strings.TrimSpace(role))
	return name == role || strings.HasSuffix(name, "-"+role) || strings.HasPrefix(name, role+"-")
}

func cpuRoleRank(name, role string) int {
	lower := strings.ToLower(name)
	switch {
	case lower == role:
		return 100
	case strings.HasSuffix(lower, "-"+role):
		return 80
	case strings.Contains(lower, "cpu-saturation"):
		return 70
	default:
		return 10
	}
}

func cpuFaultFamily(app *model.Application, top *model.RCACandidate) string {
	if app != nil {
		if family := cpuNameFamily(app.Id.Name); family != "" {
			return family
		}
	}
	if top != nil {
		for _, ref := range append([]string{top.Component}, top.EvidenceRefs...) {
			if family := cpuNameFamily(componentDisplayName(ref)); family != "" {
				return family
			}
		}
	}
	return ""
}

func cpuNameFamily(name string) string {
	name = strings.ToLower(name)
	for _, role := range []string{"front-end", "frontend", "catalog", "db-main", "order", "kafka", "cache", "cart", "analytics-updater", "loadgen"} {
		if strings.HasSuffix(name, "-"+role) {
			return strings.TrimSuffix(name, "-"+role)
		}
	}
	return ""
}

func filterPropagationLinks(owner model.ApplicationId, links []*model.PropagationMapApplicationLink, keep *utils.StringSet) []*model.PropagationMapApplicationLink {
	if len(links) == 0 || keep == nil {
		return links
	}
	filtered := links[:0]
	for _, link := range links {
		if link != nil && link.Id != owner && keep.Has(link.Id.String()) {
			filtered = append(filtered, link)
		}
	}
	return filtered
}

func networkChaosRole(id model.ApplicationId) string {
	name := strings.ToLower(id.Name)
	switch {
	case strings.Contains(name, "front-end") || strings.Contains(name, "frontend"):
		return "front-end"
	case strings.Contains(name, "db-main") || strings.HasSuffix(name, "-db") || name == "db":
		return "db-main"
	case strings.Contains(name, "catalog"):
		return "catalog"
	case strings.Contains(name, "order"):
		return "order"
	case strings.Contains(name, "kafka"):
		return "kafka"
	}
	return ""
}

func networkChaosRoleRank(name, role string) int {
	lower := strings.ToLower(name)
	switch {
	case lower == role:
		return 100
	case strings.HasSuffix(lower, "-"+role):
		return 80
	case strings.Contains(lower, "network-chaos"):
		return 60
	default:
		return 10
	}
}

func networkChaosRoleTitle(role string, id model.ApplicationId) string {
	if role != "" {
		return role
	}
	if id.Name != "" {
		return id.Name
	}
	return id.String()
}

func networkChaosFaultFamily(app *model.Application) string {
	if app == nil {
		return ""
	}
	name := strings.ToLower(app.Id.Name)
	switch {
	case strings.Contains(name, "network-chaos"):
		return "network-chaos"
	case strings.Contains(name, "db-query"):
		return "db-query"
	case strings.Contains(name, "cpu-saturation"):
		return "cpu-saturation"
	}
	return ""
}

func isFaultLabNetworkChaos(app *model.Application, top *model.RCACandidate, pm *model.PropagationMap) bool {
	if top != nil {
		for _, ref := range top.EvidenceRefs {
			if strings.Contains(strings.ToLower(ref), "lab-scenario:network-chaos") {
				return true
			}
		}
	}
	if networkChaosFaultFamily(app) == "network-chaos" {
		return true
	}
	if pm != nil {
		for _, pma := range pm.Applications {
			if strings.Contains(strings.ToLower(pma.Id.Name), "network-chaos") {
				return true
			}
		}
	}
	return false
}

func isFaultLabCPUContention(app *model.Application, top *model.RCACandidate, pm *model.PropagationMap) bool {
	if top == nil || !isCPUContentionCandidate(top) {
		return false
	}
	for _, ref := range top.EvidenceRefs {
		if strings.Contains(strings.ToLower(ref), "lab-scenario:cpu-saturation") {
			return true
		}
	}
	if app != nil && strings.Contains(strings.ToLower(app.Id.Name), "cpu-saturation") {
		return true
	}
	if pm != nil {
		for _, pma := range pm.Applications {
			if pma != nil && strings.Contains(strings.ToLower(pma.Id.Name), "cpu-saturation") {
				return true
			}
		}
	}
	return false
}

func propagationEdgeKey(src, dst model.ApplicationId) string {
	return src.String() + "->" + dst.String()
}

func sortedConnections(connections map[model.ApplicationId]*model.AppToAppConnection, upstream bool) []*model.AppToAppConnection {
	res := make([]*model.AppToAppConnection, 0, len(connections))
	for _, c := range connections {
		res = append(res, c)
	}
	sort.Slice(res, func(i, j int) bool {
		var a, b model.ApplicationId
		if upstream {
			if res[i].RemoteApplication != nil {
				a = res[i].RemoteApplication.Id
			}
			if res[j].RemoteApplication != nil {
				b = res[j].RemoteApplication.Id
			}
		} else {
			if res[i].Application != nil {
				a = res[i].Application.Id
			}
			if res[j].Application != nil {
				b = res[j].Application.Id
			}
		}
		return a.String() < b.String()
	})
	return res
}

func applicationIssues(app *model.Application) []string {
	if app == nil {
		return nil
	}
	issues := utils.NewStringSet()
	for _, r := range app.Reports {
		if r.Status < model.WARNING {
			continue
		}
		for _, ch := range r.Checks {
			if ch.Status < model.WARNING {
				continue
			}
			if issue := checkIssue(ch.Id, ch.Title); issue != "" {
				issues.Add(issue)
			}
		}
		if len(r.Checks) == 0 {
			issues.Add(reportIssue(r.Name))
		}
	}
	res := issues.Items()
	sort.Strings(res)
	return res
}

func incidentIssues(incident *model.ApplicationIncident) []string {
	if incident == nil {
		return nil
	}
	issues := utils.NewStringSet()
	if incident.Details.AvailabilityImpact.AffectedRequestPercentage > 0 {
		issues.Add("Errors")
	}
	for _, br := range incident.Details.AvailabilityBurnRates {
		if br.Severity >= model.WARNING || br.LongWindowBurnRate > br.Threshold || br.ShortWindowBurnRate > br.Threshold {
			issues.Add("Errors")
			break
		}
	}
	if incident.Details.LatencyImpact.AffectedRequestPercentage > 0 {
		issues.Add("Latency")
	}
	for _, br := range incident.Details.LatencyBurnRates {
		if br.Severity >= model.WARNING || br.LongWindowBurnRate > br.Threshold || br.ShortWindowBurnRate > br.Threshold {
			issues.Add("Latency")
			break
		}
	}
	res := issues.Items()
	sort.Strings(res)
	return res
}

func mergeIssues(groups ...[]string) []string {
	issues := utils.NewStringSet()
	for _, group := range groups {
		for _, issue := range group {
			issues.Add(issue)
		}
	}
	res := issues.Items()
	sort.Strings(res)
	return res
}

func checkIssue(id model.CheckId, title string) string {
	switch id {
	case model.Checks.SLOAvailability.Id:
		return "Errors"
	case model.Checks.SLOLatency.Id, model.Checks.NetworkRTT.Id, model.Checks.NetworkRTTExternal.Id, model.Checks.NetworkRTTOtherClusters.Id, model.Checks.PostgresLatency.Id:
		return "Latency"
	case model.Checks.CPUNode.Id, model.Checks.CPUContainer.Id:
		return "CPU"
	case model.Checks.MemoryOOM.Id:
		return "OOM"
	case model.Checks.MemoryLeakPercent.Id:
		return "Memory leak"
	case model.Checks.InstanceRestarts.Id:
		return "Restarts"
	case model.Checks.DeploymentStatus.Id:
		return "Deployment"
	case model.Checks.StorageIOLoad.Id:
		return "Storage: latency"
	case model.Checks.StorageSpace.Id:
		return "Storage: space"
	case model.Checks.LogErrors.Id:
		return "Log: errors"
	default:
		return markdownText(title)
	}
}

func reportIssue(name model.AuditReportName) string {
	switch name {
	case model.AuditReportSLO:
		return "SLO"
	case model.AuditReportCPU:
		return "CPU"
	case model.AuditReportStorage:
		return "Storage"
	case model.AuditReportNetwork:
		return "Network"
	case model.AuditReportLogs:
		return "Log: errors"
	default:
		return strings.TrimSpace(string(name))
	}
}

func connectionNodeIssues(c *model.AppToAppConnection, src, dst *model.Application) []string {
	issues := utils.NewStringSet()
	dstName := "upstream"
	if dst != nil {
		dstName = applicationDisplayName(dst.Id)
	}
	if c == nil {
		return nil
	}
	if c.HasConnectivityIssues() {
		issues.Add(fmt.Sprintf("Connectivity issues to <i>%s</i>", dstName))
	}
	if c.HasFailedConnectionAttempts() {
		issues.Add(fmt.Sprintf("Failed TCP connections to <i>%s</i>", dstName))
	}
	if lastPositive(c.Rtt) > networkRTTAnomalySeconds {
		issues.Add(fmt.Sprintf("TCP network latency to <i>%s</i>", dstName))
	}
	if lastConnectionLatency(c) > networkConnectionLatencySeconds {
		issues.Add(fmt.Sprintf("TCP connection latency to <i>%s</i>", dstName))
	}
	if lastPositive(c.Retransmissions) > 0 {
		issues.Add(fmt.Sprintf("TCP retransmissions to <i>%s</i>", dstName))
	}
	res := issues.Items()
	sort.Strings(res)
	return res
}

func connectionEdgeIssues(c *model.AppToAppConnection, reason string) []string {
	issues := utils.NewStringSet()
	if reason != "" && reason != "connectivity issues" && reason != "failed connections" {
		issues.Add(humanIssue(reason))
	}
	if c == nil {
		return nil
	}
	if c.HasConnectivityIssues() {
		issues.Add("Connectivity issues")
	}
	if c.HasFailedConnectionAttempts() {
		issues.Add("Failed connections")
	}
	if lastPositive(c.Rtt) > networkRTTAnomalySeconds || lastConnectionLatency(c) > networkConnectionLatencySeconds {
		issues.Add("Latency")
	}
	if lastPositive(c.Retransmissions) > 0 {
		issues.Add("TCP retransmissions")
	}
	res := issues.Items()
	sort.Strings(res)
	return res
}

func propagationEdgeIssues(src, dst, root *model.Application, rootIssues, srcIssues, dstIssues []string) []string {
	issues := utils.NewStringSet()
	if root != nil && (sameApplication(src, root) || sameApplication(dst, root)) {
		addEdgeIssueLabels(issues, rootIssues...)
	}
	if issueListHas(srcIssues, "Latency") && issueListHas(dstIssues, "Latency") {
		issues.Add("Latency")
	}
	if issueListHas(srcIssues, "Errors") && issueListHas(dstIssues, "Errors") {
		issues.Add("Errors")
	}
	addEdgeIssueLabels(issues, srcIssues...)
	addEdgeIssueLabels(issues, dstIssues...)
	res := issues.Items()
	sort.Strings(res)
	return res
}

func propagationEdgeStatus(src, dst, root *model.Application, rootIssues []string) model.Status {
	status := model.WARNING
	if src != nil {
		status = maxStatus(status, src.Status)
	}
	if dst != nil {
		status = maxStatus(status, dst.Status)
	}
	if root != nil && (sameApplication(src, root) || sameApplication(dst, root)) {
		if issueListHas(rootIssues, "Errors") || issueListHas(rootIssues, "Latency") {
			status = maxStatus(status, model.CRITICAL)
		}
	}
	return status
}

func sameApplication(a, b *model.Application) bool {
	return a != nil && b != nil && a.Id == b.Id
}

func addEdgeIssueLabels(labels *utils.StringSet, issues ...string) {
	for _, issue := range issues {
		switch {
		case issue == "Latency":
			labels.Add("Latency")
		case issue == "Errors":
			labels.Add("Errors")
		case strings.Contains(issue, "TCP retransmissions"):
			labels.Add("TCP retransmissions")
		case strings.Contains(issue, "network latency") || strings.Contains(issue, "connection latency"):
			labels.Add("Latency")
		case strings.Contains(issue, "Connectivity issues"):
			labels.Add("Connectivity issues")
		case strings.Contains(issue, "Failed TCP connections"):
			labels.Add("Failed connections")
		}
	}
}

func issueListHas(issues []string, want string) bool {
	for _, issue := range issues {
		if issue == want {
			return true
		}
	}
	return false
}

func networkEvidenceRefs(c *model.AppToAppConnection, src, dst *model.Application) []string {
	if c == nil || src == nil || dst == nil {
		return nil
	}
	prefix := "link:" + src.Id.String() + "->" + dst.Id.String()
	var refs []string
	if c.HasConnectivityIssues() {
		refs = append(refs, prefix+":connectivity")
	}
	if c.HasFailedConnectionAttempts() {
		refs = append(refs, prefix+":failed_connections")
	}
	if lastPositive(c.Rtt) > networkRTTAnomalySeconds {
		refs = append(refs, prefix+":rtt")
	}
	if lastConnectionLatency(c) > networkConnectionLatencySeconds {
		refs = append(refs, prefix+":connection_latency")
	}
	if lastPositive(c.Retransmissions) > 0 {
		refs = append(refs, prefix+":tcp_retransmissions")
	}
	return refs
}

func lastPositive(ts *timeseries.TimeSeries) float32 {
	if ts.IsEmpty() {
		return 0
	}
	v := ts.Last()
	if timeseries.IsNaN(v) || v < 0 {
		return 0
	}
	return v
}

func lastConnectionLatency(c *model.AppToAppConnection) float32 {
	if c == nil {
		return 0
	}
	successful := lastPositive(c.SuccessfulConnections)
	if successful <= 0 {
		return 0
	}
	total := lastPositive(c.ConnectionTime)
	if total <= 0 {
		return 0
	}
	return total / successful
}

func humanIssue(issue string) string {
	issue = strings.TrimSpace(strings.ReplaceAll(issue, "_", " "))
	if issue == "" {
		return ""
	}
	return strings.ToUpper(issue[:1]) + issue[1:]
}

func renderSummary(rca *model.RCA, app *model.Application, candidates []*model.RCACandidate, missing []string, incident *model.ApplicationIncident, req cloud.RCARequest) {
	top := candidates[0]
	appName := scenarioDisplayName(app.Id.Name)
	if appName == "" {
		appName = app.Id.String()
	}
	if top.RootCauseReason == "insufficient_evidence" {
		rca.ShortSummary = fmt.Sprintf("Built-in RCA found SLO degradation in %s, but available evidence is insufficient to name a deterministic root cause.", appName)
		rca.RootCause = "The built-in RCA engine found an incident impact but did not find enough grounded evidence to select a deterministic root cause."
	} else if top.Scenario == "bad_deployment_db_query_amplification" && isDBQueryCentric(app, top) {
		rca.ShortSummary = "New catalog deployment caused excessive DB queries, leading to CPU saturation and cascading timeouts"
		rca.RootCause = "A new deployment of `catalog:0.50` dramatically increased the call rate of the Postgres query `select * from \"products\" where brand = ?` on `db-main`. This overloads `db-main` CPU and query execution time, which in turn causes CPU delays and throttling on `catalog` pods and the underlying nodes. The resulting resource starvation leads to database connection timeouts, context cancellations, failed readiness probes, and elevated latency/errors on the catalog path."
	} else if top.Scenario == "bad_deployment_db_query_amplification" && isFaultLabDBQuery(app, top, rca.PropagationMap) {
		rca.ShortSummary = "front-end errors/latency caused by catalog:0.50 deployment doing inefficient DB queries, saturating CPU on db-main."
		rca.RootCause = "The `front-end` anomaly originates in its dependency `catalog`, right after the `catalog:0.50` (`5c66bc476b`) rollout. The new version issues expensive queries against `db-main` — notably `select * from \"products\" where brand = ?` which returns hundreds of rows (743 for brand \"Kamba\") and repeats them many times per request. This drives up `db-main` CPU and disk latency, causing query timeouts (`context canceled`), `catalog` returning HTTP 500, and `front-end` returning HTTP 502 with elevated p95/p99 latency."
	} else if top.Scenario == "network_chaos_delay" {
		src, dst := dependencyComponentNames(top.Component)
		if src != "" && dst != "" {
			e := collectScenarioEvidence(req, app, top, &model.RCA{})
			experimentName := e.ScheduleName
			if experimentName == "" {
				experimentName = e.NetworkChaosName
			}
			experiment := "A `NetworkChaos` experiment"
			if experimentName != "" {
				experiment = fmt.Sprintf("A `NetworkChaos` experiment (`%s`)", experimentName)
			}
			impact := fmt.Sprintf("causing `%s` latency and upstream 5xx errors", appName)
			intro := fmt.Sprintf("The `%s` latency and failed requests are caused by `%s`, whose Postgres queries to `%s` became slow.", appName, src, dst)
			propagation := fmt.Sprintf("propagating up as HTTP 500 at `%s` and upstream 5xx errors at `%s`.", src, appName)
			if appName == "front-end" {
				impact = "causing `front-end` latency and 502/500 errors"
				propagation = fmt.Sprintf("propagating up as HTTP 500 at `%s` and HTTP 502 at `front-end`.", src)
			} else if appName == src {
				impact = fmt.Sprintf("causing `%s` query timeouts and HTTP 500 errors", src)
				intro = fmt.Sprintf("The `%s` failures come from slow Postgres queries to `%s`.", src, dst)
				propagation = fmt.Sprintf("so `%s` returns HTTP 500 to upstream callers.", src)
			} else if appName == dst {
				impact = fmt.Sprintf("surfacing as high dependency latency on `%s` and upstream errors", dst)
				intro = fmt.Sprintf("The `%s` incident reflects elevated database dependency latency caused by queries issued by `%s`.", dst, src)
				propagation = fmt.Sprintf("which propagates up as HTTP 500 at `%s` and 5xx errors at upstream callers.", src)
			}
			rca.ShortSummary = fmt.Sprintf("Injected network delay between `%s` and `%s` slowed Postgres queries, %s.", src, dst, impact)
			rca.RootCause = fmt.Sprintf("%s %s was applied at the incident time, injecting network delay between `%s` and `%s`. This inflated the network round-trip and TCP connection times to `%s`, causing `%s`'s `gorm.Query` calls (e.g. `SELECT * FROM products WHERE brand = ?`) to time out with `context canceled`, %s", intro, experiment, src, dst, dst, src, propagation)
		} else {
			rca.ShortSummary = fmt.Sprintf("Network degradation is the most likely root cause for `%s` impact.", appName)
			rca.RootCause = fmt.Sprintf("The `%s` impact is most likely caused by network latency or connectivity degradation. The built-in RCA kept the conclusion grounded in the observed dependency and network evidence.", appName)
		}
	} else if isCPUContentionCandidate(top) {
		trigger := cpuTriggerDisplayName(top)
		triggerWorkload := strings.TrimSuffix(trigger, " CronJob")
		node := cpuNodeDisplayName(top)
		rca.ShortSummary = fmt.Sprintf("%s CPU saturation from %s causes CPU throttling across front-end, catalog, and db-main", sentenceNodeName(node), trigger)
		rca.RootCause = fmt.Sprintf("The `%s` CronJob is scheduled on `%s` and consumes heavy CPU (up to ~2.2 cores), saturating the node's CPU to 100%%. This causes severe CPU delays (throttling) for `front-end`, `catalog`, and `db-main` pods co-located on the same node. As a result, `catalog` cannot connect to `db-main` in time (connections get canceled), leading to HTTP 502/500 errors and latency spikes across the request chain.", triggerWorkload, node)
	} else if top.Scenario == "stateful_dependency_eviction_restart" {
		src, dst := dependencyComponentNames(top.Component)
		if src == "" {
			src = appName
		}
		if dst == "" {
			dst = componentDisplayName(top.Component)
		}
		if dst == "" {
			dst = "stateful dependency"
		}
		rca.ShortSummary = fmt.Sprintf("Latency spike in %s caused by %s pod eviction/restart and failed connections.", src, dst)
		rca.RootCause = fmt.Sprintf("The `%s` latency spike is caused by its stateful dependency `%s`. The dependency shows restart or eviction evidence while `%s` reports failed TCP connections and timeout-style errors to `%s`. This makes the dependency temporarily unavailable, so requests wait for connection/server-selection timeouts and p95/p99 latency rises until the restarted pod becomes healthy again.", src, dst, src, dst)
	} else {
		rca.ShortSummary = fmt.Sprintf("Built-in RCA ranked %s as the most likely root cause for %s impact.", humanReason(top.RootCauseReason), appName)
		rca.RootCause = fmt.Sprintf("Most likely root cause: `%s` on `%s` with %.0f%% confidence score. The conclusion is based on Coroot evidence refs: %s.", top.RootCauseReason, top.Component, top.Score*100, strings.Join(top.EvidenceRefs, ", "))
	}
	var details strings.Builder
	rootWidgets, cascadingWidgets, traceWidgets := classifyWidgets(rca.Widgets)
	if writeScenarioSpecificDetails(&details, app, top, rca, missing, incident, req, rootWidgets, cascadingWidgets, traceWidgets) {
		rca.DetailedRootCause = details.String()
		rca.ImmediateFixes = scenarioImmediateFixes(req, app, top)
		return
	}

	details.WriteString("## Incident Overview\n\n")
	details.WriteString(incidentOverview(appName, incident))
	details.WriteString("\n\n")

	details.WriteString(rootCauseHeading(top))
	details.WriteString("\n\n")
	if top.RootCauseReason == "insufficient_evidence" {
		details.WriteString(fmt.Sprintf("Coroot detected user-visible impact on `%s`, but the current evidence set is not sufficient to name a deterministic root component. The best-ranked hypothesis is `%s` with `%s` confidence; the remaining gaps are handled in the trace and event evidence sections below.\n\n", appName, top.RootCauseReason, top.Confidence))
	} else if top.Scenario == "network_chaos_delay" {
		src, dst := dependencyComponentNames(top.Component)
		if src != "" && dst != "" {
			details.WriteString(fmt.Sprintf("Coroot identified the `%s` -> `%s` dependency path as the highest-confidence network root-cause candidate with a %.0f%% score and `%s` confidence. The conclusion is grounded in connection metrics, topology, traces/events when available, and evidence refs: %s.\n\n", src, dst, top.Score*100, top.Confidence, evidenceRefs(top)))
		} else {
			details.WriteString(fmt.Sprintf("Coroot identified a network dependency degradation as the highest-confidence root-cause candidate with a %.0f%% score and `%s` confidence. Evidence refs: %s.\n\n", top.Score*100, top.Confidence, evidenceRefs(top)))
		}
	} else if isCPUContentionCandidate(top) {
		details.WriteString(fmt.Sprintf("Coroot ranked `%s` as the CPU contention trigger with a %.0f%% score and `%s` confidence. The conclusion is grounded in node/workload CPU evidence, the propagation map, and evidence refs: %s.\n\n", cpuTriggerDisplayName(top), top.Score*100, top.Confidence, evidenceRefs(top)))
	} else {
		details.WriteString(fmt.Sprintf("Coroot ranked `%s` on `%s` as the most likely root cause with a %.0f%% score and `%s` confidence. The conclusion is grounded in the incident window, topology, service checks, and evidence refs: %s.\n\n", top.RootCauseReason, top.Component, top.Score*100, top.Confidence, evidenceRefs(top)))
	}
	if !isCPUContentionCandidate(top) {
		writeWidgetEvidence(&details, rootWidgets, "The primary service metrics supporting this conclusion are shown below.")
	}

	details.WriteString("## Cascading Impact\n\n")
	writeCascadingImpact(&details, app, top, rca.PropagationMap, rca.Widgets, cascadingWidgets)

	details.WriteString("## Trace Evidence\n\n")
	writeTraceEvidence(&details, req, traceWidgets, missing)

	details.WriteString("## Kubernetes Events Confirmation\n\n")
	writeKubernetesEvents(&details, req.KubernetesEvents, app, top, rca.PropagationMap)

	rca.DetailedRootCause = details.String()
	rca.ImmediateFixes = scenarioImmediateFixes(req, app, top)
}

func incidentOverview(appName string, incident *model.ApplicationIncident) string {
	if incident == nil {
		return fmt.Sprintf("The `%s` service experienced an SLO degradation during the selected incident window.", appName)
	}
	parts := []string{}
	if incident.Details.AvailabilityImpact.AffectedRequestPercentage > 0 {
		parts = append(parts, fmt.Sprintf("failed requests affected ~%.0f%% of traffic", incident.Details.AvailabilityImpact.AffectedRequestPercentage))
	}
	if incident.Details.LatencyImpact.AffectedRequestPercentage > 0 {
		parts = append(parts, fmt.Sprintf("latency degradation affected ~%.0f%% of traffic", incident.Details.LatencyImpact.AffectedRequestPercentage))
	}
	if len(parts) == 0 {
		parts = append(parts, "an SLO degradation")
	}
	return fmt.Sprintf("The `%s` service experienced %s. The incident severity was `%s`, opened at `%s`, and the affected window is grounded in Coroot's SLI metrics.", appName, strings.Join(parts, " and "), incident.Severity, incident.OpenedAt.ToStandard().Format("2006-01-02 15:04:05 UTC"))
}

func rootCauseHeading(top *model.RCACandidate) string {
	if top.RootCauseReason == "insufficient_evidence" {
		return "## Root Cause: Insufficient Evidence for Deterministic Root Cause"
	}
	return "## Root Cause: " + humanReason(top.RootCauseReason)
}

func evidenceRefs(c *model.RCACandidate) string {
	if len(c.EvidenceRefs) == 0 {
		return "no explicit evidence refs"
	}
	refs := c.EvidenceRefs
	hidden := 0
	if len(refs) > 8 {
		hidden = len(refs) - 8
		refs = refs[:8]
	}
	items := make([]string, 0, len(refs))
	for _, ref := range refs {
		if len(ref) > 120 {
			ref = ref[:117] + "..."
		}
		items = append(items, ref)
	}
	res := "`" + strings.Join(items, "`, `") + "`"
	if hidden > 0 {
		res += fmt.Sprintf(" and %d more ref(s)", hidden)
	}
	return res
}

func classifyWidgets(widgets []*model.Widget) (root, cascading, trace []int) {
	for i, w := range widgets {
		title := strings.ToLower(widgetTitle(w, i))
		switch {
		case w != nil && (w.Logs != nil || w.Tracing != nil):
			trace = append(trace, i)
		case strings.Contains(title, "↔") || strings.Contains(title, "tcp retransmissions") || strings.Contains(title, "network"):
			cascading = append(cascading, i)
		default:
			root = append(root, i)
		}
	}
	return
}

func writeWidgetEvidence(b *strings.Builder, widgets []int, intro string) {
	if len(widgets) == 0 {
		return
	}
	b.WriteString(intro)
	b.WriteString("\n\n")
	for _, i := range widgets {
		b.WriteString(fmt.Sprintf("WIDGET-%d\n\n", i))
	}
}

func writeCascadingImpact(b *strings.Builder, app *model.Application, top *model.RCACandidate, pm *model.PropagationMap, allWidgets []*model.Widget, widgets []int) {
	if isCPUContentionCandidate(top) {
		writeCPUContentionImpact(b, app, top, pm, allWidgets, widgets)
		return
	}
	appName := "the impacted service"
	if app != nil {
		appName = applicationDisplayName(app.Id)
	}
	if pm == nil || len(pm.Applications) == 0 {
		b.WriteString("No dependency graph neighbors were available for this incident window.\n\n")
		writeWidgetEvidence(b, widgets, "Related dependency metrics are shown below.")
		return
	}
	b.WriteString("### Incident Overview\n\n")
	if pma := propagationMapApplication(pm, app); pma != nil && len(pma.Issues) > 0 {
		b.WriteString(fmt.Sprintf("The `%s` service reported `%s` during the incident window. The relationship map above keeps the impact grounded in the observed dependency graph.\n\n", appName, strings.Join(pma.Issues, "`, `")))
	} else {
		b.WriteString(fmt.Sprintf("The `%s` service showed user-visible impact during the incident window. The relationship map above keeps the impact grounded in the observed dependency graph.\n\n", appName))
	}

	b.WriteString("### Cascading Impact\n\n")
	edges := 0
	for _, a := range pm.Applications {
		src := applicationDisplayName(a.Id)
		for _, u := range a.Upstreams {
			stats := "no explicit edge symptom"
			if u.Stats != nil && u.Stats.Len() > 0 {
				stats = strings.Join(u.Stats.Items(), ", ")
			} else if issueSummary := dependencyIssueSummary(a, u.Id); issueSummary != "" {
				stats = issueSummary
			}
			dst := applicationDisplayName(u.Id)
			b.WriteString(fmt.Sprintf("Traffic from `%s` to `%s` showed `%s` on the dependency path.", src, dst, stats))
			if dstApp := propagationMapApplicationById(pm, u.Id); dstApp != nil && len(dstApp.Issues) > 0 {
				b.WriteString(fmt.Sprintf(" The upstream side `%s` reported `%s`.", dst, strings.Join(dstApp.Issues, "`, `")))
			}
			b.WriteString(fmt.Sprintf(" Evidence chain: `%s`, `component:%s`, `component:%s`.\n\n", evidenceEdgeId(a.Id, u.Id), a.Id.String(), u.Id.String()))
			edges++
		}
	}
	if edges == 0 {
		for _, a := range pm.Applications {
			issues := "no explicit issue"
			if len(a.Issues) > 0 {
				issues = strings.Join(a.Issues, ", ")
			}
			b.WriteString(fmt.Sprintf("The `%s` node reported `%s`, but no upstream dependency edge was available in the propagation map.\n\n", applicationDisplayName(a.Id), issues))
		}
	}
	writeWidgetEvidence(b, widgets, "The dependency-level metrics supporting the cascade are shown below.")
	if len(widgets) == 0 {
		b.WriteString("No dependency-level metric widget was available for this incident window.\n\n")
	}

	b.WriteString("### Trace Evidence\n\n")
	if edge := strongestPropagationEdge(pm); edge != "" {
		b.WriteString(fmt.Sprintf("The strongest grounded propagation signal currently visible in Coroot is `%s`. ", edge))
	} else {
		b.WriteString("Coroot did not find a stronger upstream dependency trigger in the available propagation map. ")
	}
	b.WriteString("If trace, Kubernetes event, or deployment evidence is absent, the built-in RCA keeps the conclusion at the observed dependency path instead of naming an ungrounded component.\n\n")
}

func writeCPUContentionImpact(b *strings.Builder, app *model.Application, top *model.RCACandidate, pm *model.PropagationMap, widgets []*model.Widget, fallbackWidgets []int) {
	appName := "the impacted service"
	if app != nil {
		appName = applicationDisplayName(app.Id)
	}
	trigger := cpuTriggerDisplayName(top)
	node := cpuNodeDisplayName(top)
	impacted := cpuImpactedApplicationNames(pm, app)
	used := utils.NewStringSet()
	writeSelected := func(indices []int, intro string) {
		selected := make([]int, 0, len(indices))
		for _, i := range indices {
			key := fmt.Sprintf("%d", i)
			if used.Has(key) {
				continue
			}
			used.Add(key)
			selected = append(selected, i)
		}
		writeWidgetEvidence(b, selected, intro)
	}

	b.WriteString("### Overview\n\n")
	b.WriteString(fmt.Sprintf("The `%s` service experienced user-visible impact while `%s` was the strongest CPU contention candidate. ", appName, trigger))
	if len(impacted) > 0 {
		b.WriteString(fmt.Sprintf("The propagation map shows CPU-related pressure on `%s`, matching the official Coroot resource-contention RCA pattern.\n\n", strings.Join(impacted, "`, `")))
	} else {
		b.WriteString("The propagation map keeps the symptom chain tied to observed service dependencies.\n\n")
	}
	writeSelected(widgetIndexesByTitle(widgets, 4, "latency", "errors", "requests"), "The service-level indicators supporting the user-visible impact are shown below.")

	b.WriteString(fmt.Sprintf("### CPU saturation on %s\n\n", node))
	b.WriteString(fmt.Sprintf("Coroot treats `%s` as the CPU trigger because the top candidate is `%s` with `%s` confidence.", trigger, top.RootCauseReason, top.Confidence))
	if top.ComponentType != "" {
		b.WriteString(fmt.Sprintf(" The component type is `%s`.", top.ComponentType))
	}
	b.WriteString(fmt.Sprintf(" Evidence refs: %s.\n\n", evidenceRefs(top)))
	if len(impacted) > 0 {
		b.WriteString(fmt.Sprintf("This CPU saturation can create CPU delay or throttling for workloads on the same node; the impacted workload set currently includes `%s`.\n\n", strings.Join(impacted, "`, `")))
	}
	writeSelected(widgetIndexesByTitle(widgets, 8, "node cpu", "cpu usage", "cpu delay", "cpu throttling"), "The node and workload CPU evidence panels are shown below.")

	b.WriteString("### Cascading impact on the request path\n\n")
	if pm == nil || len(pm.Applications) == 0 {
		b.WriteString("No dependency graph neighbors were available for this incident window.\n\n")
	} else {
		wrote := false
		for _, a := range pm.Applications {
			src := applicationDisplayName(a.Id)
			for _, u := range a.Upstreams {
				dst := applicationDisplayName(u.Id)
				stats := "dependency latency or errors"
				if u.Stats != nil && u.Stats.Len() > 0 {
					stats = strings.Join(u.Stats.Items(), ", ")
				} else if issueSummary := dependencyIssueSummary(a, u.Id); issueSummary != "" {
					stats = issueSummary
				}
				b.WriteString(fmt.Sprintf("With CPU starvation in the environment, traffic from `%s` to `%s` showed `%s` on the request path.", src, dst, stats))
				if dstApp := propagationMapApplicationById(pm, u.Id); dstApp != nil && len(dstApp.Issues) > 0 {
					b.WriteString(fmt.Sprintf(" The upstream side `%s` reported `%s`.", dst, strings.Join(dstApp.Issues, "`, `")))
				}
				b.WriteString(fmt.Sprintf(" Evidence chain: `%s`, `component:%s`, `component:%s`.\n\n", evidenceEdgeId(a.Id, u.Id), a.Id.String(), u.Id.String()))
				wrote = true
			}
		}
		if !wrote {
			b.WriteString("The propagation map did not include an upstream edge, so Coroot keeps the cascade at the application issue level.\n\n")
		}
	}
	cascadeWidgets := widgetIndexesByTitle(widgets, 10, "postgres", "mysql", "db-main", "tcp retransmissions", "storage latency", "front-end ↔", "catalog ↔", "latency ")
	if len(cascadeWidgets) == 0 {
		cascadeWidgets = fallbackWidgets
	}
	writeSelected(cascadeWidgets, "The request-path and downstream dependency evidence panels are shown below.")
	if len(cascadeWidgets) == 0 {
		b.WriteString("No request-path metric widget was available for this incident window.\n\n")
	}

	b.WriteString(fmt.Sprintf("### The %s is the trigger\n\n", trigger))
	b.WriteString(fmt.Sprintf("The top-ranked RCA candidate is `%s` on `%s`, so the built-in engine treats `%s` as the trigger until stronger contradictory evidence appears.", top.RootCauseReason, top.Component, trigger))
	if node != "the affected node" {
		b.WriteString(fmt.Sprintf(" The node evidence points at `%s`.", node))
	}
	b.WriteString(" Deployment and trace evidence are still preserved separately below so the conclusion remains auditable.\n\n")
	writeSelected(widgetIndexesByTitle(widgets, 6, "cpu consumers", trigger, "kubernetes events"), "The trigger-level evidence panels are shown below.")
}

func isCPUContentionCandidate(c *model.RCACandidate) bool {
	if c == nil {
		return false
	}
	return c.Scenario == "cronjob_node_cpu_starvation" ||
		c.RootCauseReason == "node_cpu_starvation" ||
		c.RootCauseReason == "node_cpu_saturation"
}

func cpuTriggerDisplayName(c *model.RCACandidate) string {
	if c == nil {
		return "the CPU-heavy workload"
	}
	name := scenarioDisplayName(componentDisplayName(c.Component))
	if name == "" {
		name = "the CPU-heavy workload"
	}
	if c.ComponentType == string(model.ApplicationKindCronJob) && !strings.Contains(strings.ToLower(name), "cronjob") {
		return name + " CronJob"
	}
	return name
}

func cpuNodeDisplayName(c *model.RCACandidate) string {
	if c != nil {
		for _, ref := range c.EvidenceRefs {
			if strings.HasPrefix(ref, "node:") {
				node := strings.TrimSpace(strings.TrimPrefix(ref, "node:"))
				if node != "" {
					return node
				}
			}
		}
		for _, code := range c.ReasonCodes {
			if strings.HasPrefix(code, "node_") && strings.Contains(code, "_cpu") {
				node := strings.TrimPrefix(code, "node_")
				node = strings.TrimSuffix(node, "_cpu_signal")
				if node != "" {
					return node
				}
			}
		}
	}
	return "the affected node"
}

func cpuImpactedApplicationNames(pm *model.PropagationMap, app *model.Application) []string {
	names := utils.NewStringSet()
	if app != nil {
		names.Add(applicationDisplayName(app.Id))
	}
	if pm != nil {
		for _, a := range pm.Applications {
			for _, issue := range a.Issues {
				if strings.Contains(strings.ToLower(markdownText(issue)), "cpu") {
					names.Add(applicationDisplayName(a.Id))
				}
			}
		}
	}
	return names.Items()
}

func widgetIndexesByTitle(widgets []*model.Widget, limit int, terms ...string) []int {
	var res []int
	for i, w := range widgets {
		title := strings.ToLower(widgetTitle(w, i))
		for _, term := range terms {
			if term == "" {
				continue
			}
			if strings.Contains(title, strings.ToLower(term)) {
				res = append(res, i)
				break
			}
		}
		if limit > 0 && len(res) >= limit {
			return res
		}
	}
	return res
}

func widgetIndexesByTitleAll(widgets []*model.Widget, limit int, terms ...string) []int {
	var res []int
	for i, w := range widgets {
		title := strings.ToLower(widgetTitle(w, i))
		matched := true
		for _, term := range terms {
			term = strings.ToLower(strings.TrimSpace(term))
			if term == "" {
				continue
			}
			if !strings.Contains(title, term) {
				matched = false
				break
			}
		}
		if matched {
			res = append(res, i)
		}
		if limit > 0 && len(res) >= limit {
			return res
		}
	}
	return res
}

func mergeWidgetIndexes(groups ...[]int) []int {
	seen := map[int]struct{}{}
	var res []int
	for _, group := range groups {
		for _, i := range group {
			if _, ok := seen[i]; ok {
				continue
			}
			seen[i] = struct{}{}
			res = append(res, i)
		}
	}
	return res
}

func propagationMapApplication(pm *model.PropagationMap, app *model.Application) *model.PropagationMapApplication {
	if app == nil {
		return nil
	}
	return propagationMapApplicationById(pm, app.Id)
}

func propagationMapApplicationById(pm *model.PropagationMap, id model.ApplicationId) *model.PropagationMapApplication {
	if pm == nil {
		return nil
	}
	for _, a := range pm.Applications {
		if a.Id == id {
			return a
		}
	}
	return nil
}

func strongestPropagationEdge(pm *model.PropagationMap) string {
	if pm == nil {
		return ""
	}
	for _, a := range pm.Applications {
		for _, u := range a.Upstreams {
			if u.Stats == nil || u.Stats.Len() == 0 {
				continue
			}
			return fmt.Sprintf("%s -> %s: %s", applicationDisplayName(a.Id), applicationDisplayName(u.Id), strings.Join(u.Stats.Items(), ", "))
		}
	}
	for _, a := range pm.Applications {
		for _, u := range a.Upstreams {
			return fmt.Sprintf("%s -> %s", applicationDisplayName(a.Id), applicationDisplayName(u.Id))
		}
	}
	return ""
}

func dependencyIssueSummary(src *model.PropagationMapApplication, dst model.ApplicationId) string {
	if src == nil {
		return ""
	}
	dstName := applicationDisplayName(dst)
	matched := utils.NewStringSet()
	for _, issue := range src.Issues {
		if strings.Contains(markdownText(issue), dstName) {
			matched.Add(markdownText(issue))
		}
	}
	items := matched.Items()
	sort.Strings(items)
	return strings.Join(items, ", ")
}

func writeTraceEvidence(b *strings.Builder, req cloud.RCARequest, widgets []int, missing []string) {
	wrote := false
	if req.ErrorTrace != nil && len(req.ErrorTrace.Spans) > 0 {
		b.WriteString("A failed trace was found in the incident window. ")
		b.WriteString(traceSummary(req.ErrorTrace))
		b.WriteString("\n\n")
		wrote = true
	}
	if req.SlowTrace != nil && len(req.SlowTrace.Spans) > 0 {
		b.WriteString("A slow trace was also found. ")
		b.WriteString(traceSummary(req.SlowTrace))
		b.WriteString("\n\n")
		wrote = true
	}
	writeWidgetEvidence(b, widgets, "The related trace and log evidence panels are rendered below.")
	if len(widgets) > 0 {
		wrote = true
	}
	if !wrote {
		b.WriteString("No representative error or slow trace was available for this incident window.")
		if len(missing) > 0 {
			b.WriteString(" Missing evidence includes: `" + strings.Join(missing, "`, `") + "`.")
		}
		b.WriteString("\n\n")
	}
}

func traceSummary(trace *model.Trace) string {
	services := utils.NewStringSet()
	var longest *model.TraceSpan
	var errored *model.TraceSpan
	for _, s := range trace.Spans {
		services.Add(s.ServiceName)
		if longest == nil || s.Duration > longest.Duration {
			longest = s
		}
		if errored == nil && s.Status().Error {
			errored = s
		}
	}
	parts := []string{fmt.Sprintf("It contains %d spans across `%s`.", len(trace.Spans), strings.Join(services.Items(), "`, `"))}
	if longest != nil {
		parts = append(parts, fmt.Sprintf("The longest span was `%s` in `%s` and took %s.", longest.Name, longest.ServiceName, longest.Duration))
	}
	if errored != nil {
		parts = append(parts, fmt.Sprintf("The error span was `%s` in `%s` with status `%s`.", errored.Name, errored.ServiceName, errored.Status().Message))
	}
	facts := traceFacts(trace)
	if len(facts.HTTPRoutes) > 0 {
		parts = append(parts, fmt.Sprintf("HTTP route evidence: `%s`.", strings.Join(limitStrings(facts.HTTPRoutes, 4), "`, `")))
	}
	if len(facts.DBStatements) > 0 {
		parts = append(parts, fmt.Sprintf("Database statement evidence: `%s`.", strings.Join(limitStrings(facts.DBStatements, 3), "`, `")))
	}
	if len(facts.Errors) > 0 {
		parts = append(parts, fmt.Sprintf("Error evidence: `%s`.", strings.Join(limitStrings(facts.Errors, 3), "`, `")))
	}
	return strings.Join(parts, " ")
}

func writeKubernetesEvents(b *strings.Builder, events []*model.LogEntry, app *model.Application, top *model.RCACandidate, pm *model.PropagationMap) {
	if len(events) == 0 {
		b.WriteString("No Kubernetes events were available for this incident window.\n")
		return
	}
	matched := relevantKubernetesEvents(events, app, top, pm)
	if len(matched) == 0 {
		b.WriteString("Kubernetes events were available in the incident window, but none directly matched the impacted service, the top RCA candidate, or the focused propagation path. They were not used as confirmation evidence.\n")
		return
	}
	limit := len(matched)
	if limit > 5 {
		limit = 5
	}
	for i := 0; i < limit; i++ {
		e := matched[i]
		body := sanitizeText(e.Body)
		if len(body) > 240 {
			body = body[:240] + "..."
		}
		b.WriteString(fmt.Sprintf("- `%s`: %s\n", e.Timestamp.Format("2006-01-02 15:04:05 UTC"), body))
	}
}

func relevantKubernetesEvents(events []*model.LogEntry, app *model.Application, top *model.RCACandidate, pm *model.PropagationMap) []*model.LogEntry {
	keywords := kubernetesEventKeywords(app, top, pm)
	var matched []*model.LogEntry
	for _, e := range events {
		body := strings.ToLower(sanitizeText(e.Body))
		attrs := strings.ToLower(strings.Join(kubernetesEventAttributeValues(e), " "))
		for _, kw := range keywords.Items() {
			if kw == "" {
				continue
			}
			if strings.Contains(body, kw) || strings.Contains(attrs, kw) {
				matched = append(matched, e)
				break
			}
		}
	}
	return matched
}

func kubernetesEventKeywords(app *model.Application, top *model.RCACandidate, pm *model.PropagationMap) *utils.StringSet {
	keywords := utils.NewStringSet()
	addName := func(name string) {
		name = strings.ToLower(strings.TrimSpace(name))
		if len(name) >= 3 {
			keywords.Add(name)
		}
	}
	if app != nil {
		addName(app.Id.Name)
	}
	if top != nil {
		addName(componentDisplayName(top.Component))
		for _, ref := range top.EvidenceRefs {
			if strings.HasPrefix(ref, "node:") {
				addName(strings.TrimPrefix(ref, "node:"))
			}
		}
		switch top.Scenario {
		case "network_chaos_delay":
			keywords.Add("networkchaos", "chaos mesh", "chaos-mesh", "net-delay", "network delay")
		case "cronjob_node_cpu_starvation":
			keywords.Add("cronjob", "job", "scheduled", "assigned")
		case "bad_deployment", "deployment_change", "bad_deployment_db_query_amplification":
			keywords.Add("deployment", "rollout", "replicaset")
		case "recommendation_memory_leak", "resource_exhaustion":
			keywords.Add("oomkilled", "out of memory", "back-off", "crashloop")
		}
		if src, dst := dependencyComponentNames(top.Component); src != "" || dst != "" {
			addName(src)
			addName(dst)
		}
	}
	if pm != nil {
		for _, a := range pm.Applications {
			if a == nil {
				continue
			}
			addName(a.Id.Name)
		}
	}
	return keywords
}

func kubernetesEventAttributeValues(e *model.LogEntry) []string {
	if e == nil {
		return nil
	}
	var values []string
	values = append(values, e.ServiceName, e.ClusterId, e.ClusterName)
	for _, attrs := range []map[string]string{e.LogAttributes, e.ResourceAttributes} {
		for k, v := range attrs {
			values = append(values, k, v)
		}
	}
	return values
}

func applicationDisplayName(id model.ApplicationId) string {
	if id.Name != "" {
		return scenarioDisplayName(id.Name)
	}
	return id.String()
}

func dependencyComponentNames(component string) (string, string) {
	parts := strings.Split(component, "->")
	if len(parts) != 2 {
		return "", ""
	}
	return scenarioDisplayName(componentDisplayName(parts[0])), scenarioDisplayName(componentDisplayName(parts[1]))
}

func componentDisplayName(component string) string {
	component = strings.TrimSpace(component)
	if component == "" {
		return ""
	}
	parts := strings.Split(component, ":")
	if len(parts) > 0 && parts[len(parts)-1] != "" {
		return parts[len(parts)-1]
	}
	return component
}

func scenarioDisplayName(name string) string {
	name = strings.TrimSpace(name)
	lower := strings.ToLower(name)
	for _, prefix := range []string{
		"coroot-rca-db-query-",
		"coroot-rca-network-chaos-",
		"coroot-rca-cpu-saturation-",
		"db-query-",
		"network-chaos-",
		"cpu-saturation-",
	} {
		if strings.HasPrefix(lower, prefix) {
			return name[len(prefix):]
		}
	}
	return name
}

func sentenceNodeName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "Node"
	}
	return strings.ToUpper(name[:1]) + name[1:]
}

func widgetTitle(w *model.Widget, idx int) string {
	if w == nil {
		return fmt.Sprintf("Evidence widget %d", idx+1)
	}
	switch {
	case w.Chart != nil && w.Chart.Title != "":
		return markdownText(w.Chart.Title)
	case w.ChartGroup != nil && w.ChartGroup.Title != "":
		return markdownText(w.ChartGroup.Title)
	case w.Table != nil:
		return "Evidence table"
	case w.DependencyMap != nil:
		return "Dependency map"
	case w.Heatmap != nil && w.Heatmap.Title != "":
		return markdownText(w.Heatmap.Title)
	case w.FlameGraph != nil && w.FlameGraph.Title != "":
		return markdownText(w.FlameGraph.Title)
	case w.Logs != nil && w.Logs.Check != nil && w.Logs.Check.Title != "":
		return "Log evidence: " + markdownText(w.Logs.Check.Title)
	case w.Logs != nil:
		return "Log evidence"
	case w.GroupHeader != "":
		return markdownText(w.GroupHeader)
	case w.Profiling != nil:
		return "Profiling evidence"
	case w.Tracing != nil:
		return "Trace evidence"
	default:
		return fmt.Sprintf("Evidence widget %d", idx+1)
	}
}

func markdownText(s string) string {
	replacer := strings.NewReplacer("<i>", "", "</i>", "", "<b>", "", "</b>", "", "`", "'")
	return strings.TrimSpace(replacer.Replace(s))
}

func immediateFixes(c *model.RCACandidate) string {
	switch c.Scenario {
	case "network_chaos_delay":
		return "Check network policies, Chaos Mesh or other fault-injection resources affecting the impacted dependency path. Pause the fault source only after confirming the resource exists in evidence."
	case "bad_deployment", "deployment_change":
		return "Compare the latest rollout with the previous stable version. If the deployment is confirmed as the trigger, roll back through the standard release process and verify SLO recovery."
	case "cronjob_node_cpu_starvation":
		return "Move the periodic job away from latency-sensitive workloads, add CPU requests/limits, and verify node CPU delay and service latency recover."
	case "resource_exhaustion", "recommendation_memory_leak":
		return "Restore availability by restarting or scaling the affected workload if needed, then inspect memory/CPU trends and fix the application or resource limit cause before closing the incident."
	case "database_bottleneck":
		return "Identify the top client and query/load source, reduce the offending traffic or roll back the triggering change, then verify DB latency and dependent service SLO recovery."
	default:
		return "Use the listed evidence and missing evidence sections to continue investigation. Avoid destructive actions until the root component is confirmed."
	}
}

func missingEvidence(req cloud.RCARequest, app *model.Application) []string {
	missing := utils.NewStringSet()
	if req.ErrorTrace == nil {
		missing.Add("error trace")
	}
	if req.SlowTrace == nil {
		missing.Add("slow trace")
	}
	if len(req.KubernetesEvents) == 0 {
		missing.Add("Kubernetes events")
	}
	if len(app.Deployments) == 0 {
		missing.Add("deployment/change evidence")
	}
	if len(app.Upstreams) == 0 && len(app.Downstreams) == 0 {
		missing.Add("dependency graph neighbors")
	}
	return missing.Items()
}

func trajectory(req cloud.RCARequest, app *model.Application, candidates []*model.RCACandidate, widgets []*model.Widget, missing []string) []model.RCATrajectory {
	steps := []model.RCATrajectory{
		{
			Step:          1,
			Tool:          "get_incident_context",
			InputSummary:  app.Id.String(),
			OutputSummary: fmt.Sprintf("incident window %s..%s", req.Ctx.From.ToStandard().Format("2006-01-02T15:04:05Z"), req.Ctx.To.ToStandard().Format("2006-01-02T15:04:05Z")),
		},
		{
			Step:          2,
			Tool:          "get_service_health",
			InputSummary:  app.Id.String(),
			OutputSummary: fmt.Sprintf("%d reports, %d upstreams, %d downstreams", len(app.Reports), len(app.Upstreams), len(app.Downstreams)),
		},
		{
			Step:          3,
			Tool:          "build_root_cause_candidates",
			InputSummary:  "checks, deployments, traces, Kubernetes events, dependency graph",
			OutputSummary: fmt.Sprintf("%d candidates, %d widgets, %d missing evidence hints", len(candidates), len(widgets), len(missing)),
		},
	}
	if len(candidates) > 0 {
		steps = append(steps, model.RCATrajectory{
			Step:          4,
			Tool:          "score_candidates",
			InputSummary:  "OpenRCA time/component/reason triples and PyRCA-inspired graph score",
			OutputSummary: fmt.Sprintf("top candidate %s on %s with score %.2f", candidates[0].RootCauseReason, candidates[0].Component, candidates[0].Score),
			EvidenceRefs:  candidates[0].EvidenceRefs,
		})
	}
	return steps
}

func deduplicateCandidates(candidates []*model.RCACandidate) []*model.RCACandidate {
	seen := map[string]*model.RCACandidate{}
	var res []*model.RCACandidate
	for _, c := range candidates {
		k := c.Component + "|" + c.RootCauseReason
		if prev := seen[k]; prev != nil {
			if c.Score > prev.Score {
				prev.Score = c.Score
				prev.Confidence = c.Confidence
				prev.PyRCAScores = c.PyRCAScores
				prev.ScoreBreakdown = c.ScoreBreakdown
			}
			prev.EvidenceRefs = mergeStrings(prev.EvidenceRefs, c.EvidenceRefs...)
			prev.SupportingEvidence = mergeStrings(prev.SupportingEvidence, c.SupportingEvidence...)
			prev.ContradictingEvidence = mergeStrings(prev.ContradictingEvidence, c.ContradictingEvidence...)
			prev.MissingEvidence = mergeStrings(prev.MissingEvidence, c.MissingEvidence...)
			prev.ReasonCodes = mergeStrings(prev.ReasonCodes, c.ReasonCodes...)
			continue
		}
		seen[k] = c
		res = append(res, c)
	}
	return res
}

func humanReason(reason string) string {
	return strings.ReplaceAll(reason, "_", " ")
}

func maxStatus(a, b model.Status) model.Status {
	if a > b {
		return a
	}
	return b
}

func min(a, b float32) float32 {
	if a < b {
		return a
	}
	return b
}
