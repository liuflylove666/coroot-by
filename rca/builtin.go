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
	widgets := evidenceWidgets(world, app, pm)
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
			candidate.Score = scoreCandidate(candidate, app, 0, len(ch.Widgets)+len(r.Widgets), 1)
			candidate.PyRCAScores = pyRCAScores(candidate, app, 0, len(candidate.EvidenceRefs))
			candidates = append(candidates, candidate)
		}
	}
	candidates = append(candidates, periodicJobCPUCandidates(req, world, app, len(candidates))...)
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

	if len(app.Deployments) > 0 {
		for _, d := range app.Deployments {
			if d.StartedAt.Before(req.Ctx.From.Add(-30*timeseries.Minute)) || d.StartedAt.After(req.Ctx.To) {
				continue
			}
			reason, scenario := "recent_deployment", "deployment_change"
			if hasUnhealthyDatabaseUpstream(app) {
				reason, scenario = "bad_deployment_db_query_amplification", "bad_deployment_db_query_amplification"
			}
			candidate := newCandidate(len(candidates)+1, d.StartedAt, app, reason, scenario)
			candidate.ReasonCodes = append(candidate.ReasonCodes, "deployment_in_incident_window")
			candidate.EvidenceRefs = append(candidate.EvidenceRefs, "deployment:"+d.Id())
			candidate.Score = scoreCandidate(candidate, app, 0, 1, 1)
			candidate.PyRCAScores = pyRCAScores(candidate, app, 0, len(candidate.EvidenceRefs))
			candidates = append(candidates, candidate)
			break
		}
	}

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
	case strings.HasPrefix(ref, "k8s:"):
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
	appName := app.Id.Name
	if appName == "" {
		appName = app.Id.String()
	}
	if top.RootCauseReason == "insufficient_evidence" {
		rca.ShortSummary = fmt.Sprintf("Built-in RCA found SLO degradation in %s, but available evidence is insufficient to name a deterministic root cause.", appName)
		rca.RootCause = "The built-in RCA engine found an incident impact but did not find enough grounded evidence to select a deterministic root cause."
	} else if top.Scenario == "network_chaos_delay" {
		src, dst := dependencyComponentNames(top.Component)
		if src != "" && dst != "" {
			rca.ShortSummary = fmt.Sprintf("Network degradation on `%s` -> `%s` is the most likely root cause for `%s` impact.", src, dst, appName)
			rca.RootCause = fmt.Sprintf("The `%s` impact is most likely caused by network latency or connectivity degradation on the `%s` -> `%s` dependency path. Coroot selected this because the candidate scored %.0f%% and is backed by evidence refs: %s.", appName, src, dst, top.Score*100, evidenceRefs(top))
		} else {
			rca.ShortSummary = fmt.Sprintf("Network degradation is the most likely root cause for `%s` impact.", appName)
			rca.RootCause = fmt.Sprintf("The `%s` impact is most likely caused by network latency or connectivity degradation. Coroot selected this because the candidate scored %.0f%% and is backed by evidence refs: %s.", appName, top.Score*100, evidenceRefs(top))
		}
	} else if isCPUContentionCandidate(top) {
		trigger := cpuTriggerDisplayName(top)
		node := cpuNodeDisplayName(top)
		rca.ShortSummary = fmt.Sprintf("%s CPU saturation is the most likely root cause for `%s` impact.", trigger, appName)
		rca.RootCause = fmt.Sprintf("The `%s` impact is most likely caused by `%s` saturating CPU on `%s`, which created CPU delay and propagated latency/errors through the dependency path. Coroot selected this because the candidate scored %.0f%% and is backed by evidence refs: %s.", appName, trigger, node, top.Score*100, evidenceRefs(top))
	} else {
		rca.ShortSummary = fmt.Sprintf("Built-in RCA ranked %s as the most likely root cause for %s impact.", humanReason(top.RootCauseReason), appName)
		rca.RootCause = fmt.Sprintf("Most likely root cause: `%s` on `%s` with %.0f%% confidence score. The conclusion is based on Coroot evidence refs: %s.", top.RootCauseReason, top.Component, top.Score*100, strings.Join(top.EvidenceRefs, ", "))
	}
	var details strings.Builder
	rootWidgets, cascadingWidgets, traceWidgets := classifyWidgets(rca.Widgets)

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
	rca.ImmediateFixes = immediateFixes(top)
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
	return "`" + strings.Join(c.EvidenceRefs, "`, `") + "`"
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
	b.WriteString("### What happened\n\n")
	if pma := propagationMapApplication(pm, app); pma != nil && len(pma.Issues) > 0 {
		b.WriteString(fmt.Sprintf("The `%s` service reported `%s` during the incident window. The relationship map above keeps the impact grounded in the observed dependency graph.\n\n", appName, strings.Join(pma.Issues, "`, `")))
	} else {
		b.WriteString(fmt.Sprintf("The `%s` service showed user-visible impact during the incident window. The relationship map above keeps the impact grounded in the observed dependency graph.\n\n", appName))
	}

	b.WriteString("### Following the dependency chain\n\n")
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

	b.WriteString("### The trigger\n\n")
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
	name := componentDisplayName(c.Component)
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
		return id.Name
	}
	return id.String()
}

func dependencyComponentNames(component string) (string, string) {
	parts := strings.Split(component, "->")
	if len(parts) != 2 {
		return "", ""
	}
	return componentDisplayName(parts[0]), componentDisplayName(parts[1])
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
