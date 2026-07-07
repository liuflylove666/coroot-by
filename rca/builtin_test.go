package rca

import (
	"fmt"
	"strings"
	"testing"

	"github.com/coroot/coroot/cloud"
	"github.com/coroot/coroot/model"
	"github.com/coroot/coroot/timeseries"
)

func TestRenderSummaryEmbedsEvidenceWidgets(t *testing.T) {
	app := model.NewApplication(model.NewApplicationId("test", "default", model.ApplicationKindDeployment, "checkout"))
	candidate := &model.RCACandidate{
		Id:              "h-001",
		Component:       app.Id.String(),
		RootCauseReason: "application_error_logs",
		Scenario:        "log_error_spike",
		Score:           0.81,
		Confidence:      "high",
		EvidenceRefs:    []string{"check:LogErrors"},
		PyRCAScores:     &model.PyRCAScores{Combined: 0.88},
	}
	rca := &model.RCA{
		Widgets: []*model.Widget{
			{Chart: model.NewChart(timeseries.Context{}, "Latency, seconds")},
			{Logs: &model.Logs{ApplicationId: app.Id, Check: &model.Check{Title: "Errors"}}},
		},
		PropagationMap: &model.PropagationMap{Applications: []*model.PropagationMapApplication{
			{Id: app.Id, Status: model.CRITICAL, Issues: []string{"Errors", "Latency"}},
		}},
	}

	renderSummary(rca, app, []*model.RCACandidate{candidate}, []string{"slow trace"}, &model.ApplicationIncident{Key: "abc123"}, cloud.RCARequest{})

	for _, want := range []string{
		"## Incident Overview",
		"## Root Cause: application error logs",
		"## Cascading Impact",
		"## Trace Evidence",
		"## Kubernetes Events Confirmation",
		"WIDGET-0",
		"WIDGET-1",
		"The related trace and log evidence panels are rendered below.",
	} {
		if !strings.Contains(rca.DetailedRootCause, want) {
			t.Fatalf("expected detailed RCA to contain %q:\n%s", want, rca.DetailedRootCause)
		}
	}
}

func TestPropagationMapBuildsBidirectionalEdgesAndNodeIssues(t *testing.T) {
	front := model.NewApplication(model.NewApplicationId("test", "default", model.ApplicationKindDeployment, "front-end"))
	catalog := model.NewApplication(model.NewApplicationId("test", "default", model.ApplicationKindDeployment, "catalog"))
	db := model.NewApplication(model.NewApplicationId("test", "default", model.ApplicationKindStatefulSet, "db-main"))
	for _, app := range []*model.Application{front, catalog, db} {
		app.Reports = []*model.AuditReport{
			{
				Name:   model.AuditReportSLO,
				Status: model.WARNING,
				Checks: []*model.Check{
					{Id: model.Checks.SLOLatency.Id, Title: "Latency", Status: model.WARNING},
				},
			},
		}
	}
	frontCatalog := &model.AppToAppConnection{Application: front, RemoteApplication: catalog}
	catalogDB := &model.AppToAppConnection{
		Application:           catalog,
		RemoteApplication:     db,
		Rtt:                   testSeries(0.5),
		SuccessfulConnections: testSeries(10),
		ConnectionTime:        testSeries(2),
	}
	front.Upstreams[catalog.Id] = frontCatalog
	catalog.Downstreams[front.Id] = frontCatalog
	catalog.Upstreams[db.Id] = catalogDB
	db.Downstreams[catalog.Id] = catalogDB

	pm := propagationMap(front, nil)
	apps := map[string]*model.PropagationMapApplication{}
	for _, app := range pm.Applications {
		apps[app.Id.Name] = app
	}

	for _, name := range []string{"front-end", "catalog", "db-main"} {
		if apps[name] == nil {
			t.Fatalf("expected propagation map to contain %s: %+v", name, pm.Applications)
		}
	}
	if !hasLink(apps["front-end"].Upstreams, catalog.Id, "") {
		t.Fatalf("expected front-end -> catalog upstream link: %+v", apps["front-end"].Upstreams)
	}
	if !hasLink(apps["front-end"].Upstreams, catalog.Id, "Latency") {
		t.Fatalf("expected front-end -> catalog edge to expose propagated latency: %+v", apps["front-end"].Upstreams)
	}
	if !hasLink(apps["catalog"].Downstreams, front.Id, "") {
		t.Fatalf("expected catalog downstream back-link to front-end: %+v", apps["catalog"].Downstreams)
	}
	if !hasLink(apps["catalog"].Upstreams, db.Id, "") {
		t.Fatalf("expected catalog -> db-main upstream link: %+v", apps["catalog"].Upstreams)
	}
	if !hasLink(apps["catalog"].Upstreams, db.Id, "Latency") {
		t.Fatalf("expected catalog -> db-main edge to expose latency evidence: %+v", apps["catalog"].Upstreams)
	}
	if !hasIssue(apps["catalog"], "TCP network latency to <i>db-main</i>") || !hasIssue(apps["catalog"], "TCP connection latency to <i>db-main</i>") {
		t.Fatalf("expected catalog node to include network evidence to db-main: %+v", apps["catalog"].Issues)
	}
	if !hasLink(apps["db-main"].Downstreams, catalog.Id, "") {
		t.Fatalf("expected db-main downstream back-link to catalog: %+v", apps["db-main"].Downstreams)
	}
}

func TestFocusPropagationMapLimitsExternalFanout(t *testing.T) {
	front := model.NewApplication(model.NewApplicationId("test", "default", model.ApplicationKindDeployment, "front-end"))
	front.Status = model.CRITICAL
	openresty := model.NewApplication(model.NewApplicationId("test", "default", model.ApplicationKindDeployment, "openresty"))
	openresty.Status = model.CRITICAL
	downstream := &model.AppToAppConnection{Application: openresty, RemoteApplication: front}
	openresty.Upstreams[front.Id] = downstream
	front.Downstreams[openresty.Id] = downstream

	var seededExternal model.ApplicationId
	for i := 0; i < 10; i++ {
		ext := model.NewApplication(model.NewApplicationId("external", "external", model.ApplicationKindExternalService, fmt.Sprintf("cache-%02d.very-long-service-name.example.com:6379", i)))
		ext.Status = model.WARNING
		if i == 0 {
			seededExternal = ext.Id
		}
		conn := &model.AppToAppConnection{
			Application:           front,
			RemoteApplication:     ext,
			Rtt:                   testSeries(0.5),
			SuccessfulConnections: testSeries(10),
			ConnectionTime:        testSeries(2),
		}
		front.Upstreams[ext.Id] = conn
		ext.Downstreams[front.Id] = conn
	}

	pm := propagationMap(front, nil)
	if len(pm.Applications) <= maxRCAPropagationApplications {
		t.Fatalf("test setup should create a large propagation map, got %d", len(pm.Applications))
	}
	top := &model.RCACandidate{
		Component:       front.Id.String(),
		RootCauseReason: "network_connectivity_or_latency",
		Scenario:        "network_chaos_delay",
		PyRCAScores:     &model.PyRCAScores{GraphPaths: [][]string{{front.Id.String(), seededExternal.String()}}},
	}
	focused := focusPropagationMap(pm, front, top)
	if got := len(focused.Applications); got > maxRCAPropagationApplications {
		t.Fatalf("expected focused propagation map to have at most %d applications, got %d", maxRCAPropagationApplications, got)
	}
	external := 0
	apps := map[string]*model.PropagationMapApplication{}
	for _, a := range focused.Applications {
		apps[a.Id.String()] = a
		if a.Id.Kind == model.ApplicationKindExternalService {
			external++
		}
	}
	if external > maxRCAExternalPropagationApplications {
		t.Fatalf("expected at most %d external services, got %d", maxRCAExternalPropagationApplications, external)
	}
	for _, id := range []model.ApplicationId{front.Id, openresty.Id, seededExternal} {
		if apps[id.String()] == nil {
			t.Fatalf("expected focused propagation map to keep %s: %+v", id, focused.Applications)
		}
	}
}

func TestKubernetesEventsFilterUnrelatedEvents(t *testing.T) {
	app := model.NewApplication(model.NewApplicationId("test", "default", model.ApplicationKindDeployment, "checkout"))
	candidate := &model.RCACandidate{
		Id:              "h-001",
		Component:       app.Id.String(),
		RootCauseReason: "application_error_logs",
		Scenario:        "log_error_spike",
		Score:           0.8,
		Confidence:      "high",
		EvidenceRefs:    []string{"check:LogErrors"},
	}
	rca := &model.RCA{
		PropagationMap: &model.PropagationMap{Applications: []*model.PropagationMapApplication{
			{Id: app.Id, Status: model.CRITICAL, Issues: []string{"Errors"}},
		}},
		Widgets: []*model.Widget{},
	}
	req := cloud.RCARequest{
		KubernetesEvents: []*model.LogEntry{
			{Body: "Back-off restarting failed container fluidity-spot-fox in pod fluidity-spot-fox-55c45ccc64-mv8rs_default"},
			{Body: "Readiness probe failed for checkout-7dc9bd9d8f-jtr6x"},
		},
	}
	renderSummary(rca, app, []*model.RCACandidate{candidate}, nil, &model.ApplicationIncident{ApplicationId: app.Id, Key: "event", OpenedAt: timeseries.Time(1000), Severity: model.CRITICAL}, req)
	if strings.Contains(rca.DetailedRootCause, "fluidity-spot-fox") {
		t.Fatalf("unrelated Kubernetes event should not be rendered as confirmation:\n%s", rca.DetailedRootCause)
	}
	if !strings.Contains(rca.DetailedRootCause, "checkout-7dc9bd9d8f-jtr6x") {
		t.Fatalf("expected related Kubernetes event in details:\n%s", rca.DetailedRootCause)
	}
}

func testSeries(v float32) *timeseries.TimeSeries {
	return timeseries.NewWithData(0, timeseries.Minute, []float32{v})
}

func hasLink(links []*model.PropagationMapApplicationLink, id model.ApplicationId, stat string) bool {
	for _, link := range links {
		if link.Id != id {
			continue
		}
		if stat == "" {
			return true
		}
		return link.Stats != nil && link.Stats.Has(stat)
	}
	return false
}

func widgetTitlesForTest(widgets []*model.Widget) string {
	var titles []string
	for i, w := range widgets {
		titles = append(titles, widgetTitle(w, i))
	}
	return strings.Join(titles, "\n")
}

func linkHasStats(links []*model.PropagationMapApplicationLink, id model.ApplicationId) bool {
	for _, link := range links {
		if link.Id == id {
			return link.Stats != nil && link.Stats.Len() > 0
		}
	}
	return false
}

func hasIssue(app *model.PropagationMapApplication, issue string) bool {
	for _, got := range app.Issues {
		if got == issue {
			return true
		}
	}
	return false
}

func TestDemoReferenceFixtureBuildsNetworkDelayCascade(t *testing.T) {
	t.Setenv(officialDemoScenarioEnv, "mqxss00z")
	app := model.NewApplication(model.NewApplicationId("test", "default", model.ApplicationKindDeployment, "coroot-incident-bad-api"))
	ctx := timeseries.NewContext(timeseries.Time(1000), timeseries.Time(4600), timeseries.Minute)
	rca := demoOfficialRCA(cloud.RCARequest{ApplicationId: app.Id, Ctx: ctx}, &model.ApplicationIncident{ApplicationId: app.Id, Key: "demo"}, app)
	if rca == nil {
		t.Fatalf("expected official demo fixture RCA")
	}
	if got := len(rca.PropagationMap.Applications); got != 4 {
		t.Fatalf("expected 4 mqxss00z official demo applications, got %d", got)
	}
	apps := map[string]*model.PropagationMapApplication{}
	for _, app := range rca.PropagationMap.Applications {
		apps[app.Id.Name] = app
	}
	for _, name := range []string{"front-end", "order", "catalog", "db-main"} {
		if apps[name] == nil {
			t.Fatalf("expected %s in propagation map", name)
		}
	}
	if !hasLink(apps["front-end"].Upstreams, apps["catalog"].Id, "") {
		t.Fatalf("expected front-end -> catalog edge")
	}
	if !hasLink(apps["front-end"].Upstreams, apps["order"].Id, "") {
		t.Fatalf("expected front-end -> order edge")
	}
	if !hasLink(apps["order"].Upstreams, apps["catalog"].Id, "") {
		t.Fatalf("expected order -> catalog edge")
	}
	if !hasLink(apps["catalog"].Upstreams, apps["db-main"].Id, "") {
		t.Fatalf("expected catalog -> db-main root edge")
	}
	if linkHasStats(apps["catalog"].Upstreams, apps["db-main"].Id) {
		t.Fatalf("mqxss00z topology should not render edge labels: %+v", apps["catalog"].Upstreams)
	}
	if !hasIssue(apps["catalog"], "TCP network latency to <i>db-main</i>") || !hasIssue(apps["catalog"], "TCP connection latency to <i>db-main</i>") {
		t.Fatalf("expected catalog network issues in node card: %+v", apps["catalog"].Issues)
	}
	if got := len(rca.Widgets); got != 4 {
		t.Fatalf("expected mqxss00z detail widget set, got %d widgets", got)
	}
	for i, w := range rca.Widgets {
		if w.Logs != nil {
			t.Fatalf("official detail fixture should render log evidence as charts, not AppLogs query widget: widget=%d", i)
		}
	}
	for _, want := range []string{
		"## Incident Overview",
		"## Cascading Impact",
		"## Trace Evidence",
		"NetworkChaos experiment `net-delay-catalog-pg-bwpfn`",
		"WIDGET-3",
	} {
		if !strings.Contains(rca.DetailedRootCause, want) {
			t.Fatalf("expected detailed RCA to contain %q:\n%s", want, rca.DetailedRootCause)
		}
	}
	if strings.Contains(rca.DetailedRootCause, "WIDGET-4") {
		t.Fatalf("unexpected AppLogs widget reference in detailed RCA:\n%s", rca.DetailedRootCause)
	}
	if !strings.Contains(rca.ImmediateFixes, "kubectl delete networkchaos net-delay-catalog-pg-bwpfn -n default") {
		t.Fatalf("expected official immediate fix commands:\n%s", rca.ImmediateFixes)
	}
	if rca.Candidates[0].Scenario != "network_chaos_delay" {
		t.Fatalf("expected network_chaos_delay, got %+v", rca.Candidates[0])
	}
	if rca.Candidates[0].ScoreBreakdown == nil || rca.Candidates[0].ScoreBreakdown.Final == 0 {
		t.Fatalf("expected candidate score breakdown: %+v", rca.Candidates[0])
	}
	if !hasString(rca.Candidates[0].SupportingEvidence, "score:"+rca.Candidates[0].Id) {
		t.Fatalf("expected candidate supporting evidence to include score evidence: %+v", rca.Candidates[0].SupportingEvidence)
	}
	if !hasEvidence(rca.Evidence, "widget:3") || !hasEvidence(rca.Evidence, "score:"+rca.Candidates[0].Id) {
		t.Fatalf("expected evidence registry to include widget and score evidence: %+v", rca.Evidence)
	}
	if !hasEvidence(rca.Evidence, "edge:"+apps["catalog"].Id.String()+"->"+apps["db-main"].Id.String()) {
		t.Fatalf("expected evidence registry to include catalog -> db-main edge evidence: %+v", rca.Evidence)
	}
	for _, step := range rca.Trajectory {
		if len(step.EvidenceChain) == 0 {
			t.Fatalf("expected trajectory step to include evidence chain: %+v", step)
		}
	}
	if rca.Grounding == nil || rca.Grounding.EvidenceCoverage < 1 {
		t.Fatalf("expected fully covered fixture RCA, got %+v", rca.Grounding)
	}
	if rca.Grounding.Status != "unsafe" || !hasString(rca.Grounding.Issues, "destructive kubectl command requires human approval") {
		t.Fatalf("expected official delete command to require human review, got %+v", rca.Grounding)
	}
}

func TestPostProcessAnnotatesCompetingHypothesis(t *testing.T) {
	top := &model.RCACandidate{
		Id:              "c-network",
		Component:       "test:default:Deployment:catalog",
		RootCauseReason: "network_chaos_delay",
		Scenario:        "network_chaos_delay",
		Score:           0.93,
		EvidenceRefs:    []string{"k8s-event:networkchaos/net-delay-catalog-pg", "edge:catalog->db-main"},
	}
	alt := &model.RCACandidate{
		Id:              "c-db-query",
		Component:       "test:default:Deployment:catalog",
		RootCauseReason: "bad_deployment_db_query_amplification",
		Scenario:        "bad_deployment_db_query_amplification",
		Score:           0.88,
		EvidenceRefs:    []string{"trace:db_statement:select-from-recommendations", "deployment:catalog"},
	}
	rca := &model.RCA{
		RootCause:         "network_chaos_delay on catalog",
		DetailedRootCause: "network_chaos_delay evidence points to catalog before db-main latency.",
		ImmediateFixes:    "Verify the NetworkChaos evidence before changing production.",
		Candidates:        []*model.RCACandidate{top, alt},
		Trajectory: []model.RCATrajectory{
			{Step: 1, Tool: "score_candidates", EvidenceRefs: []string{"k8s-event:networkchaos/net-delay-catalog-pg"}, EvidenceChain: []string{"k8s-event:networkchaos/net-delay-catalog-pg"}},
		},
	}
	rootBefore := rca.RootCause

	PostProcess(rca)

	if rca.RootCause != rootBefore {
		t.Fatalf("competing hypothesis annotation must not rewrite visible root cause: %q", rca.RootCause)
	}
	if !hasString(top.SupportingEvidence, "winner_margin:0.05") {
		t.Fatalf("expected winner margin supporting evidence: %+v", top.SupportingEvidence)
	}
	foundAlternative := false
	for _, e := range top.ContradictingEvidence {
		if strings.Contains(e, "alternative:bad_deployment_db_query_amplification") && strings.Contains(e, "score=0.88") {
			foundAlternative = true
			break
		}
	}
	if !foundAlternative {
		t.Fatalf("expected close competing hypothesis in contradicting evidence: %+v", top.ContradictingEvidence)
	}
	var comparison *model.RCATrajectory
	for i := range rca.Trajectory {
		if rca.Trajectory[i].Tool == "compare_competing_hypotheses" {
			comparison = &rca.Trajectory[i]
			break
		}
	}
	if comparison == nil {
		t.Fatalf("expected trajectory to include competing hypothesis comparison: %+v", rca.Trajectory)
	}
	for _, want := range []string{"k8s-event:networkchaos/net-delay-catalog-pg", "trace:db_statement:select-from-recommendations"} {
		if !hasString(comparison.EvidenceChain, want) {
			t.Fatalf("expected comparison evidence chain to include %q: %+v", want, comparison.EvidenceChain)
		}
	}

	PostProcess(rca)
	count := 0
	for _, step := range rca.Trajectory {
		if step.Tool == "compare_competing_hypotheses" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("competing hypothesis annotation must be idempotent, got %d comparison steps", count)
	}
}

func TestPostProcessAuditsSingleCandidateConfidence(t *testing.T) {
	top := &model.RCACandidate{
		Id:              "c-network",
		Component:       "test:default:Deployment:catalog",
		RootCauseReason: "network_chaos_delay",
		Scenario:        "network_chaos_delay",
		Score:           0.93,
		Confidence:      "high",
		EvidenceRefs:    []string{"k8s-event:networkchaos/net-delay-catalog-pg", "edge:catalog->db-main"},
	}
	rca := &model.RCA{
		RootCause:         "network_chaos_delay on catalog",
		DetailedRootCause: "network_chaos_delay evidence points to catalog before db-main latency.",
		ImmediateFixes:    "Verify the NetworkChaos evidence before changing production.",
		Candidates:        []*model.RCACandidate{top},
		Trajectory: []model.RCATrajectory{
			{Step: 1, Tool: "score_candidates", EvidenceRefs: []string{"k8s-event:networkchaos/net-delay-catalog-pg"}, EvidenceChain: []string{"k8s-event:networkchaos/net-delay-catalog-pg"}},
		},
	}

	PostProcess(rca)

	if !hasString(top.SupportingEvidence, "candidate_audit:single_candidate") {
		t.Fatalf("expected single-candidate audit supporting evidence: %+v", top.SupportingEvidence)
	}
	var audit *model.RCATrajectory
	for i := range rca.Trajectory {
		if rca.Trajectory[i].Tool == "audit_candidate_confidence" {
			audit = &rca.Trajectory[i]
			break
		}
	}
	if audit == nil {
		t.Fatalf("expected confidence audit trajectory step: %+v", rca.Trajectory)
	}
	for _, want := range top.EvidenceRefs {
		if !hasString(audit.EvidenceChain, want) {
			t.Fatalf("expected confidence audit evidence chain to include %q: %+v", want, audit.EvidenceChain)
		}
	}
}

func TestDemoOfficialZ14FixtureIsPreserved(t *testing.T) {
	t.Setenv(officialDemoScenarioEnv, "z14gocke")
	app := model.NewApplication(model.NewApplicationId("test", "default", model.ApplicationKindDeployment, "coroot-incident-bad-api"))
	ctx := timeseries.NewContext(timeseries.Time(1000), timeseries.Time(4600), timeseries.Minute)
	rca := demoOfficialRCA(cloud.RCARequest{ApplicationId: app.Id, Ctx: ctx}, &model.ApplicationIncident{ApplicationId: app.Id, Key: "demo"}, app)
	if rca == nil {
		t.Fatalf("expected z14gocke fixture RCA")
	}
	if got := len(rca.PropagationMap.Applications); got != 6 {
		t.Fatalf("expected 6 z14gocke applications, got %d", got)
	}
	if rca.Candidates[0].Scenario != "cronjob_node_cpu_starvation" {
		t.Fatalf("expected cronjob_node_cpu_starvation, got %+v", rca.Candidates[0])
	}
	if !strings.Contains(rca.DetailedRootCause, "## Root Cause: analytics-updater CronJob saturated node3 CPU") {
		t.Fatalf("expected z14gocke details to be preserved:\n%s", rca.DetailedRootCause)
	}
}

func TestEvidenceWidgetsUseOfficialEvidenceOnly(t *testing.T) {
	world := model.NewWorld(1000, 4600, timeseries.Minute, timeseries.Minute)
	app := model.NewApplication(model.NewApplicationId("test", "default", model.ApplicationKindDeployment, "checkout"))
	app.Reports = []*model.AuditReport{
		{
			Name:   model.AuditReportSLO,
			Status: model.CRITICAL,
			Widgets: []*model.Widget{
				{Chart: model.NewChart(world.Ctx, "Latency, seconds")},
				{Logs: &model.Logs{ApplicationId: app.Id, Check: &model.Check{Title: "Log errors"}}},
				{Tracing: &model.Tracing{ApplicationId: app.Id}},
				{Profiling: &model.Profiling{ApplicationId: app.Id}},
			},
		},
	}

	widgets := evidenceWidgets(world, app, nil)
	if len(widgets) != 1 {
		t.Fatalf("expected only chart evidence widget, got %d", len(widgets))
	}
	for _, w := range widgets {
		if w.Logs != nil || w.Tracing != nil || w.Profiling != nil {
			t.Fatalf("interactive query widgets must not be embedded in RCA details: %+v", w)
		}
	}
}

func TestProductionNetworkCandidateUsesConnectionEvidence(t *testing.T) {
	front := model.NewApplication(model.NewApplicationId("test", "default", model.ApplicationKindDeployment, "front-end"))
	catalog := model.NewApplication(model.NewApplicationId("test", "default", model.ApplicationKindDeployment, "catalog"))
	db := model.NewApplication(model.NewApplicationId("test", "default", model.ApplicationKindStatefulSet, "db-main"))
	front.Upstreams[catalog.Id] = &model.AppToAppConnection{Application: front, RemoteApplication: catalog}
	catalog.Downstreams[front.Id] = front.Upstreams[catalog.Id]
	catalog.Upstreams[db.Id] = &model.AppToAppConnection{
		Application:           catalog,
		RemoteApplication:     db,
		Rtt:                   testSeries(0.8),
		SuccessfulConnections: testSeries(10),
		ConnectionTime:        testSeries(3),
	}
	db.Downstreams[catalog.Id] = catalog.Upstreams[db.Id]

	candidates := buildCandidates(cloud.RCARequest{
		ApplicationId: front.Id,
		Ctx:           timeseries.NewContext(0, 3600, timeseries.Minute),
		KubernetesEvents: []*model.LogEntry{
			{Body: "NetworkChaos net-delay-catalog-pg applied to catalog targeting db-main"},
		},
	}, nil, front)

	var network *model.RCACandidate
	for _, c := range candidates {
		if c.Scenario == "network_chaos_delay" && strings.Contains(c.Component, "catalog") && strings.Contains(c.Component, "db-main") {
			network = c
			break
		}
	}
	if network == nil {
		t.Fatalf("expected production network dependency candidate, got %+v", candidates)
	}
	for _, want := range []string{"link:" + catalog.Id.String() + "->" + db.Id.String(), "k8s:event"} {
		if !hasString(network.EvidenceRefs, want) {
			t.Fatalf("expected evidence ref %q in %+v", want, network.EvidenceRefs)
		}
	}
	if network.ScoreBreakdown == nil || network.ScoreBreakdown.Final == 0 {
		t.Fatalf("expected scored production network candidate: %+v", network)
	}
}

func TestProductionCronJobCPUContentionCandidateAndDetails(t *testing.T) {
	world := model.NewWorld(0, 3600, timeseries.Minute, timeseries.Minute)
	front := model.NewApplication(model.NewApplicationId("test", "default", model.ApplicationKindDeployment, "front-end"))
	front.Status = model.CRITICAL
	catalog := model.NewApplication(model.NewApplicationId("test", "default", model.ApplicationKindDeployment, "catalog"))
	db := model.NewApplication(model.NewApplicationId("test", "default", model.ApplicationKindStatefulSet, "db-main"))
	cron := model.NewApplication(model.NewApplicationId("test", "default", model.ApplicationKindCronJob, "analytics-updater"))
	cron.Status = model.CRITICAL
	cron.Reports = []*model.AuditReport{
		{
			Name:   model.AuditReportCPU,
			Status: model.CRITICAL,
			Checks: []*model.Check{
				{
					Id:      model.Checks.CPUNode.Id,
					Status:  model.CRITICAL,
					Message: "analytics-updater caused node3 CPU saturation",
					Widgets: []*model.Widget{
						{Chart: model.NewChart(world.Ctx, "Node CPU usage on <i>node3</i>, %")},
						{Chart: model.NewChart(world.Ctx, "CPU consumers on <i>node3</i>, cores")},
					},
				},
			},
		},
	}
	front.Upstreams[catalog.Id] = &model.AppToAppConnection{Application: front, RemoteApplication: catalog}
	catalog.Downstreams[front.Id] = front.Upstreams[catalog.Id]
	catalog.Upstreams[db.Id] = &model.AppToAppConnection{Application: catalog, RemoteApplication: db, Rtt: testSeries(0.8)}
	db.Downstreams[catalog.Id] = catalog.Upstreams[db.Id]
	for _, app := range []*model.Application{front, catalog, db, cron} {
		world.Applications[app.Id] = app
	}
	req := cloud.RCARequest{
		ApplicationId: front.Id,
		Ctx:           world.Ctx,
		KubernetesEvents: []*model.LogEntry{
			{Body: "Successfully assigned default/analytics-updater-123 to node3; CPU pressure warning on node3"},
		},
	}
	candidates := buildCandidates(req, world, front)
	var cpu *model.RCACandidate
	for _, c := range candidates {
		if c.Scenario == "cronjob_node_cpu_starvation" && strings.Contains(c.Component, "analytics-updater") {
			cpu = c
			break
		}
	}
	if cpu == nil {
		t.Fatalf("expected cronjob CPU candidate, got %+v", candidates)
	}
	for _, want := range []string{"k8s:event", "node:node3", "check:" + string(model.Checks.CPUNode.Id)} {
		if !hasString(cpu.EvidenceRefs, want) {
			t.Fatalf("expected evidence ref %q in %+v", want, cpu.EvidenceRefs)
		}
	}

	rca := &model.RCA{
		Status:         "OK",
		PropagationMap: propagationMap(front, nil),
		Widgets: []*model.Widget{
			{Chart: model.NewChart(world.Ctx, "Latency, seconds")},
			{Chart: model.NewChart(world.Ctx, "Errors, per second")},
			{Chart: model.NewChart(world.Ctx, "Node CPU usage on <i>node3</i>, %")},
			{Chart: model.NewChart(world.Ctx, "CPU delay of <i>front-end</i>, seconds/second")},
			{Chart: model.NewChart(world.Ctx, "Latency <i>front-end</i> ↔ <i>catalog</i>, seconds")},
			{Chart: model.NewChart(world.Ctx, "TCP retransmissions <i>catalog</i> ↔ <i>db-main</i>, segments/second")},
			{Chart: model.NewChart(world.Ctx, "CPU consumers on <i>node3</i>, cores")},
		},
		Candidates: []*model.RCACandidate{cpu},
	}
	renderSummary(rca, front, []*model.RCACandidate{cpu}, nil, &model.ApplicationIncident{ApplicationId: front.Id, Key: "cpu", OpenedAt: timeseries.Time(1000), Severity: model.CRITICAL}, req)
	for _, want := range []string{
		"## Incident Overview",
		"## CPU saturation on node3",
		"## Cascading Impact",
		"### The analytics-updater CronJob is the trigger",
		"WIDGET-2",
		"WIDGET-6",
	} {
		if !strings.Contains(rca.DetailedRootCause, want) {
			t.Fatalf("expected detailed RCA to contain %q:\n%s", want, rca.DetailedRootCause)
		}
	}
}

func TestProductionDBQueryDeploymentCandidateAndScenarioRenderer(t *testing.T) {
	ctx := timeseries.NewContext(0, 3600, timeseries.Minute)
	front := model.NewApplication(model.NewApplicationId("test", "default", model.ApplicationKindDeployment, "front-end"))
	front.Status = model.CRITICAL
	catalog := model.NewApplication(model.NewApplicationId("test", "default", model.ApplicationKindDeployment, "catalog"))
	db := model.NewApplication(model.NewApplicationId("test", "default", model.ApplicationKindStatefulSet, "db-main"))
	db.Status = model.WARNING
	catalog.Deployments = []*model.ApplicationDeployment{
		{
			ApplicationId: catalog.Id,
			Name:          "catalog-5c66bc476b",
			StartedAt:     timeseries.Time(1200),
			Details:       &model.ApplicationDeploymentDetails{ContainerImages: []string{"catalog:0.50"}},
		},
	}
	front.Upstreams[catalog.Id] = &model.AppToAppConnection{Application: front, RemoteApplication: catalog}
	catalog.Downstreams[front.Id] = front.Upstreams[catalog.Id]
	catalog.Upstreams[db.Id] = &model.AppToAppConnection{Application: catalog, RemoteApplication: db, Rtt: testSeries(0.8)}
	db.Downstreams[catalog.Id] = catalog.Upstreams[db.Id]

	req := cloud.RCARequest{
		ApplicationId: front.Id,
		Ctx:           ctx,
		ErrorTrace:    testDBTrace(),
		KubernetesEvents: []*model.LogEntry{
			{Body: "Scaled up ReplicaSet catalog-5c66bc476b for Deployment catalog; readiness probe failed for catalog-5c66bc476b-abcde"},
		},
	}
	candidates := buildCandidates(req, nil, front)
	var deployment *model.RCACandidate
	for _, c := range candidates {
		if c.Scenario == "bad_deployment_db_query_amplification" && strings.Contains(c.Component, "catalog") {
			deployment = c
			break
		}
	}
	if deployment == nil {
		t.Fatalf("expected upstream catalog deployment DB amplification candidate, got %+v", candidates)
	}
	if !hasString(deployment.EvidenceRefs, "trace:db_statement:"+evidenceSlug(`select * from "products" where brand = ?`)) {
		t.Fatalf("expected DB statement evidence ref in %+v", deployment.EvidenceRefs)
	}

	rca := &model.RCA{
		Status:         "OK",
		PropagationMap: propagationMap(front, nil),
		Widgets: []*model.Widget{
			{Chart: model.NewChart(ctx, "Latency, seconds")},
			{Chart: model.NewChart(ctx, "Postgres queries by total time")},
			{Chart: model.NewChart(ctx, "Latency <i>catalog</i> ↔ <i>db-main</i>, seconds")},
		},
		Candidates: []*model.RCACandidate{deployment},
	}
	renderSummary(rca, front, []*model.RCACandidate{deployment}, nil, &model.ApplicationIncident{ApplicationId: front.Id, Key: "dbq", OpenedAt: timeseries.Time(1000), Severity: model.CRITICAL}, req)
	for _, want := range []string{
		"## Cascading Impact",
		"## Trace Evidence",
		`select * from "products" where brand = ?`,
		"kubectl -n default rollout undo deployment/catalog",
	} {
		if !strings.Contains(rca.DetailedRootCause+"\n"+rca.ImmediateFixes, want) {
			t.Fatalf("expected DB renderer to contain %q:\n%s\nFIXES:\n%s", want, rca.DetailedRootCause, rca.ImmediateFixes)
		}
	}
}

func TestProductionNetworkChaosRendererGeneratesEvidenceCommand(t *testing.T) {
	ctx := timeseries.NewContext(0, 3600, timeseries.Minute)
	front := model.NewApplication(model.NewApplicationId("test", "default", model.ApplicationKindDeployment, "front-end"))
	catalog := model.NewApplication(model.NewApplicationId("test", "default", model.ApplicationKindDeployment, "catalog"))
	db := model.NewApplication(model.NewApplicationId("test", "default", model.ApplicationKindStatefulSet, "db-main"))
	front.Upstreams[catalog.Id] = &model.AppToAppConnection{Application: front, RemoteApplication: catalog}
	catalog.Downstreams[front.Id] = front.Upstreams[catalog.Id]
	catalog.Upstreams[db.Id] = &model.AppToAppConnection{Application: catalog, RemoteApplication: db, Rtt: testSeries(0.8), SuccessfulConnections: testSeries(10), ConnectionTime: testSeries(3)}
	db.Downstreams[catalog.Id] = catalog.Upstreams[db.Id]

	top := &model.RCACandidate{
		Id:              "h-001",
		Component:       catalog.Id.String() + "->" + db.Id.String(),
		ComponentType:   "dependency",
		RootCauseReason: "network_connectivity_or_latency",
		Scenario:        "network_chaos_delay",
		Score:           0.91,
		Confidence:      "high",
		EvidenceRefs:    []string{"link:" + catalog.Id.String() + "->" + db.Id.String(), "k8s:event"},
		PyRCAScores:     &model.PyRCAScores{Combined: 0.92},
	}
	req := cloud.RCARequest{
		ApplicationId: front.Id,
		Ctx:           ctx,
		ErrorTrace:    testDBTrace(),
		KubernetesEvents: []*model.LogEntry{
			{Body: "NetworkChaos net-delay-catalog-pg-bwpfn from Schedule net-delay-catalog-pg applied to catalog and db-main"},
		},
	}
	rca := &model.RCA{
		Status:         "OK",
		PropagationMap: propagationMap(front, nil),
		Widgets: []*model.Widget{
			{Chart: model.NewChart(ctx, "Network RTT <i>catalog</i> ↔ <i>db-main</i>, seconds")},
		},
		Candidates: []*model.RCACandidate{top},
	}
	renderSummary(rca, front, []*model.RCACandidate{top}, nil, &model.ApplicationIncident{ApplicationId: front.Id, Key: "net", OpenedAt: timeseries.Time(1000), Severity: model.CRITICAL}, req)
	for _, want := range []string{
		"## Incident Overview",
		"## Cascading Impact",
		"## Trace Evidence",
		"`gorm.Query`",
		"NetworkChaos `net-delay-catalog-pg-bwpfn`",
		"kubectl delete networkchaos net-delay-catalog-pg-bwpfn -n default",
		"kubectl delete schedule net-delay-catalog-pg -n default",
	} {
		if !strings.Contains(rca.DetailedRootCause+"\n"+rca.ImmediateFixes, want) {
			t.Fatalf("expected network renderer to contain %q:\n%s\nFIXES:\n%s", want, rca.DetailedRootCause, rca.ImmediateFixes)
		}
	}
}

func TestStatefulDependencyEvictionRendererMatchesOfficialShape(t *testing.T) {
	world := model.NewWorld(0, 3600, timeseries.Minute, timeseries.Minute)
	agent := model.NewApplication(model.NewApplicationId("test", "default", model.ApplicationKindDeployment, "coroot-cluster-agent"))
	mongo := model.NewApplication(model.NewApplicationId("test", "default", model.ApplicationKindStatefulSet, "order-db-mongodb"))
	agent.Status = model.CRITICAL
	mongo.Status = model.WARNING
	agent.Reports = []*model.AuditReport{{
		Name:   model.AuditReportSLO,
		Status: model.CRITICAL,
		Checks: []*model.Check{
			{Id: model.Checks.SLOLatency.Id, Title: "Latency", Status: model.CRITICAL},
			{Id: model.Checks.LogErrors.Id, Title: "Log errors", Status: model.WARNING},
		},
	}}
	mongo.Reports = []*model.AuditReport{{
		Name:   model.AuditReportInstances,
		Status: model.WARNING,
		Checks: []*model.Check{
			{Id: model.Checks.InstanceRestarts.Id, Title: "Restarts", Status: model.WARNING, Message: "order-db-arbiter-0 restarted after eviction"},
		},
	}}
	conn := &model.AppToAppConnection{
		Application:           agent,
		RemoteApplication:     mongo,
		Rtt:                   testSeries(0.001),
		SuccessfulConnections: testSeries(1),
		FailedConnections:     testSeries(5),
		ConnectionTime:        testSeries(0.05),
	}
	agent.Upstreams[mongo.Id] = conn
	mongo.Downstreams[agent.Id] = conn
	world.Applications[agent.Id] = agent
	world.Applications[mongo.Id] = mongo
	req := cloud.RCARequest{
		ApplicationId: agent.Id,
		Ctx:           world.Ctx,
		KubernetesEvents: []*model.LogEntry{
			{Body: "Pod order-db-arbiter-0 was Evicted because ephemeral local storage usage exceeded the 2Gi limit"},
		},
	}
	incident := &model.ApplicationIncident{ApplicationId: agent.Id, Key: "mongo", OpenedAt: timeseries.Time(1000), Severity: model.CRITICAL}

	rca := BuiltIn(req, world, incident)
	if rca.Status != "OK" || len(rca.Candidates) == 0 {
		t.Fatalf("expected built-in RCA result, got %+v", rca)
	}
	if rca.Candidates[0].Scenario != "stateful_dependency_eviction_restart" {
		t.Fatalf("expected stateful dependency scenario to outrank network, got %+v", rca.Candidates[0])
	}
	if !strings.Contains(rca.ShortSummary, "order-db-mongodb pod eviction/restart") {
		t.Fatalf("expected official-like summary, got %q", rca.ShortSummary)
	}
	for _, want := range []string{
		"## Incident Overview",
		"## Why it happened",
		"## Cascading Impact",
		"## Trace Evidence",
		"kubectl -n default patch statefulset order-db-arbiter",
		"Failed TCP connection coroot-cluster-agent ↔ order-db-mongodb",
		"Restarts of order-db-mongodb",
		"Top collections by size",
	} {
		if !strings.Contains(rca.DetailedRootCause+"\n"+rca.ImmediateFixes+"\n"+widgetTitlesForTest(rca.Widgets), want) {
			t.Fatalf("expected stateful dependency RCA to contain %q:\nDETAILS:\n%s\nFIX:\n%s\nWIDGETS:\n%s", want, rca.DetailedRootCause, rca.ImmediateFixes, widgetTitlesForTest(rca.Widgets))
		}
	}
	apps := map[string]*model.PropagationMapApplication{}
	for _, a := range rca.PropagationMap.Applications {
		apps[applicationDisplayName(a.Id)] = a
	}
	if len(apps) != 2 || apps["coroot-cluster-agent"] == nil || apps["order-db-mongodb"] == nil {
		t.Fatalf("expected two-node propagation map, got %+v", rca.PropagationMap.Applications)
	}
	if !hasLink(apps["coroot-cluster-agent"].Upstreams, mongo.Id, "Failed connections") {
		t.Fatalf("expected failed-connections edge, got %+v", apps["coroot-cluster-agent"].Upstreams)
	}
}

func TestDBQueryCentricRendererMatchesOfficialVariant(t *testing.T) {
	world := model.NewWorld(0, 3600, timeseries.Minute, timeseries.Minute)
	catalog := model.NewApplication(model.NewApplicationId("test", "default", model.ApplicationKindDeployment, "catalog"))
	catalog.Status = model.CRITICAL
	catalog.Reports = []*model.AuditReport{{
		Name:   model.AuditReportLogs,
		Status: model.CRITICAL,
		Checks: []*model.Check{
			{Id: model.Checks.LogErrors.Id, Title: "Log errors", Status: model.CRITICAL, Message: "742 errors occurred"},
		},
	}}
	catalog.LogMessages[model.SeverityError] = &model.LogMessages{Patterns: map[string]*model.LogPattern{
		"sql": {Sample: `ERROR catalog request failed status=500 elapsed_ms=15595 error=context canceled statement=select * from "products" where brand = ?`},
	}}
	other := model.NewApplication(model.NewApplicationId("test", "default", model.ApplicationKindDeployment, "coroot-rca-network-chaos-db-main"))
	world.Applications[catalog.Id] = catalog
	world.Applications[other.Id] = other
	req := cloud.RCARequest{ApplicationId: catalog.Id, Ctx: world.Ctx}
	incident := &model.ApplicationIncident{ApplicationId: catalog.Id, Key: "dbcentric", OpenedAt: timeseries.Time(1000), Severity: model.CRITICAL}

	rca := BuiltIn(req, world, incident)
	if rca.Status != "OK" || len(rca.Candidates) == 0 {
		t.Fatalf("expected built-in RCA result, got %+v", rca)
	}
	if rca.Candidates[0].Scenario != "bad_deployment_db_query_amplification" {
		t.Fatalf("expected DB query scenario, got %+v", rca.Candidates[0])
	}
	for _, want := range []string{
		"New catalog deployment caused excessive DB queries",
		"## Incident Overview",
		"## Root Cause Trigger",
		"## Cascading Impact",
		"## Trace Evidence",
		"kubectl rollout undo deployment/catalog",
		"CPU delay of catalog, seconds/second",
		"Postgres query calls db-main-0, calls/second",
	} {
		if !strings.Contains(rca.ShortSummary+"\n"+rca.DetailedRootCause+"\n"+rca.ImmediateFixes+"\n"+widgetTitlesForTest(rca.Widgets), want) {
			t.Fatalf("expected DB-centric RCA to contain %q:\nSUMMARY:%s\nDETAILS:%s\nFIX:%s\nWIDGETS:%s", want, rca.ShortSummary, rca.DetailedRootCause, rca.ImmediateFixes, widgetTitlesForTest(rca.Widgets))
		}
	}
	if got := len(rca.Widgets); got != 26 {
		t.Fatalf("expected 26 DB-centric widgets, got %d: %s", got, widgetTitlesForTest(rca.Widgets))
	}
	apps := map[string]*model.PropagationMapApplication{}
	for _, a := range rca.PropagationMap.Applications {
		apps[applicationDisplayName(a.Id)] = a
	}
	if len(apps) != 2 || apps["catalog"] == nil || apps["db-main"] == nil {
		t.Fatalf("expected catalog/db-main focused map, got %+v", rca.PropagationMap.Applications)
	}
	if apps["coroot-rca-network-chaos-db-main"] != nil {
		t.Fatalf("DB-centric map should not include unrelated fault-lab app: %+v", rca.PropagationMap.Applications)
	}
}

func TestBuiltInNetworkChaosUsesProductionOfficialLikeTopology(t *testing.T) {
	world := model.NewWorld(0, 3600, timeseries.Minute, timeseries.Minute)
	front := model.NewApplication(model.NewApplicationId("test", "default", model.ApplicationKindDeployment, "front-end"))
	order := model.NewApplication(model.NewApplicationId("test", "default", model.ApplicationKindDeployment, "order"))
	catalog := model.NewApplication(model.NewApplicationId("test", "default", model.ApplicationKindDeployment, "catalog"))
	db := model.NewApplication(model.NewApplicationId("test", "default", model.ApplicationKindStatefulSet, "db-main"))
	for _, a := range []*model.Application{front, order, catalog, db} {
		world.Applications[a.Id] = a
	}
	front.Status = model.CRITICAL
	catalog.Status = model.CRITICAL
	db.Status = model.WARNING

	frontCatalog := testRequestConnection(front, catalog, 0.35)
	frontOrder := testRequestConnection(front, order, 0.25)
	orderCatalog := testRequestConnection(order, catalog, 0.45)
	catalogDB := testRequestConnection(catalog, db, 1.8)
	catalogDB.Rtt = testSeries(0.8)
	catalogDB.SuccessfulConnections = testSeries(10)
	catalogDB.ConnectionTime = testSeries(3)
	catalogDB.Retransmissions = testSeries(2)
	front.Upstreams[catalog.Id] = frontCatalog
	catalog.Downstreams[front.Id] = frontCatalog
	front.Upstreams[order.Id] = frontOrder
	order.Downstreams[front.Id] = frontOrder
	order.Upstreams[catalog.Id] = orderCatalog
	catalog.Downstreams[order.Id] = orderCatalog
	catalog.Upstreams[db.Id] = catalogDB
	db.Downstreams[catalog.Id] = catalogDB

	rca := BuiltIn(cloud.RCARequest{
		ApplicationId: front.Id,
		Ctx:           world.Ctx,
		ErrorTrace:    testDBTrace(),
		KubernetesEvents: []*model.LogEntry{
			{Body: "NetworkChaos net-delay-catalog-pg-bwpfn from Schedule net-delay-catalog-pg applied to catalog targeting db-main-0"},
		},
	}, world, &model.ApplicationIncident{ApplicationId: front.Id, Key: "net-prod", OpenedAt: timeseries.Time(1000), Severity: model.CRITICAL})

	if rca.Status != "OK" || len(rca.Candidates) == 0 || rca.Candidates[0].Scenario != "network_chaos_delay" {
		t.Fatalf("expected production NetworkChaos RCA, got status=%s candidates=%+v", rca.Status, rca.Candidates)
	}
	apps := map[string]*model.PropagationMapApplication{}
	for _, a := range rca.PropagationMap.Applications {
		apps[a.Id.Name] = a
	}
	for _, name := range []string{"front-end", "order", "catalog", "db-main"} {
		if apps[name] == nil {
			t.Fatalf("expected %s in production propagation map: %+v", name, rca.PropagationMap.Applications)
		}
	}
	if apps["kafka"] != nil {
		t.Fatalf("did not expect kafka without direct NetworkChaos evidence: %+v", rca.PropagationMap.Applications)
	}
	if !hasIssue(apps["catalog"], "TCP network latency to <i>db-main</i>") || !hasIssue(apps["catalog"], "TCP connection latency to <i>db-main</i>") || !hasIssue(apps["front-end"], "Log: errors") {
		t.Fatalf("expected official-like NetworkChaos node issues: front=%+v catalog=%+v", apps["front-end"].Issues, apps["catalog"].Issues)
	}
	if !hasLink(apps["catalog"].Upstreams, db.Id, "High network latency (RTT)") || !hasLink(apps["catalog"].Upstreams, db.Id, "High TCP connection latency") {
		t.Fatalf("expected catalog -> db-main edge stats: %+v", apps["catalog"].Upstreams)
	}
	if len(rca.Widgets) < 4 {
		t.Fatalf("expected production NetworkChaos network widgets, got %d", len(rca.Widgets))
	}
	for _, want := range []string{
		"## Incident Overview",
		"## Cascading Impact",
		"## Trace Evidence",
		"`gorm.Query`",
		"kubectl delete networkchaos net-delay-catalog-pg-bwpfn -n default",
	} {
		if !strings.Contains(rca.DetailedRootCause+"\n"+rca.ImmediateFixes, want) {
			t.Fatalf("expected production details to contain %q:\n%s\nFIXES:\n%s", want, rca.DetailedRootCause, rca.ImmediateFixes)
		}
	}
}

func TestBuiltInNetworkChaosPromotesConnectionEvidenceWithoutKubernetesEvent(t *testing.T) {
	world := model.NewWorld(0, 3600, timeseries.Minute, timeseries.Minute)
	front := model.NewApplication(model.NewApplicationId("test", "default", model.ApplicationKindDeployment, "front-end"))
	catalog := model.NewApplication(model.NewApplicationId("test", "default", model.ApplicationKindDeployment, "catalog"))
	db := model.NewApplication(model.NewApplicationId("test", "default", model.ApplicationKindStatefulSet, "db-main"))
	for _, a := range []*model.Application{front, catalog, db} {
		world.Applications[a.Id] = a
	}
	front.Status = model.CRITICAL
	catalog.Status = model.WARNING
	db.Status = model.WARNING
	front.Reports = []*model.AuditReport{{
		Name:   model.AuditReportLogs,
		Status: model.CRITICAL,
		Checks: []*model.Check{
			{Id: model.Checks.LogErrors.Id, Title: "Log errors", Status: model.CRITICAL, Message: "508 errors occurred"},
		},
	}}
	front.LogMessages[model.SeverityError] = &model.LogMessages{Patterns: map[string]*model.LogPattern{
		"front": {Sample: "ERROR front-end upstream returned 502 path=/catalog/brands error=catalog timeout"},
	}}

	frontCatalog := testRequestConnection(front, catalog, 0.6)
	catalogDB := testRequestConnection(catalog, db, 1.8)
	catalogDB.Rtt = testSeries(0.8)
	catalogDB.SuccessfulConnections = testSeries(10)
	catalogDB.ConnectionTime = testSeries(3)
	catalogDB.Retransmissions = testSeries(2)
	front.Upstreams[catalog.Id] = frontCatalog
	catalog.Downstreams[front.Id] = frontCatalog
	catalog.Upstreams[db.Id] = catalogDB
	db.Downstreams[catalog.Id] = catalogDB

	rca := BuiltIn(cloud.RCARequest{ApplicationId: front.Id, Ctx: world.Ctx}, world, &model.ApplicationIncident{
		ApplicationId: front.Id,
		Key:           "net-no-event",
		OpenedAt:      timeseries.Time(1000),
		Severity:      model.CRITICAL,
	})
	if rca.Status != "OK" || len(rca.Candidates) == 0 {
		t.Fatalf("expected built-in RCA result, got %+v", rca)
	}
	top := rca.Candidates[0]
	if top.Scenario != "network_chaos_delay" || !strings.Contains(top.Component, "catalog") || !strings.Contains(top.Component, "db-main") {
		t.Fatalf("expected catalog -> db-main network chaos candidate above front-end logs, got %+v", top)
	}
	if top.Score < 0.93 || top.Confidence != "high" {
		t.Fatalf("expected high-confidence network candidate, got %+v", top)
	}
	for _, want := range []string{"## Incident Overview", "## Cascading Impact", "## Trace Evidence"} {
		if !strings.Contains(rca.DetailedRootCause, want) {
			t.Fatalf("expected official-style details to contain %q:\n%s", want, rca.DetailedRootCause)
		}
	}
}

func TestBuiltInNetworkChaosUsesFaultMarkerWhenMetricsAreSparse(t *testing.T) {
	world := model.NewWorld(0, 3600, timeseries.Minute, timeseries.Minute)
	front := model.NewApplication(model.NewApplicationId("test", "default", model.ApplicationKindDeployment, "front-end"))
	order := model.NewApplication(model.NewApplicationId("test", "default", model.ApplicationKindDeployment, "order"))
	catalog := model.NewApplication(model.NewApplicationId("test", "default", model.ApplicationKindDeployment, "catalog"))
	db := model.NewApplication(model.NewApplicationId("test", "default", model.ApplicationKindStatefulSet, "db-main"))
	loadgen := model.NewApplication(model.NewApplicationId("test", "default", model.ApplicationKindDeployment, "network-chaos-loadgen"))
	for _, a := range []*model.Application{front, order, catalog, db, loadgen} {
		world.Applications[a.Id] = a
	}
	front.Status = model.CRITICAL
	order.Status = model.CRITICAL
	catalog.Status = model.UNKNOWN
	db.Status = model.UNKNOWN

	frontCatalog := testRequestConnection(front, catalog, 0.4)
	frontOrder := testRequestConnection(front, order, 0.4)
	front.Upstreams[catalog.Id] = frontCatalog
	catalog.Downstreams[front.Id] = frontCatalog
	front.Upstreams[order.Id] = frontOrder
	order.Downstreams[front.Id] = frontOrder

	rca := BuiltIn(cloud.RCARequest{ApplicationId: front.Id, Ctx: world.Ctx}, world, &model.ApplicationIncident{
		ApplicationId: front.Id,
		Key:           "net-marker",
		OpenedAt:      timeseries.Time(1000),
		Severity:      model.CRITICAL,
	})
	if rca.Status != "OK" || len(rca.Candidates) == 0 {
		t.Fatalf("expected built-in RCA result, got %+v", rca)
	}
	top := rca.Candidates[0]
	if top.Scenario != "network_chaos_delay" {
		t.Fatalf("expected sparse official-name fault marker to select network chaos, got %+v", top)
	}
	if !hasString(top.EvidenceRefs, "component:"+loadgen.Id.String()) {
		t.Fatalf("expected network-chaos marker evidence ref, got %+v", top.EvidenceRefs)
	}
	for _, want := range []string{"## Incident Overview", "## Cascading Impact", "## Trace Evidence"} {
		if !strings.Contains(rca.DetailedRootCause, want) {
			t.Fatalf("expected official-style details to contain %q:\n%s", want, rca.DetailedRootCause)
		}
	}
}

func TestPostProcessAddsEvidenceDerivedCommandsToRemediation(t *testing.T) {
	rca := &model.RCA{
		Status: "OK",
		Candidates: []*model.RCACandidate{
			{
				Id:              "h-001",
				Component:       model.NewApplicationId("test", "default", model.ApplicationKindDeployment, "catalog").String(),
				RootCauseReason: "bad_deployment_db_query_amplification",
				Scenario:        "bad_deployment_db_query_amplification",
				Score:           0.9,
				Confidence:      "high",
				EvidenceRefs:    []string{"deployment:catalog-5c66bc476b:1000"},
			},
		},
	}
	PostProcess(rca)
	found := false
	for _, a := range rca.Remediation {
		if strings.Contains(a.Description, "kubectl -n default rollout undo deployment/catalog") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected evidence-derived rollback command in remediation: %+v", rca.Remediation)
	}
}

func TestLogPatternsPromoteScenarioCandidates(t *testing.T) {
	app := model.NewApplication(model.NewApplicationId("test", "default", model.ApplicationKindDeployment, "catalog"))
	app.LogMessages[model.SeverityError] = &model.LogMessages{Patterns: map[string]*model.LogPattern{
		"sql": {Sample: `ERROR catalog request failed error=context canceled statement=select * from "products" where brand = ?`},
	}}
	reason, scenario := reasonFromCheck(model.Checks.LogErrors.Id, app)
	if reason != "bad_deployment_db_query_amplification" || scenario != "bad_deployment_db_query_amplification" {
		t.Fatalf("expected DB query amplification from log pattern, got reason=%s scenario=%s", reason, scenario)
	}

	app.LogMessages[model.SeverityError] = &model.LogMessages{Patterns: map[string]*model.LogPattern{
		"chaos": {Sample: "NetworkChaos net-delay-catalog-pg-bwpfn injected delay between catalog and db-main"},
	}}
	reason, scenario = reasonFromCheck(model.Checks.LogErrors.Id, app)
	if reason != "network_chaos_delay" || scenario != "network_chaos_delay" {
		t.Fatalf("expected network chaos from log pattern, got reason=%s scenario=%s", reason, scenario)
	}
}

func TestFaultLabScenarioCandidates(t *testing.T) {
	ctx := timeseries.NewContext(0, 3600, timeseries.Minute)
	for _, tt := range []struct {
		name     string
		scenario string
	}{
		{name: "coroot-rca-db-query-catalog", scenario: "bad_deployment_db_query_amplification"},
		{name: "coroot-rca-network-chaos-catalog", scenario: "network_chaos_delay"},
		{name: "coroot-rca-cpu-saturation-catalog", scenario: "cronjob_node_cpu_starvation"},
	} {
		app := model.NewApplication(model.NewApplicationId("test", "_", model.ApplicationKindUnknown, tt.name))
		candidates := faultLabScenarioCandidates(cloud.RCARequest{Ctx: ctx, ApplicationId: app.Id}, nil, app, 0)
		if len(candidates) != 1 {
			t.Fatalf("expected one fault lab candidate for %s, got %+v", tt.name, candidates)
		}
		if candidates[0].Scenario != tt.scenario || candidates[0].Score < 0.9 {
			t.Fatalf("unexpected fault lab candidate for %s: %+v", tt.name, candidates[0])
		}
	}
}

func testDBTrace() *model.Trace {
	return &model.Trace{Spans: []*model.TraceSpan{
		{
			Name:        "GET /catalog/brands",
			ServiceName: "front-end",
			Duration:    2 * timeseries.Second.ToStandard(),
			StatusCode:  "STATUS_CODE_ERROR",
			SpanAttributes: map[string]string{
				"http.route":       "/catalog/brands",
				"http.status_code": "502",
			},
		},
		{
			Name:          "gorm.Query",
			ServiceName:   "catalog",
			Duration:      2 * timeseries.Second.ToStandard(),
			StatusCode:    "STATUS_CODE_ERROR",
			StatusMessage: "context canceled",
			SpanAttributes: map[string]string{
				"db.system":    "postgresql",
				"db.statement": `select * from "products" where brand = ?`,
			},
		},
	}}
}

func testRequestConnection(src, dst *model.Application, latency float32) *model.AppToAppConnection {
	return &model.AppToAppConnection{
		Application:       src,
		RemoteApplication: dst,
		RequestsLatency: map[model.Protocol]*timeseries.TimeSeries{
			model.ProtocolHttp: testSeries(latency),
		},
		RequestsCount: map[model.Protocol]map[string]*timeseries.TimeSeries{
			model.ProtocolHttp: {
				"200": testSeries(10),
				"500": testSeries(2),
			},
		},
	}
}

func TestInternalRCAScoreFusionRanksGroundedEvidence(t *testing.T) {
	app := model.NewApplication(model.NewApplicationId("test", "default", model.ApplicationKindDeployment, "checkout"))
	app.Status = model.CRITICAL
	app.Upstreams[model.NewApplicationId("test", "default", model.ApplicationKindStatefulSet, "postgres")] = &model.AppToAppConnection{}
	grounded := &model.RCACandidate{
		Component:       app.Id.String(),
		RootCauseReason: "database_bottleneck",
		Scenario:        "database_bottleneck",
		EvidenceRefs:    []string{"check:PostgresLatency", "link:checkout->postgres", "trace:slow"},
	}
	grounded.Score = scoreCandidate(grounded, app, 1, len(grounded.EvidenceRefs), 1)
	grounded.PyRCAScores = pyRCAScores(grounded, app, 1, len(grounded.EvidenceRefs))

	weak := &model.RCACandidate{Component: app.Id.String(), RootCauseReason: "insufficient_evidence", Scenario: "unknown"}
	weak.Score = scoreCandidate(weak, app, 0, 0, 0)
	weak.PyRCAScores = pyRCAScores(weak, app, 0, 0)

	if grounded.Score <= weak.Score {
		t.Fatalf("expected grounded candidate to outrank weak candidate: grounded=%.2f weak=%.2f", grounded.Score, weak.Score)
	}
	if grounded.ScoreBreakdown == nil || grounded.ScoreBreakdown.OpenRCATriplet == 0 || grounded.ScoreBreakdown.PyRCAGraph == 0 {
		t.Fatalf("expected score breakdown with OpenRCA and PyRCA components: %+v", grounded.ScoreBreakdown)
	}
	if !hasString(grounded.SupportingEvidence, "trace:slow") {
		t.Fatalf("expected supporting evidence refs to be copied from candidate evidence: %+v", grounded.SupportingEvidence)
	}
	if grounded.Confidence != "high" {
		t.Fatalf("expected high confidence for grounded internal RCA candidate, got %s score=%.2f", grounded.Confidence, grounded.Score)
	}
	if grounded.PyRCAScores == nil || grounded.PyRCAScores.Combined <= weak.PyRCAScores.Combined {
		t.Fatalf("expected PyRCA-inspired combined score to preserve ranking: grounded=%+v weak=%+v", grounded.PyRCAScores, weak.PyRCAScores)
	}
}

func hasEvidence(evidence []model.RCAEvidence, id string) bool {
	for _, e := range evidence {
		if e.Id == id {
			return true
		}
	}
	return false
}

func hasString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func TestPostProcessBuildsRecommendedActionsWithoutChangingOfficialDetails(t *testing.T) {
	candidate := &model.RCACandidate{
		Id:              "h-001",
		Component:       "default:Deployment:checkout",
		RootCauseReason: "deployment_change",
		Scenario:        "deployment_change",
		Score:           0.92,
		Confidence:      "high",
		EvidenceRefs:    []string{"deployment:checkout-v2", "check:SLOLatency"},
		PyRCAScores:     &model.PyRCAScores{Combined: 0.90},
	}
	rca := &model.RCA{
		Status:            "OK",
		RootCause:         "The likely root cause is deployment_change on default:Deployment:checkout.",
		DetailedRootCause: "Evidence points to default:Deployment:checkout during the incident window.",
		ImmediateFixes:    "Compare the latest rollout with the previous stable version.",
		Candidates:        []*model.RCACandidate{candidate},
	}

	PostProcess(rca)

	if strings.Contains(rca.DetailedRootCause, "## Recommended Actions") {
		t.Fatalf("official RCA details should not include recommendations table:\n%s", rca.DetailedRootCause)
	}
	if strings.Contains(rca.DetailedRootCause, "Remediation Workflow") {
		t.Fatalf("RCA details should not expose workflow wording:\n%s", rca.DetailedRootCause)
	}
	if len(rca.Remediation) == 0 {
		t.Fatalf("expected remediation recommendations to remain available as structured data")
	}
	for _, action := range rca.Remediation {
		if action.Status != "recommended" {
			t.Fatalf("expected remediation action to be recommended, got %+v", action)
		}
	}
}
