package rca

import (
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
		"## What happened",
		"## Following the dependency chain",
		"## The trigger",
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
		"### Overview",
		"### CPU saturation on node3",
		"### Cascading impact on the request path",
		"### The analytics-updater CronJob is the trigger",
		"WIDGET-2",
		"WIDGET-6",
	} {
		if !strings.Contains(rca.DetailedRootCause, want) {
			t.Fatalf("expected detailed RCA to contain %q:\n%s", want, rca.DetailedRootCause)
		}
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
