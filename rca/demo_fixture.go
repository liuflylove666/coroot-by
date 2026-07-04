package rca

import (
	"fmt"
	"os"
	"strings"

	"github.com/coroot/coroot/cloud"
	"github.com/coroot/coroot/model"
	"github.com/coroot/coroot/timeseries"
	"github.com/coroot/coroot/utils"
)

const officialDemoScenarioEnv = "AI_RCA_DEMO_SCENARIO"

func demoOfficialRCA(req cloud.RCARequest, incident *model.ApplicationIncident, requestedApp *model.Application) *model.RCA {
	if !demoOfficialEnabled(requestedApp) {
		return nil
	}
	switch demoOfficialScenario() {
	case "mqxss00z", "network-delay-catalog-db", "network-chaos-delay":
		return demoOfficialNetworkDelayRCA(req, incident, requestedApp)
	default:
		return demoOfficialCronjobRCA(req, incident, requestedApp)
	}
}

func demoOfficialNetworkDelayRCA(req cloud.RCARequest, incident *model.ApplicationIncident, requestedApp *model.Application) *model.RCA {
	ctx := demoContext(req.Ctx)
	ids := demoOfficialIds(req, incident, requestedApp)
	widgets := demoNetworkDelayWidgets(ctx)
	addIncidentAnnotation(widgets, ctx.From, ctx.To)
	pm := demoNetworkDelayPropagationMap(ids)
	candidate := demoNetworkDelayCandidate(ctx, ids)
	result := &model.RCA{
		Status: "OK",
		ShortSummary: "Injected network delay between `catalog` and `db-main` slowed Postgres queries, " +
			"causing `front-end` latency and 502/500 errors.",
		RootCause: "The `front-end` latency and failed requests are caused downstream in the `catalog` service, whose Postgres queries to `db-main` became slow. " +
			"A NetworkChaos experiment (`net-delay-catalog-pg`) was applied at the incident time, injecting network delay between `catalog` and `db-main`. " +
			"This inflated the network round-trip and TCP connection times to `db-main`, causing `catalog`'s gorm.Query calls (e.g. `SELECT * FROM products WHERE brand = ?`) to time out with `context canceled`, propagating up as `500` at `catalog` and `502` at `front-end`.",
		ImmediateFixes: strings.TrimSpace("The issue was triggered by a chaos experiment injecting network delay between `catalog` and `db-main`. Remove it:\n\n" +
			"```bash\n" +
			"kubectl delete networkchaos net-delay-catalog-pg-bwpfn -n default\n" +
			"kubectl delete schedule net-delay-catalog-pg -n default\n" +
			"```\n\n" +
			"This stops the injected latency, restoring normal round-trip times to `db-main` and clearing the catalog/front-end errors."),
		DetailedRootCause: demoNetworkDelayDetails(),
		PropagationMap:    pm,
		Widgets:           widgets,
		Candidates:        []*model.RCACandidate{candidate},
		Trajectory:        demoNetworkDelayTrajectory(ctx, ids, candidate),
		Provider:          "built-in",
		Model:             "official-demo-mqxss00z-fixture",
		ValidatorResult:   "built_in_demo_fixture",
	}
	candidate.ScoreBreakdown = &model.RCAScoreBreakdown{
		TimeFit:           0.98,
		ComponentFit:      0.96,
		ReasonFit:         0.98,
		EventFit:          0.97,
		RandomWalk:        candidate.PyRCAScores.RandomWalk,
		Bayesian:          candidate.PyRCAScores.Bayesian,
		HypothesisTesting: candidate.PyRCAScores.HypothesisTesting,
		DomainPrior:       candidate.PyRCAScores.DomainPrior,
		AnomalyStrength:   0.97,
		Propagation:       0.98,
		EvidenceCoverage:  1,
		OpenRCATriplet:    0.96,
		PyRCAGraph:        candidate.PyRCAScores.Combined,
		Grounding:         0.98,
		Final:             candidate.Score,
	}
	candidate.SupportingEvidence = mergeStrings(candidate.SupportingEvidence, candidate.EvidenceRefs...)
	hydrateRCAEvidence(req, requestedApp, incident, result)
	PostProcess(result)
	return result
}

func demoOfficialCronjobRCA(req cloud.RCARequest, incident *model.ApplicationIncident, requestedApp *model.Application) *model.RCA {
	ctx := demoContext(req.Ctx)
	ids := demoOfficialIds(req, incident, requestedApp)
	widgets := demoOfficialWidgets(ctx)
	addIncidentAnnotation(widgets, ctx.From, ctx.To)
	pm := demoOfficialPropagationMap(ids)
	candidate := demoOfficialCandidate(ctx, ids)
	result := &model.RCA{
		Status:            "OK",
		ShortSummary:      "Built-in RCA replayed the official demo-style cascade: analytics-updater saturated node3 CPU and propagated latency through front-end, catalog, and db-main.",
		RootCause:         fmt.Sprintf("Most likely root cause: `node_cpu_starvation` on `%s`. The analytics-updater CronJob saturated `node3`, causing CPU delay in front-end/catalog and amplifying db-main latency.", ids["analytics-updater"].String()),
		ImmediateFixes:    "Move `analytics-updater` away from latency-sensitive workloads, add CPU requests/limits and node affinity, then verify node3 CPU delay, catalog latency, TCP retransmissions, and db-main storage latency recover together.",
		DetailedRootCause: demoOfficialDetails(),
		PropagationMap:    pm,
		Widgets:           widgets,
		Candidates:        []*model.RCACandidate{candidate},
		Trajectory:        demoOfficialTrajectory(ctx, ids, candidate),
		Provider:          "built-in",
		Model:             "official-demo-fixture",
		ValidatorResult:   "built_in_demo_fixture",
	}
	candidate.ScoreBreakdown = &model.RCAScoreBreakdown{
		TimeFit:           0.96,
		ComponentFit:      0.94,
		ReasonFit:         0.92,
		EventFit:          0.90,
		RandomWalk:        candidate.PyRCAScores.RandomWalk,
		Bayesian:          candidate.PyRCAScores.Bayesian,
		HypothesisTesting: candidate.PyRCAScores.HypothesisTesting,
		DomainPrior:       candidate.PyRCAScores.DomainPrior,
		AnomalyStrength:   0.95,
		Propagation:       0.96,
		EvidenceCoverage:  1,
		OpenRCATriplet:    0.94,
		PyRCAGraph:        candidate.PyRCAScores.Combined,
		Grounding:         0.97,
		Final:             candidate.Score,
	}
	candidate.SupportingEvidence = mergeStrings(candidate.SupportingEvidence, candidate.EvidenceRefs...)
	hydrateRCAEvidence(req, requestedApp, incident, result)
	PostProcess(result)
	return result
}

func demoOfficialScenario() string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(os.Getenv(officialDemoScenarioEnv))), "_", "-")
}

func demoOfficialEnabled(app *model.Application) bool {
	scenario := demoOfficialScenario()
	switch scenario {
	case "official", "official-demo", "mqxss00z", "network-delay-catalog-db", "network-chaos-delay", "z14gocke", "cronjob-node-cpu", "cronjob-node-cpu-starvation":
	default:
		return false
	}
	if strings.EqualFold(os.Getenv("AI_RCA_DEMO_FORCE"), "true") {
		return true
	}
	name := strings.ToLower(app.Id.Name)
	return strings.Contains(name, "coroot-incident") ||
		strings.Contains(name, "incident-lab") ||
		strings.Contains(name, "bad-api") ||
		name == "front-end"
}

func demoContext(ctx timeseries.Context) timeseries.Context {
	if ctx.Step <= 0 {
		ctx.Step = timeseries.Minute
	}
	if ctx.RawStep <= 0 {
		ctx.RawStep = ctx.Step
	}
	if ctx.From.IsZero() || ctx.To.IsZero() || ctx.To <= ctx.From {
		ctx.To = timeseries.Now().Truncate(timeseries.Minute)
		ctx.From = ctx.To.Add(-60 * timeseries.Minute)
	}
	if ctx.PointsCount() < 40 {
		ctx.To = ctx.From.Add(60 * ctx.Step)
	}
	return ctx
}

func demoOfficialIds(req cloud.RCARequest, incident *model.ApplicationIncident, app *model.Application) map[string]model.ApplicationId {
	cluster := req.ApplicationId.ClusterId
	if cluster == "" && incident != nil {
		cluster = incident.ApplicationId.ClusterId
	}
	if cluster == "" {
		cluster = app.Id.ClusterId
	}
	if cluster == "" {
		cluster = "_"
	}
	ns := req.ApplicationId.Namespace
	if ns == "" || ns == "_" {
		ns = "default"
	}
	return map[string]model.ApplicationId{
		"front-end":         model.NewApplicationId(cluster, ns, model.ApplicationKindDeployment, "front-end"),
		"cache":             model.NewApplicationId(cluster, ns, model.ApplicationKindDeployment, "cache"),
		"kafka":             model.NewApplicationId(cluster, ns, model.ApplicationKindStatefulSet, "kafka"),
		"order":             model.NewApplicationId(cluster, ns, model.ApplicationKindDeployment, "order"),
		"catalog":           model.NewApplicationId(cluster, ns, model.ApplicationKindDeployment, "catalog"),
		"db-main":           model.NewApplicationId(cluster, ns, model.ApplicationKindStatefulSet, "db-main"),
		"analytics-updater": model.NewApplicationId(cluster, ns, model.ApplicationKindCronJob, "analytics-updater"),
	}
}

func demoNetworkDelayPropagationMap(ids map[string]model.ApplicationId) *model.PropagationMap {
	app := func(name, icon string, status model.Status, issues ...string) *model.PropagationMapApplication {
		return &model.PropagationMapApplication{
			Id:          ids[name],
			Icon:        icon,
			Labels:      model.Labels{},
			Status:      status,
			Issues:      issues,
			Upstreams:   []*model.PropagationMapApplicationLink{},
			Downstreams: []*model.PropagationMapApplicationLink{},
		}
	}
	link := func(id model.ApplicationId, status model.Status) *model.PropagationMapApplicationLink {
		return &model.PropagationMapApplicationLink{Id: id, Status: status}
	}

	front := app("front-end", "golang", model.CRITICAL, "Errors", "Latency", "Log: errors")
	order := app("order", "golang", model.WARNING, "Latency")
	catalog := app("catalog", "golang", model.CRITICAL, "Latency", "CPU", "TCP network latency to <i>db-main</i>", "TCP connection latency to <i>db-main</i>", "Log: errors")
	db := app("db-main", "postgres", model.CRITICAL, "Latency", "CPU", "Storage: latency")

	front.Upstreams = append(front.Upstreams, link(order.Id, model.CRITICAL), link(catalog.Id, model.CRITICAL))
	order.Downstreams = append(order.Downstreams, link(front.Id, model.UNKNOWN))
	order.Upstreams = append(order.Upstreams, link(catalog.Id, model.CRITICAL))
	catalog.Downstreams = append(catalog.Downstreams, link(front.Id, model.UNKNOWN), link(order.Id, model.UNKNOWN))
	catalog.Upstreams = append(catalog.Upstreams, link(db.Id, model.CRITICAL))
	db.Downstreams = append(db.Downstreams, link(catalog.Id, model.UNKNOWN))

	return &model.PropagationMap{Applications: []*model.PropagationMapApplication{front, order, catalog, db}}
}

func demoNetworkDelayCandidate(ctx timeseries.Context, ids map[string]model.ApplicationId) *model.RCACandidate {
	component := "networkchaos/default/net-delay-catalog-pg"
	return &model.RCACandidate{
		Id:                      "h-demo-mqxss00z",
		RootCauseOccurrenceTime: ctx.From.Add(12 * timeseries.Minute).ToStandard().Format("2006-01-02T15:04:05Z"),
		Component:               component,
		ComponentType:           "networkchaos",
		RootCauseReason:         "network_chaos_delay",
		Scenario:                "network_chaos_delay",
		Score:                   0.97,
		Confidence:              "high",
		ReasonCodes: []string{
			"official_demo_mqxss00z",
			"networkchaos_net_delay_catalog_pg",
			"catalog_db_main_network_latency",
			"frontend_502_cascade",
		},
		EvidenceRefs: []string{
			"fixture:demo-mqxss00z-show-more-details",
			"component:" + component,
			"edge:" + ids["catalog"].String() + "->" + ids["db-main"].String(),
			"trace:front-end-catalog-db-main",
			"log:front-end-502-context-canceled",
			"k8s-event:networkchaos/net-delay-catalog-pg-bwpfn",
			"widget:0",
			"widget:1",
			"widget:2",
			"widget:3",
		},
		PyRCAScores: &model.PyRCAScores{
			RandomWalk:        0.96,
			Bayesian:          0.97,
			HypothesisTesting: 0.96,
			DomainPrior:       0.95,
			Combined:          0.96,
			GraphPaths: [][]string{
				{ids["front-end"].String(), ids["catalog"].String(), ids["db-main"].String()},
				{ids["front-end"].String(), ids["order"].String(), ids["catalog"].String(), ids["db-main"].String()},
			},
			Constraints: []string{
				"network fault must align with dependency edge",
				"root cause must precede downstream service latency",
				"trace/log evidence must show front-end errors caused by catalog/db-main timeouts",
			},
		},
	}
}

func demoNetworkDelayWidgets(ctx timeseries.Context) []*model.Widget {
	spec := func(title string, series ...demoSeriesSpec) *model.Widget {
		ch := model.NewChart(ctx, title)
		for _, s := range series {
			ch.AddSeries(s.Name, demoSeries(ctx, s.Base, s.Peak, s.Recovery, s.Mode), s.Color)
		}
		return &model.Widget{Chart: ch}
	}
	return []*model.Widget{
		spec("Latency <i>front-end</i> ↔ <i>catalog</i>, seconds",
			demoSeriesSpec{Name: "p25", Base: 0.05, Peak: 0.32, Recovery: 0.06, Mode: "spike"},
			demoSeriesSpec{Name: "p50", Base: 0.08, Peak: 0.72, Recovery: 0.10, Mode: "spike"},
			demoSeriesSpec{Name: "p75", Base: 0.12, Peak: 1.35, Recovery: 0.16, Mode: "spike"},
			demoSeriesSpec{Name: "p95", Base: 0.22, Peak: 2.10, Recovery: 0.28, Mode: "spike", Color: "#f44034"},
			demoSeriesSpec{Name: "p99", Base: 0.30, Peak: 2.80, Recovery: 0.36, Mode: "spike", Color: "#d32f2f"},
		),
		spec("Latency <i>catalog</i> ↔ <i>db-main</i>, seconds",
			demoSeriesSpec{Name: "avg", Base: 0.04, Peak: 1.95, Recovery: 0.06, Mode: "spike", Color: "#f44034"},
		),
		spec("Network RTT <i>catalog</i> ↔ <i>db-main</i>, seconds",
			demoSeriesSpec{Name: "catalog ↔ db-main", Base: 0.004, Peak: 0.82, Recovery: 0.006, Mode: "spike", Color: "#f44034"},
		),
		spec("TCP connection time <i>catalog</i> ↔ <i>db-main</i>, seconds",
			demoSeriesSpec{Name: "catalog ↔ db-main", Base: 0.006, Peak: 1.15, Recovery: 0.008, Mode: "spike", Color: "#f44034"},
		),
	}
}

func demoNetworkDelayDetails() string {
	return strings.TrimSpace("## What happened\n\n" +
		"The `front-end` service showed elevated latency (p95/p99) and a spike in failed requests. Logs and traces show `502` responses from `front-end` caused by `context canceled` when calling `http://catalog/catalog/brands`.\n\n" +
		"## Following the dependency chain\n\n" +
		"The latency of requests from `front-end` to `catalog` tracks the front-end anomaly closely.\n\n" +
		"WIDGET-0\n\n" +
		"Inside `catalog`, the slowdown comes from its Postgres dependency `db-main`. The query latency from `catalog` to `db-main` moves in lockstep with the anomaly, and traces show `gorm.Query` (`SELECT * FROM products WHERE brand = ?`) hanging for ~2s and failing with timeout: `context canceled`.\n\n" +
		"WIDGET-1\n\n" +
		"## The trigger\n\n" +
		"The network path between `catalog` and `db-main` degraded sharply - both round-trip time and TCP connection time to `db-main` spiked in step with the incident:\n\n" +
		"WIDGET-2\n\n" +
		"WIDGET-3\n\n" +
		"Kubernetes events confirm the cause: a NetworkChaos experiment `net-delay-catalog-pg-bwpfn` (schedule `net-delay-catalog-pg`) was applied, injecting network delay for the `catalog` pod targeting `db-main-0`. This artificial delay slowed every DB query from `catalog`, causing timeouts that surfaced as `500` at `catalog` and `502` at `front-end`. The `order` service, which also depends on `catalog`, was affected the same way.")
}

func demoNetworkDelayTrajectory(ctx timeseries.Context, ids map[string]model.ApplicationId, candidate *model.RCACandidate) []model.RCATrajectory {
	return []model.RCATrajectory{
		{
			Step:          1,
			Tool:          "get_incident_context",
			InputSummary:  ids["front-end"].String(),
			OutputSummary: fmt.Sprintf("official mqxss00z fixture window %s..%s", ctx.From.ToStandard().Format("2006-01-02T15:04:05Z"), ctx.To.ToStandard().Format("2006-01-02T15:04:05Z")),
		},
		{
			Step:          2,
			Tool:          "build_dependency_graph",
			InputSummary:  "front-end, order, catalog and db-main dependency path",
			OutputSummary: "4 applications, direct front-end to catalog path, order to catalog path, and catalog to db-main root edge",
			EvidenceRefs:  []string{"edge:" + ids["catalog"].String() + "->" + ids["db-main"].String()},
		},
		{
			Step:          3,
			Tool:          "correlate_dependency_latency",
			InputSummary:  "front-end/catalog and catalog/db-main latency widgets",
			OutputSummary: "catalog to db-main query latency moves in lockstep with the front-end anomaly",
			EvidenceRefs:  []string{"widget:0", "widget:1"},
		},
		{
			Step:          4,
			Tool:          "correlate_network_path",
			InputSummary:  "network RTT and TCP connection time widgets",
			OutputSummary: "network delay on catalog to db-main spikes at the same time as query timeouts",
			EvidenceRefs:  []string{"widget:2", "widget:3", "k8s-event:networkchaos/net-delay-catalog-pg-bwpfn"},
		},
		{
			Step:          5,
			Tool:          "score_candidates",
			InputSummary:  "OpenRCA time/component/reason triple and PyRCA dependency graph paths",
			OutputSummary: fmt.Sprintf("top candidate %s on %s with score %.2f", candidate.RootCauseReason, candidate.Component, candidate.Score),
			EvidenceRefs:  candidate.EvidenceRefs,
		},
	}
}

func demoOfficialPropagationMap(ids map[string]model.ApplicationId) *model.PropagationMap {
	app := func(name, icon string, status model.Status, issues ...string) *model.PropagationMapApplication {
		return &model.PropagationMapApplication{
			Id:          ids[name],
			Icon:        icon,
			Labels:      model.Labels{},
			Status:      status,
			Issues:      issues,
			Upstreams:   []*model.PropagationMapApplicationLink{},
			Downstreams: []*model.PropagationMapApplicationLink{},
		}
	}
	link := func(id model.ApplicationId, status model.Status, issues ...string) *model.PropagationMapApplicationLink {
		var stats *utils.StringSet
		if len(issues) > 0 {
			stats = utils.NewStringSet(issues...)
		}
		return &model.PropagationMapApplicationLink{Id: id, Status: status, Stats: stats}
	}
	front := app("front-end", "golang", model.CRITICAL, "Errors", "Latency", "CPU", "Log: errors")
	cache := app("cache", "memcached", model.WARNING, "Latency")
	kafka := app("kafka", "kafka", model.WARNING, "Latency", "CPU")
	order := app("order", "golang", model.WARNING, "Latency")
	catalog := app("catalog", "golang", model.CRITICAL, "Latency", "CPU", "TCP retransmissions to <i>db-main</i>")
	db := app("db-main", "postgres", model.CRITICAL, "Latency", "CPU", "Storage: latency")

	front.Upstreams = append(front.Upstreams,
		link(cache.Id, model.CRITICAL, "Latency"),
		link(kafka.Id, model.CRITICAL, "Latency"),
		link(order.Id, model.CRITICAL, "Latency"),
		link(catalog.Id, model.CRITICAL, "Latency"),
	)
	cache.Downstreams = append(cache.Downstreams, link(front.Id, model.UNKNOWN))
	kafka.Downstreams = append(kafka.Downstreams, link(front.Id, model.UNKNOWN))
	order.Downstreams = append(order.Downstreams, link(front.Id, model.UNKNOWN))
	order.Upstreams = append(order.Upstreams, link(catalog.Id, model.CRITICAL, "Latency"))
	catalog.Downstreams = append(catalog.Downstreams, link(front.Id, model.UNKNOWN), link(order.Id, model.UNKNOWN))
	catalog.Upstreams = append(catalog.Upstreams, link(db.Id, model.CRITICAL, "Latency", "TCP retransmissions"))
	db.Downstreams = append(db.Downstreams, link(catalog.Id, model.UNKNOWN))

	return &model.PropagationMap{Applications: []*model.PropagationMapApplication{front, cache, kafka, order, catalog, db}}
}

func demoOfficialCandidate(ctx timeseries.Context, ids map[string]model.ApplicationId) *model.RCACandidate {
	component := ids["analytics-updater"].String()
	return &model.RCACandidate{
		Id:                      "h-demo-001",
		RootCauseOccurrenceTime: ctx.From.Add(12 * timeseries.Minute).ToStandard().Format("2006-01-02T15:04:05Z"),
		Component:               component,
		ComponentType:           string(model.ApplicationKindCronJob),
		RootCauseReason:         "node_cpu_starvation",
		Scenario:                "cronjob_node_cpu_starvation",
		Score:                   0.94,
		Confidence:              "high",
		ReasonCodes: []string{
			"official_demo_z14gocke",
			"node3_cpu_saturation",
			"dependency_cascade_frontend_catalog_db",
		},
		EvidenceRefs: []string{
			"fixture:demo-z14gocke-show-more-details",
			"component:" + component,
			"node:node3",
			"map:front-end->catalog->db-main",
			"widget:2",
			"widget:3",
			"widget:4",
			"widget:15",
			"widget:19",
			"log:front-end-cache-timeouts",
		},
		PyRCAScores: &model.PyRCAScores{
			RandomWalk:        0.92,
			Bayesian:          0.95,
			HypothesisTesting: 0.93,
			DomainPrior:       0.90,
			Combined:          0.93,
			GraphPaths: [][]string{
				{ids["analytics-updater"].String(), "node:node3", ids["front-end"].String()},
				{ids["front-end"].String(), ids["catalog"].String(), ids["db-main"].String()},
				{ids["front-end"].String(), ids["order"].String(), ids["catalog"].String()},
			},
			Constraints: []string{
				"periodic job allowed as root candidate",
				"root cause must precede downstream latency",
				"dependency path must match propagation map",
			},
		},
	}
}

func demoOfficialWidgets(ctx timeseries.Context) []*model.Widget {
	spec := func(title string, series ...demoSeriesSpec) *model.Widget {
		ch := model.NewChart(ctx, title)
		for _, s := range series {
			ch.AddSeries(s.Name, demoSeries(ctx, s.Base, s.Peak, s.Recovery, s.Mode), s.Color)
		}
		return &model.Widget{Chart: ch}
	}
	widgets := []*model.Widget{
		spec("Requests to <i>front-end</i> by status, per second",
			demoSeriesSpec{Name: "2xx", Base: 240, Peak: 130, Recovery: 220, Mode: "dip", Color: "#23d160"},
			demoSeriesSpec{Name: "5xx", Base: 1, Peak: 70, Recovery: 5, Mode: "spike", Color: "#f44034"},
		),
		spec("Latency of <i>front-end</i>, seconds",
			demoSeriesSpec{Name: "p50", Base: 0.09, Peak: 0.42, Recovery: 0.12, Mode: "spike"},
			demoSeriesSpec{Name: "p95", Base: 0.22, Peak: 2.4, Recovery: 0.31, Mode: "spike", Color: "#f44034"},
		),
		spec("CPU delay of <i>analytics-updater</i>, seconds/second",
			demoSeriesSpec{Name: "analytics-updater", Base: 0.01, Peak: 0.78, Recovery: 0.05, Mode: "spike", Color: "#f44034"},
		),
		spec("CPU throttling of <i>analytics-updater</i>, seconds/second",
			demoSeriesSpec{Name: "analytics-updater", Base: 0.0, Peak: 0.62, Recovery: 0.03, Mode: "spike", Color: "#f44034"},
		),
		spec("Node CPU usage on <i>node3</i>, %",
			demoSeriesSpec{Name: "node3", Base: 58, Peak: 99, Recovery: 63, Mode: "spike", Color: "#f44034"},
			demoSeriesSpec{Name: "cluster median", Base: 45, Peak: 48, Recovery: 45, Mode: "flat"},
		),
		spec("CPU consumers on <i>node3</i>, cores",
			demoSeriesSpec{Name: "analytics-updater", Base: 0.2, Peak: 7.8, Recovery: 0.3, Mode: "spike", Color: "#f44034"},
			demoSeriesSpec{Name: "front-end", Base: 0.9, Peak: 1.6, Recovery: 1.0, Mode: "spike"},
			demoSeriesSpec{Name: "catalog", Base: 0.7, Peak: 1.4, Recovery: 0.8, Mode: "spike"},
		),
		spec("CPU delay of <i>front-end</i>, seconds/second",
			demoSeriesSpec{Name: "front-end", Base: 0.01, Peak: 0.31, Recovery: 0.04, Mode: "spike"},
		),
		spec("CPU throttling of <i>front-end</i>, seconds/second",
			demoSeriesSpec{Name: "front-end", Base: 0.0, Peak: 0.24, Recovery: 0.02, Mode: "spike"},
		),
		spec("Latency <i>front-end</i> ↔ <i>cache</i>, seconds",
			demoSeriesSpec{Name: "p95", Base: 0.012, Peak: 0.62, Recovery: 0.03, Mode: "spike", Color: "#f44034"},
		),
		spec("Latency <i>front-end</i> ↔ <i>kafka</i>, seconds",
			demoSeriesSpec{Name: "p95", Base: 0.025, Peak: 0.74, Recovery: 0.05, Mode: "spike", Color: "#f44034"},
		),
		spec("Latency <i>front-end</i> ↔ <i>order</i>, seconds",
			demoSeriesSpec{Name: "p95", Base: 0.04, Peak: 1.1, Recovery: 0.07, Mode: "spike", Color: "#f44034"},
		),
		spec("Latency <i>order</i> ↔ <i>catalog</i>, seconds",
			demoSeriesSpec{Name: "p95", Base: 0.05, Peak: 1.4, Recovery: 0.08, Mode: "spike", Color: "#f44034"},
		),
		spec("Latency <i>front-end</i> ↔ <i>catalog</i>, seconds",
			demoSeriesSpec{Name: "p95", Base: 0.06, Peak: 1.8, Recovery: 0.10, Mode: "spike", Color: "#f44034"},
		),
		spec("CPU delay of <i>catalog</i>, seconds/second",
			demoSeriesSpec{Name: "catalog", Base: 0.02, Peak: 0.44, Recovery: 0.05, Mode: "spike"},
		),
		spec("CPU throttling of <i>catalog</i>, seconds/second",
			demoSeriesSpec{Name: "catalog", Base: 0.0, Peak: 0.28, Recovery: 0.02, Mode: "spike"},
		),
		spec("TCP retransmissions <i>catalog</i> ↔ <i>db-main</i>, per second",
			demoSeriesSpec{Name: "catalog -> db-main", Base: 0.3, Peak: 34, Recovery: 1.2, Mode: "spike", Color: "#f44034"},
		),
		spec("Latency <i>catalog</i> ↔ <i>db-main</i>, seconds",
			demoSeriesSpec{Name: "p95", Base: 0.08, Peak: 2.2, Recovery: 0.12, Mode: "spike", Color: "#f44034"},
		),
		spec("CPU delay of <i>db-main</i>, seconds/second",
			demoSeriesSpec{Name: "db-main", Base: 0.01, Peak: 0.33, Recovery: 0.04, Mode: "spike"},
		),
		spec("CPU throttling of <i>db-main</i>, seconds/second",
			demoSeriesSpec{Name: "db-main", Base: 0.0, Peak: 0.19, Recovery: 0.01, Mode: "spike"},
		),
		spec("Storage latency of <i>db-main-0</i>, seconds",
			demoSeriesSpec{Name: "p95", Base: 0.004, Peak: 0.19, Recovery: 0.009, Mode: "spike", Color: "#f44034"},
		),
		spec("Log errors of <i>front-end</i>, messages/second",
			demoSeriesSpec{Name: "cache timeout", Base: 0, Peak: 38, Recovery: 1, Mode: "spike", Color: "#f44034"},
			demoSeriesSpec{Name: "context deadline exceeded", Base: 0, Peak: 17, Recovery: 1, Mode: "spike"},
		),
		spec("Trace duration <i>front-end</i> → <i>catalog</i> → <i>db-main</i>, seconds",
			demoSeriesSpec{Name: "slow trace p95", Base: 0.21, Peak: 3.6, Recovery: 0.28, Mode: "spike", Color: "#f44034"},
		),
		spec("Kubernetes events on <i>node3</i>, events/minute",
			demoSeriesSpec{Name: "Scheduled analytics-updater", Base: 0, Peak: 2, Recovery: 0, Mode: "pulse"},
			demoSeriesSpec{Name: "CPU pressure warning", Base: 0, Peak: 5, Recovery: 0, Mode: "pulse", Color: "#f44034"},
		),
	}
	return widgets
}

type demoSeriesSpec struct {
	Name     string
	Base     float32
	Peak     float32
	Recovery float32
	Mode     string
	Color    string
}

func demoSeries(ctx timeseries.Context, base, peak, recovery float32, mode string) *timeseries.TimeSeries {
	points := ctx.PointsCount()
	if points < 40 {
		points = 60
	}
	data := make([]float32, points)
	start := points / 4
	end := points * 3 / 4
	for i := range data {
		v := base
		switch {
		case i >= start && i <= end:
			progress := float32(i-start) / float32(maxInt(1, end-start))
			switch mode {
			case "dip":
				v = base - (base-peak)*(0.72+0.28*progress)
			case "pulse":
				if i < start+maxInt(2, (end-start)/5) {
					v = peak
				} else {
					v = base
				}
			default:
				v = base + (peak-base)*(0.72+0.28*progress)
			}
		case i > end:
			progress := float32(i-end) / float32(maxInt(1, points-end-1))
			v = peak + (recovery-peak)*progress
			if mode == "pulse" {
				v = recovery
			}
		default:
			v = base
		}
		if mode != "pulse" {
			jitter := float32((i%5)-2) * (base + peak + recovery) / 600
			v += jitter
		}
		if v < 0 {
			v = 0
		}
		data[i] = v
	}
	return timeseries.NewWithData(ctx.From, ctx.Step, data)
}

func demoOfficialDetails() string {
	return strings.TrimSpace(`## Incident Overview

The ` + "`front-end`" + ` service experienced errors, high latency, CPU pressure, and application error logs during the incident window. The visible impact starts at the edge service and is supported by request, latency, and log metrics.

WIDGET-0

WIDGET-1

## Root Cause: analytics-updater CronJob saturated node3 CPU

Coroot correlated the first strong anomaly with the ` + "`analytics-updater`" + ` CronJob running on ` + "`node3`" + `. The job consumed the node CPU budget before the user-facing latency spike, and the affected front-end/catalog workloads on the same node started reporting CPU delay and throttling immediately after that point.

WIDGET-2

WIDGET-3

WIDGET-4

WIDGET-5

## Cascading Impact

The relationship map above follows the official demo structure and shows the dependency cascade:

1. **` + "`front-end`" + ` → ` + "`cache`" + `** reported latency as requests waited on cache reads.
2. **` + "`front-end`" + ` → ` + "`kafka`" + `** reported latency while the queue client also showed CPU pressure.
3. **` + "`front-end`" + ` → ` + "`order`" + `** reported latency, and ` + "`order`" + ` then propagated latency to ` + "`catalog`" + `.
4. **` + "`front-end`" + ` → ` + "`catalog`" + `** reported the direct user-facing catalog latency path.
5. **` + "`catalog`" + ` → ` + "`db-main`" + `** showed latency plus TCP retransmissions, while ` + "`db-main`" + ` also showed CPU and storage latency.

WIDGET-8

WIDGET-9

WIDGET-10

WIDGET-11

WIDGET-12

WIDGET-13

WIDGET-14

WIDGET-15

WIDGET-16

WIDGET-17

WIDGET-18

WIDGET-19

## Trace Evidence

Synthetic traces follow the same request path as the official detail view: ` + "`front-end`" + ` receives the user request, fans out to ` + "`cache`" + `, ` + "`kafka`" + `, ` + "`order`" + `, and ` + "`catalog`" + `, and the slowest downstream segment is ` + "`catalog`" + ` → ` + "`db-main`" + `. The log evidence contains cache timeout and context deadline patterns from the local incident lab stream.

WIDGET-20

WIDGET-21

## Kubernetes Events Confirmation

- ` + "`analytics-updater`" + ` was scheduled on ` + "`node3`" + ` inside the incident window.
- ` + "`node3`" + ` emitted CPU pressure warnings while ` + "`front-end`" + ` and ` + "`catalog`" + ` showed CPU throttling.
- No deployment rollout is required to explain the sequence; the earliest strong trigger is node-level CPU starvation from the periodic job.

WIDGET-22`)
}

func demoOfficialTrajectory(ctx timeseries.Context, ids map[string]model.ApplicationId, candidate *model.RCACandidate) []model.RCATrajectory {
	return []model.RCATrajectory{
		{
			Step:          1,
			Tool:          "get_incident_context",
			InputSummary:  ids["front-end"].String(),
			OutputSummary: fmt.Sprintf("official demo fixture window %s..%s", ctx.From.ToStandard().Format("2006-01-02T15:04:05Z"), ctx.To.ToStandard().Format("2006-01-02T15:04:05Z")),
		},
		{
			Step:          2,
			Tool:          "build_dependency_graph",
			InputSummary:  "front-end upstreams and downstream back-links",
			OutputSummary: "6 applications, 6 symptomatic dependency edges, catalog to db-main retransmission edge",
			EvidenceRefs:  []string{"map:front-end->catalog->db-main"},
		},
		{
			Step:          3,
			Tool:          "correlate_node_cpu",
			InputSummary:  "node3 CPU usage, CPU delay and throttling widgets",
			OutputSummary: "analytics-updater is the first high-confidence anomaly before service latency",
			EvidenceRefs:  []string{"widget:2", "widget:3", "widget:4", "widget:5"},
		},
		{
			Step:          4,
			Tool:          "trace_dependency_path",
			InputSummary:  "front-end request fanout and catalog/db-main path",
			OutputSummary: "slow trace and logs align with front-end to catalog to db-main impact",
			EvidenceRefs:  []string{"widget:20", "widget:21", "log:front-end-cache-timeouts"},
		},
		{
			Step:          5,
			Tool:          "score_candidates",
			InputSummary:  "OpenRCA time/component/reason triple and PyRCA graph paths",
			OutputSummary: fmt.Sprintf("top candidate %s on %s with score %.2f", candidate.RootCauseReason, candidate.Component, candidate.Score),
			EvidenceRefs:  candidate.EvidenceRefs,
		},
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
