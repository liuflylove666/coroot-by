package rca

import (
	"strings"
	"testing"

	"github.com/coroot/coroot/model"
	"github.com/coroot/coroot/timeseries"
	"github.com/coroot/coroot/utils"
)

func TestAIPromptUsesOfficialFindingsPackage(t *testing.T) {
	front := model.NewApplicationId("test", "default", model.ApplicationKindDeployment, "front-end")
	catalog := model.NewApplicationId("test", "default", model.ApplicationKindDeployment, "catalog")
	db := model.NewApplicationId("test", "default", model.ApplicationKindStatefulSet, "db-main")
	rca := &model.RCA{
		ShortSummary:   "front-end latency and errors increased",
		RootCause:      "catalog cannot reach db-main in time",
		ImmediateFixes: "Verify catalog to db-main connectivity; token=secret should be hidden",
		Candidates: []*model.RCACandidate{
			{
				Id:              "h-001",
				Component:       catalog.String() + "->" + db.String(),
				RootCauseReason: "network_connectivity_or_latency",
				Scenario:        "network_chaos_delay",
				Score:           0.91,
				Confidence:      "high",
				EvidenceRefs:    []string{"link:" + catalog.String() + "->" + db.String(), "message:api_key=secret"},
				PyRCAScores: &model.PyRCAScores{
					RandomWalk:        0.8,
					Bayesian:          0.9,
					HypothesisTesting: 0.85,
					DomainPrior:       0.8,
					Combined:          0.84,
					GraphPaths:        [][]string{{front.String(), catalog.String(), db.String()}},
				},
			},
		},
		PropagationMap: &model.PropagationMap{Applications: []*model.PropagationMapApplication{
			{
				Id:     front,
				Status: model.CRITICAL,
				Issues: []string{"Errors", "Latency"},
				Upstreams: []*model.PropagationMapApplicationLink{
					{Id: catalog, Status: model.CRITICAL, Stats: utils.NewStringSet("Latency")},
				},
			},
			{
				Id:     catalog,
				Status: model.CRITICAL,
				Issues: []string{"Latency", "TCP retransmissions to db-main"},
				Upstreams: []*model.PropagationMapApplicationLink{
					{Id: db, Status: model.CRITICAL, Stats: utils.NewStringSet("Latency", "TCP retransmissions")},
				},
			},
			{Id: db, Status: model.WARNING, Issues: []string{"Storage: latency"}},
		}},
		Widgets: []*model.Widget{
			{Chart: model.NewChart(timeseries.Context{}, "Latency <i>front-end</i> ↔ <i>catalog</i>, seconds")},
			{Chart: model.NewChart(timeseries.Context{}, "TCP retransmissions <i>catalog</i> ↔ <i>db-main</i>, segments/second")},
		},
		Evidence: []model.RCAEvidence{
			{Id: "edge:" + catalog.String() + "->" + db.String(), Type: "edge", Title: "catalog -> db-main", Summary: "Dependency edge used by Cascading Impact."},
			{Id: "widget:1", Type: "widget", Title: "TCP retransmissions catalog ↔ db-main"},
		},
		Trajectory: []model.RCATrajectory{
			{Step: 1, Tool: "build_dependency_graph", OutputSummary: "front-end -> catalog -> db-main", EvidenceRefs: []string{"edge:" + catalog.String() + "->" + db.String()}},
		},
		MissingEvidence: []string{"Kubernetes events"},
	}

	system, prompt := aiPrompt(rca)
	for _, want := range []string{
		"Coroot has already performed the root-cause investigation",
		"not raw telemetry",
	} {
		if !strings.Contains(system, want) {
			t.Fatalf("expected system prompt to contain %q:\n%s", want, system)
		}
	}
	for _, want := range []string{
		"Built-in anomaly summary",
		"Propagation map findings",
		"edge=test:default:Deployment:front-end -> test:default:Deployment:catalog",
		"Relevant chart/widget findings",
		"WIDGET-1: TCP retransmissions catalog ↔ db-main, segments/second",
		"Evidence registry",
		"Investigation trajectory",
		"Anomaly summary, Issue propagation paths, Key findings and Root Cause Analysis, Remediation, Relevant charts",
	} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("expected prompt to contain %q:\n%s", want, prompt)
		}
	}
	if strings.Contains(prompt, "secret") || !strings.Contains(prompt, "token=<redacted>") || !strings.Contains(prompt, "api_key=<redacted>") {
		t.Fatalf("expected sensitive values to be redacted:\n%s", prompt)
	}
}
