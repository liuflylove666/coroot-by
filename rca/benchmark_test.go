package rca

import (
	"testing"

	"github.com/coroot/coroot/model"
)

func TestEvaluateBenchmark(t *testing.T) {
	fixtures := DemoParityFixtures()
	results := map[string]*model.RCA{}
	for _, f := range fixtures {
		results[f.Name] = benchmarkRCA(f.ExpectedScenario)
	}
	report := EvaluateBenchmark(fixtures, results)
	if !report.Passed {
		t.Fatalf("expected benchmark to pass: %+v", report)
	}
}

func TestDemoParityBenchmarkReport(t *testing.T) {
	run := DemoParityBenchmarkReport()
	if run.Mode != "fixture-contract" {
		t.Fatalf("unexpected mode: %s", run.Mode)
	}
	if len(run.Fixtures) == 0 || run.Report.Total != len(run.Fixtures) || !run.Report.Passed {
		t.Fatalf("unexpected benchmark run: %+v", run)
	}
}

func TestGroundingFlagsUnsafeFixes(t *testing.T) {
	res := benchmarkRCA("network_chaos_delay")
	res.ImmediateFixes = "```bash\nkubectl delete networkchaos catalog-delay\n```"
	PostProcess(res)
	if res.Grounding == nil || res.Grounding.Status != "unsafe" || len(res.Grounding.UnsafeFixes) == 0 {
		t.Fatalf("expected unsafe grounding result: %+v", res.Grounding)
	}
	if res.ValidatorResult != "unsafe_needs_human_review" {
		t.Fatalf("unexpected validator result: %s", res.ValidatorResult)
	}
}

func TestGroundingFlagsHallucinatedResources(t *testing.T) {
	res := benchmarkRCA("bad_deployment_db_query_amplification")
	res.RootCause = "The rollout on `payment-service` caused DB pressure."
	res.DetailedRootCause = "Known evidence still only points to `catalog` latency and `db-main` pressure."
	res.ImmediateFixes = "Check `payment-service` and roll it back if confirmed."
	res.Candidates[0].Component = "cluster:default:Deployment:catalog"
	res.Candidates[0].EvidenceRefs = []string{"metric:catalog:latency", "metric:db-main:query-latency"}
	res.PropagationMap = &model.PropagationMap{Applications: []*model.PropagationMapApplication{
		{Id: model.NewApplicationId("cluster", "default", model.ApplicationKindDeployment, "catalog")},
		{Id: model.NewApplicationId("cluster", "default", model.ApplicationKindStatefulSet, "db-main")},
	}}

	PostProcess(res)

	if res.Grounding == nil || res.Grounding.Status != "suspicious" {
		t.Fatalf("expected suspicious grounding result: %+v", res.Grounding)
	}
	if !hasString(res.Grounding.HallucinatedResources, "payment-service") {
		t.Fatalf("expected payment-service hallucination, got %+v", res.Grounding.HallucinatedResources)
	}
	if res.ValidatorResult != "grounded_with_warnings" {
		t.Fatalf("unexpected validator result: %s", res.ValidatorResult)
	}
}

func TestGroundingAllowsEvidenceResources(t *testing.T) {
	res := benchmarkRCA("network_chaos_delay")
	res.RootCause = "The active `networkchaos/catalog-delay` resource delayed `catalog` to `db-main` calls."
	res.DetailedRootCause = "Evidence shows `deployment/catalog`, `catalog`, and `db-main` latency on the propagation path."
	res.ImmediateFixes = "Verify `networkchaos/catalog-delay` and recover only after evidence is confirmed."
	res.Candidates[0].Component = "cluster:default:Deployment:catalog"
	res.Candidates[0].EvidenceRefs = []string{
		"networkchaos/default/catalog-delay",
		"metric:catalog:latency",
		"metric:db-main:tcp-retransmissions",
	}
	res.Evidence = []model.RCAEvidence{
		{
			Id:        "networkchaos/default/catalog-delay",
			Type:      "k8s_event",
			Title:     "NetworkChaos catalog-delay is active",
			Component: "cluster:default:Deployment:catalog",
			Refs:      []string{"networkchaos/catalog-delay"},
		},
	}
	res.PropagationMap = &model.PropagationMap{Applications: []*model.PropagationMapApplication{
		{Id: model.NewApplicationId("cluster", "default", model.ApplicationKindDeployment, "catalog")},
		{Id: model.NewApplicationId("cluster", "default", model.ApplicationKindStatefulSet, "db-main")},
	}}

	PostProcess(res)

	if res.Grounding == nil || len(res.Grounding.HallucinatedResources) != 0 {
		t.Fatalf("expected no hallucinated resources, got %+v", res.Grounding)
	}
}

func TestPostProcessBuildsAIOpsEnhancements(t *testing.T) {
	res := benchmarkRCA("cronjob_node_cpu_starvation")
	if len(res.Anomalies) == 0 {
		t.Fatalf("expected anomaly signals")
	}
	if res.Anomalies[0].Detector != aiopsDetector {
		t.Fatalf("unexpected detector: %+v", res.Anomalies[0])
	}
	if len(res.SLOForecasts) == 0 {
		t.Fatalf("expected SLO forecasts")
	}
	if res.Runbook == nil || !res.Runbook.SectionsComplete {
		t.Fatalf("expected complete runbook: %+v", res.Runbook)
	}
	if !hasString(res.Runbook.AffectedServices, "cronjob_node_cpu_starvation") {
		t.Fatalf("expected affected services to include component display name: %+v", res.Runbook.AffectedServices)
	}
	if !hasTrajectoryTool(res, "aiops_signal_enrichment") {
		t.Fatalf("expected aiops enrichment trajectory: %+v", res.Trajectory)
	}
}

func TestAIOpsEnhancementsSkipInsufficientEvidenceSignals(t *testing.T) {
	res := benchmarkRCA("network_chaos_delay")
	res.Candidates[0].RootCauseReason = "insufficient_evidence"
	res.Candidates[0].Scenario = ""
	res.Candidates[0].Score = 0.30
	res.Candidates[0].ScoreBreakdown = nil

	PostProcess(res)

	if len(res.Anomalies) != 0 {
		t.Fatalf("expected no anomaly signals for insufficient evidence, got %+v", res.Anomalies)
	}
	if len(res.SLOForecasts) != 0 {
		t.Fatalf("expected no SLO forecasts for insufficient evidence, got %+v", res.SLOForecasts)
	}
}

func TestGroundingChecksRunbookAndRemediationResources(t *testing.T) {
	res := benchmarkRCA("bad_deployment_db_query_amplification")
	res.Remediation = []model.RCARemediationAction{
		{
			Id:           "rollback",
			Title:        "Rollback unverified service",
			Description:  "Suggested command from evidence:\n```bash\nkubectl -n default rollout undo deployment/payment-service\n```",
			EvidenceRefs: []string{"metric:catalog:latency"},
		},
	}
	res.Runbook = &model.RCARunbook{
		Title:            "Unverified service rollback",
		Summary:          "Rollback `deployment/payment-service` if confirmed.",
		ImpactAssessment: "Payment service is mentioned without evidence.",
		DiagnosisSteps:   "Verify `deployment/payment-service` before acting.",
		RemediationSteps: "Do not change `deployment/payment-service` until evidence exists.",
		FollowUpActions:  "Add missing evidence.",
	}

	res.Grounding = ValidateGrounding(res)

	if res.Grounding == nil || !hasString(res.Grounding.HallucinatedResources, "deployment/payment-service") {
		t.Fatalf("expected remediation/runbook resource hallucination, got %+v", res.Grounding)
	}
}

func benchmarkRCA(scenario string) *model.RCA {
	c := &model.RCACandidate{
		Id:              "h-001",
		Component:       "default:Deployment:" + scenario,
		RootCauseReason: scenario,
		Scenario:        scenario,
		Score:           0.91,
		Confidence:      "high",
		EvidenceRefs:    []string{"check:" + scenario, "widget:" + scenario},
		PyRCAScores:     &model.PyRCAScores{Combined: 0.90},
	}
	res := &model.RCA{
		Status:            "OK",
		ShortSummary:      "Synthetic RCA for " + scenario,
		RootCause:         "The root cause is " + scenario + " on " + c.Component + ".",
		DetailedRootCause: "Evidence shows " + scenario + " on " + c.Component + ".",
		ImmediateFixes:    "Verify evidence and apply the approved workflow.",
		Candidates:        []*model.RCACandidate{c},
	}
	PostProcess(res)
	return res
}
