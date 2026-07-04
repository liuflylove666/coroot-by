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
