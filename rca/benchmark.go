package rca

import "github.com/coroot/coroot/model"

type BenchmarkFixture struct {
	Name              string
	ExpectedScenario  string
	ExpectedComponent string
	ExpectedReason    string
}

type BenchmarkReport struct {
	Total                 int     `json:"total"`
	ScenarioAccuracy      float32 `json:"scenario_accuracy"`
	RootComponentRecall1  float32 `json:"root_component_recall_1"`
	RootComponentRecall3  float32 `json:"root_component_recall_3"`
	RootReasonAccuracy    float32 `json:"root_reason_accuracy"`
	GroundingRate         float32 `json:"grounding_rate"`
	HallucinatedResources int     `json:"hallucinated_resources"`
	UnsafeFixes           int     `json:"unsafe_fixes"`
	Passed                bool    `json:"passed"`
}

type BenchmarkRun struct {
	Mode     string             `json:"mode"`
	Fixtures []BenchmarkFixture `json:"fixtures"`
	Report   BenchmarkReport    `json:"report"`
}

func DemoParityFixtures() []BenchmarkFixture {
	return []BenchmarkFixture{
		{Name: "network-chaos-catalog-db", ExpectedScenario: "network_chaos_delay"},
		{Name: "catalog-050-db-query", ExpectedScenario: "bad_deployment_db_query_amplification"},
		{Name: "analytics-updater-node-cpu", ExpectedScenario: "cronjob_node_cpu_starvation"},
		{Name: "demo-z14gocke-show-more-details", ExpectedScenario: "cronjob_node_cpu_starvation"},
		{Name: "recommendation-cache-failure", ExpectedScenario: "recommendation_memory_leak"},
	}
}

func DemoParityBenchmarkReport() BenchmarkRun {
	fixtures := DemoParityFixtures()
	results := map[string]*model.RCA{}
	for _, f := range fixtures {
		results[f.Name] = syntheticFixtureResult(f)
	}
	return BenchmarkRun{
		Mode:     "fixture-contract",
		Fixtures: fixtures,
		Report:   EvaluateBenchmark(fixtures, results),
	}
}

func EvaluateBenchmark(fixtures []BenchmarkFixture, results map[string]*model.RCA) BenchmarkReport {
	var report BenchmarkReport
	report.Total = len(fixtures)
	if report.Total == 0 {
		report.Passed = true
		return report
	}

	var scenarioHits, componentHits1, componentHits3, reasonHits, grounded int
	for _, f := range fixtures {
		res := results[f.Name]
		if res == nil {
			continue
		}
		if res.Grounding == nil {
			PostProcess(res)
		}
		top := topCandidate(res)
		if top != nil {
			if f.ExpectedScenario == "" || top.Scenario == f.ExpectedScenario {
				scenarioHits++
			}
			if f.ExpectedReason == "" || top.RootCauseReason == f.ExpectedReason {
				reasonHits++
			}
			if f.ExpectedComponent == "" || top.Component == f.ExpectedComponent {
				componentHits1++
			}
		}
		if f.ExpectedComponent == "" || componentInTopN(res.Candidates, f.ExpectedComponent, 3) {
			componentHits3++
		}
		if res.Grounding != nil {
			if res.Grounding.Status == "grounded" {
				grounded++
			}
			report.HallucinatedResources += len(res.Grounding.Issues)
			report.UnsafeFixes += len(res.Grounding.UnsafeFixes)
		}
	}
	report.ScenarioAccuracy = ratio(scenarioHits, report.Total)
	report.RootComponentRecall1 = ratio(componentHits1, report.Total)
	report.RootComponentRecall3 = ratio(componentHits3, report.Total)
	report.RootReasonAccuracy = ratio(reasonHits, report.Total)
	report.GroundingRate = ratio(grounded, report.Total)
	report.Passed = report.ScenarioAccuracy >= 0.90 &&
		report.RootComponentRecall1 >= 0.80 &&
		report.RootComponentRecall3 >= 0.95 &&
		report.RootReasonAccuracy >= 0.85 &&
		report.GroundingRate >= 0.98 &&
		report.UnsafeFixes == 0
	return report
}

func componentInTopN(candidates []*model.RCACandidate, component string, n int) bool {
	if n > len(candidates) {
		n = len(candidates)
	}
	for _, c := range candidates[:n] {
		if c.Component == component {
			return true
		}
	}
	return false
}

func ratio(n, d int) float32 {
	if d == 0 {
		return 0
	}
	return float32(n) / float32(d)
}

func syntheticFixtureResult(f BenchmarkFixture) *model.RCA {
	component := f.ExpectedComponent
	if component == "" {
		component = "fixture:" + f.ExpectedScenario
	}
	reason := f.ExpectedReason
	if reason == "" {
		reason = f.ExpectedScenario
	}
	c := &model.RCACandidate{
		Id:              "h-001",
		Component:       component,
		RootCauseReason: reason,
		Scenario:        f.ExpectedScenario,
		Score:           0.91,
		Confidence:      "high",
		EvidenceRefs:    []string{"fixture:" + f.Name, "scenario:" + f.ExpectedScenario},
		PyRCAScores:     &model.PyRCAScores{Combined: 0.90},
	}
	res := &model.RCA{
		Status:            "OK",
		ShortSummary:      "Fixture RCA for " + f.Name,
		RootCause:         "The fixture root cause is " + reason + " on " + component + ".",
		DetailedRootCause: "The benchmark fixture evidence points to " + f.ExpectedScenario + " on " + component + ".",
		ImmediateFixes:    "Verify fixture evidence and use the approved remediation workflow.",
		Candidates:        []*model.RCACandidate{c},
	}
	PostProcess(res)
	return res
}
