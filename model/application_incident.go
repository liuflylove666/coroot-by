package model

import (
	"fmt"

	"github.com/coroot/coroot/timeseries"
	"github.com/coroot/coroot/utils"
)

type Impact struct {
	AffectedRequestPercentage float32 `json:"percentage"`
}

type IncidentDetails struct {
	AvailabilityBurnRates []BurnRate `json:"availability_burn_rates"`
	LatencyBurnRates      []BurnRate `json:"latency_burn_rates"`
	AvailabilityImpact    Impact     `json:"availability_impact"`
	LatencyImpact         Impact     `json:"latency_impact"`
}

type RCA struct {
	Status            string                 `json:"status"`
	Error             string                 `json:"error"`
	ShortSummary      string                 `json:"short_summary"`
	RootCause         string                 `json:"root_cause"`
	ImmediateFixes    string                 `json:"immediate_fixes"`
	DetailedRootCause string                 `json:"detailed_root_cause_analysis"`
	PropagationMap    *PropagationMap        `json:"propagation_map"`
	Widgets           []*Widget              `json:"widgets"`
	Candidates        []*RCACandidate        `json:"candidates,omitempty"`
	Evidence          []RCAEvidence          `json:"evidence,omitempty"`
	MissingEvidence   []string               `json:"missing_evidence,omitempty"`
	Trajectory        []RCATrajectory        `json:"trajectory,omitempty"`
	Grounding         *RCAGrounding          `json:"grounding,omitempty"`
	Remediation       []RCARemediationAction `json:"remediation,omitempty"`
	HistoricalContext []RCAHistoricalContext `json:"historical_context,omitempty"`
	Provider          string                 `json:"provider,omitempty"`
	Model             string                 `json:"model,omitempty"`
	ValidatorResult   string                 `json:"validator_result,omitempty"`
	TokenInput        int                    `json:"input_tokens,omitempty"`
	TokenOutput       int                    `json:"output_tokens,omitempty"`
	LatencyMs         int64                  `json:"latency_ms,omitempty"`
}

type RCAGrounding struct {
	Status            string   `json:"status"`
	EvidenceCoverage  float32  `json:"evidence_coverage"`
	HallucinationRisk string   `json:"hallucination_risk"`
	Issues            []string `json:"issues,omitempty"`
	UnsafeFixes       []string `json:"unsafe_fixes,omitempty"`
}

type RCARemediationAction struct {
	Id                 string          `json:"id"`
	Title              string          `json:"title"`
	Description        string          `json:"description"`
	Risk               string          `json:"risk"`
	Status             string          `json:"status"`
	RequiresApproval   bool            `json:"requires_approval"`
	EvidenceRefs       []string        `json:"evidence_refs,omitempty"`
	Verification       string          `json:"verification,omitempty"`
	ApprovedBy         string          `json:"approved_by,omitempty"`
	ApprovedAt         timeseries.Time `json:"approved_at,omitempty"`
	StartedBy          string          `json:"started_by,omitempty"`
	StartedAt          timeseries.Time `json:"started_at,omitempty"`
	CompletedBy        string          `json:"completed_by,omitempty"`
	CompletedAt        timeseries.Time `json:"completed_at,omitempty"`
	VerificationStatus string          `json:"verification_status,omitempty"`
	VerificationNote   string          `json:"verification_note,omitempty"`
	VerifiedBy         string          `json:"verified_by,omitempty"`
	VerifiedAt         timeseries.Time `json:"verified_at,omitempty"`
	UpdatedAt          timeseries.Time `json:"updated_at,omitempty"`
}

type RCAHistoricalContext struct {
	IncidentKey string  `json:"incident_key"`
	Scenario    string  `json:"scenario"`
	Component   string  `json:"component"`
	Similarity  float32 `json:"similarity"`
	FixSummary  string  `json:"fix_summary,omitempty"`
	Outcome     string  `json:"outcome,omitempty"`
}

type RCATrajectory struct {
	Step          int      `json:"step"`
	Tool          string   `json:"tool"`
	InputSummary  string   `json:"input_summary"`
	OutputSummary string   `json:"output_summary"`
	EvidenceRefs  []string `json:"evidence_refs,omitempty"`
	EvidenceChain []string `json:"evidence_chain,omitempty"`
	DurationMs    int64    `json:"duration_ms,omitempty"`
}

type RCACandidate struct {
	Id                      string             `json:"id"`
	RootCauseOccurrenceTime string             `json:"root_cause_occurrence_time,omitempty"`
	Component               string             `json:"component"`
	ComponentType           string             `json:"component_type,omitempty"`
	RootCauseReason         string             `json:"root_cause_reason"`
	Scenario                string             `json:"scenario,omitempty"`
	PyRCAScores             *PyRCAScores       `json:"pyrca_scores,omitempty"`
	ScoreBreakdown          *RCAScoreBreakdown `json:"score_breakdown,omitempty"`
	Score                   float32            `json:"score"`
	Confidence              string             `json:"confidence"`
	ReasonCodes             []string           `json:"reason_codes,omitempty"`
	EvidenceRefs            []string           `json:"evidence_refs,omitempty"`
	SupportingEvidence      []string           `json:"supporting_evidence,omitempty"`
	ContradictingEvidence   []string           `json:"contradicting_evidence,omitempty"`
	MissingEvidence         []string           `json:"missing_evidence,omitempty"`
}

type RCAEvidence struct {
	Id         string            `json:"id"`
	Type       string            `json:"type"`
	Title      string            `json:"title"`
	Component  string            `json:"component,omitempty"`
	Summary    string            `json:"summary,omitempty"`
	Source     string            `json:"source,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
	Refs       []string          `json:"refs,omitempty"`
}

type RCAScoreBreakdown struct {
	TimeFit           float32 `json:"time_fit"`
	ComponentFit      float32 `json:"component_fit"`
	ReasonFit         float32 `json:"reason_fit"`
	EventFit          float32 `json:"event_fit"`
	RandomWalk        float32 `json:"random_walk"`
	Bayesian          float32 `json:"bayesian"`
	HypothesisTesting float32 `json:"hypothesis_testing"`
	DomainPrior       float32 `json:"domain_prior"`
	AnomalyStrength   float32 `json:"anomaly_strength"`
	Propagation       float32 `json:"propagation"`
	EvidenceCoverage  float32 `json:"evidence_coverage"`
	OpenRCATriplet    float32 `json:"openrca_triplet"`
	PyRCAGraph        float32 `json:"pyrca_graph"`
	Grounding         float32 `json:"grounding"`
	Final             float32 `json:"final"`
}

type PyRCAScores struct {
	RandomWalk        float32    `json:"random_walk"`
	Bayesian          float32    `json:"bayesian"`
	HypothesisTesting float32    `json:"hypothesis_testing"`
	DomainPrior       float32    `json:"domain_prior"`
	Combined          float32    `json:"combined"`
	GraphPaths        [][]string `json:"graph_paths,omitempty"`
	Constraints       []string   `json:"domain_constraints_applied,omitempty"`
}

type PropagationMap struct {
	Applications []*PropagationMapApplication `json:"applications"`
}

type PropagationMapApplication struct {
	Id     ApplicationId `json:"id"`
	Icon   string        `json:"icon"`
	Labels Labels        `json:"labels"`
	Status Status        `json:"status"`
	Issues []string      `json:"issues,omitempty"`

	Upstreams   []*PropagationMapApplicationLink `json:"upstreams"`
	Downstreams []*PropagationMapApplicationLink `json:"downstreams"`
}

func (app *PropagationMapApplication) Issue(format string, a ...any) {
	issue := fmt.Sprintf(format, a...)
	for _, i := range app.Issues {
		if i == issue {
			return
		}
	}
	app.Issues = append(app.Issues, issue)
}

type PropagationMapApplicationLink struct {
	Id     ApplicationId    `json:"id"`
	Status Status           `json:"status"`
	Stats  *utils.StringSet `json:"stats"`
}

func (l *PropagationMapApplicationLink) AddIssues(issues ...string) {
	l.Status = CRITICAL
	l.Stats.Add(issues...)
}

type ApplicationIncident struct {
	ApplicationId ApplicationId   `json:"application_id"`
	Key           string          `json:"key"`
	OpenedAt      timeseries.Time `json:"opened_at"`
	ResolvedAt    timeseries.Time `json:"resolved_at"`
	Severity      Status          `json:"severity"`
	Details       IncidentDetails `json:"details"`
	RCA           *RCA            `json:"rca"`
}

func (i *ApplicationIncident) Resolved() bool {
	return !i.ResolvedAt.IsZero()
}

func (i *ApplicationIncident) ShortDescription() string {
	var (
		a, l bool
	)

	if i.RCA != nil && i.RCA.ShortSummary != "" {
		return i.RCA.ShortSummary
	}

	if i.Details.AvailabilityImpact.AffectedRequestPercentage > 0 {
		a = true
	}
	if i.Details.LatencyImpact.AffectedRequestPercentage > 0 {
		l = true
	}
	switch {
	case a && l:
		return "High latency and errors"
	case l:
		return "High latency"
	case a:
		return "Elevated error rate"
	}
	return "SLO violation"
}
