package db

import (
	"testing"

	"github.com/coroot/coroot/model"
	"github.com/coroot/coroot/timeseries"
)

func TestApplyRCARemediationActionStates(t *testing.T) {
	rca := &model.RCA{
		Remediation: []model.RCARemediationAction{
			{
				Id:           "verify-evidence",
				Title:        "Verify evidence",
				Status:       RCARemediationStatusNotStarted,
				EvidenceRefs: []string{"check:SLO"},
			},
		},
	}
	ApplyRCARemediationActionStates(rca, map[string]model.RCARemediationAction{
		"verify-evidence": {
			Id:                 "verify-evidence",
			Status:             RCARemediationStatusVerified,
			VerificationStatus: "passed",
			VerifiedBy:         "sre@example.com",
			VerifiedAt:         timeseries.Time(100),
		},
	})
	action := rca.Remediation[0]
	if action.Title != "Verify evidence" || len(action.EvidenceRefs) != 1 {
		t.Fatalf("expected remediation metadata to be preserved: %+v", action)
	}
	if action.Status != RCARemediationStatusVerified || action.VerificationStatus != "passed" || action.VerifiedBy != "sre@example.com" {
		t.Fatalf("unexpected merged state: %+v", action)
	}
}
