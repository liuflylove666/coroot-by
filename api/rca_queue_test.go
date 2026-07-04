package api

import (
	"testing"

	"github.com/coroot/coroot/db"
	"github.com/coroot/coroot/model"
	"github.com/coroot/coroot/timeseries"
)

func TestRetryableRCAFailure(t *testing.T) {
	if !retryableRCAFailure("timeout: provider did not respond") {
		t.Fatal("expected provider timeout to be retryable")
	}
	if retryableRCAFailure("application not found") {
		t.Fatal("expected application not found to be fatal")
	}
	if retryableRCAFailure("Metric cache is empty") {
		t.Fatal("expected empty metric cache to be fatal")
	}
}

func TestRCARemediationTransitionApprovalFlow(t *testing.T) {
	now := timeseries.Time(100)
	action := model.RCARemediationAction{
		Id:               "rollback-rollout",
		Status:           db.RCARemediationStatusWaitingForApproval,
		RequiresApproval: true,
	}
	if _, err := applyRCARemediationTransition(action, rcaRemediationForm{Action: "start"}, "alice@example.com", now); err == nil {
		t.Fatal("expected start before approval to fail")
	}

	action, err := applyRCARemediationTransition(action, rcaRemediationForm{Action: "approve"}, "alice@example.com", now)
	if err != nil {
		t.Fatal(err)
	}
	if action.Status != db.RCARemediationStatusApproved || action.ApprovedBy != "alice@example.com" || action.ApprovedAt != now {
		t.Fatalf("unexpected approved action: %+v", action)
	}

	action, err = applyRCARemediationTransition(action, rcaRemediationForm{Action: "start"}, "bob@example.com", now+1)
	if err != nil {
		t.Fatal(err)
	}
	if action.Status != db.RCARemediationStatusInProgress || action.StartedBy != "bob@example.com" {
		t.Fatalf("unexpected started action: %+v", action)
	}

	action, err = applyRCARemediationTransition(action, rcaRemediationForm{Action: "complete"}, "bob@example.com", now+2)
	if err != nil {
		t.Fatal(err)
	}
	action, err = applyRCARemediationTransition(action, rcaRemediationForm{Action: "verify_pass"}, "carol@example.com", now+3)
	if err != nil {
		t.Fatal(err)
	}
	if action.Status != db.RCARemediationStatusVerified || action.VerificationStatus != "passed" || action.VerifiedBy != "carol@example.com" {
		t.Fatalf("unexpected verified action: %+v", action)
	}
}
