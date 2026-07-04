package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/coroot/coroot/db"
	"github.com/coroot/coroot/model"
	"github.com/coroot/coroot/rbac"
	"github.com/coroot/coroot/timeseries"
	"github.com/coroot/coroot/utils"
	"github.com/gorilla/mux"
	"k8s.io/klog"
)

type rcaRemediationForm struct {
	Action             string `json:"action"`
	VerificationStatus string `json:"verification_status"`
	VerificationNote   string `json:"verification_note"`
}

func (api *Api) IncidentRCARemediation(w http.ResponseWriter, r *http.Request, u *db.User) {
	vars := mux.Vars(r)
	projectId := db.ProjectId(vars["project"])
	incidentKey := vars["incident"]
	actionId := vars["action"]

	if !api.IsAllowed(u, rbac.Actions.Project(string(projectId)).Alerts().Edit()) {
		http.Error(w, "You are not allowed to update incident remediation workflows.", http.StatusForbidden)
		return
	}

	var form rcaRemediationForm
	if err := utils.ReadJson(r, &form); err != nil {
		klog.Warningln("bad request:", err)
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	incident, err := api.db.GetIncidentByKey(projectId, incidentKey)
	if err != nil {
		klog.Warningln("incident not found:", err)
		http.Error(w, "incident not found", http.StatusNotFound)
		return
	}
	if incident.RCA == nil || len(incident.RCA.Remediation) == 0 {
		http.Error(w, "RCA remediation workflow not found", http.StatusNotFound)
		return
	}

	if err := api.overlayRCARemediationState(projectId, incident); err != nil {
		klog.Errorln(err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	idx := -1
	for i, a := range incident.RCA.Remediation {
		if a.Id == actionId {
			idx = i
			break
		}
	}
	if idx < 0 {
		http.Error(w, "RCA remediation action not found", http.StatusNotFound)
		return
	}

	updated, err := applyRCARemediationTransition(incident.RCA.Remediation[idx], form, rcaActor(u), timeseries.Now())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := api.db.SaveRCARemediationActionState(projectId, incidentKey, updated); err != nil {
		klog.Errorln(err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	incident.RCA.Remediation[idx] = updated
	utils.WriteJson(w, incident.RCA.Remediation)
}

func (api *Api) overlayRCARemediationState(projectId db.ProjectId, incident *model.ApplicationIncident) error {
	if incident == nil || incident.RCA == nil || len(incident.RCA.Remediation) == 0 {
		return nil
	}
	states, err := api.db.GetRCARemediationActionStates(projectId, incident.Key)
	if err != nil {
		return err
	}
	db.ApplyRCARemediationActionStates(incident.RCA, states)
	return nil
}

func applyRCARemediationTransition(a model.RCARemediationAction, form rcaRemediationForm, actor string, now timeseries.Time) (model.RCARemediationAction, error) {
	action := strings.TrimSpace(strings.ToLower(form.Action))
	if a.Status == "" {
		a.Status = db.RCARemediationStatusNotStarted
	}
	if actor == "" {
		actor = "unknown"
	}
	a.UpdatedAt = now

	switch action {
	case "approve":
		if !a.RequiresApproval {
			return a, fmt.Errorf("action does not require approval")
		}
		if a.Status != db.RCARemediationStatusWaitingForApproval {
			return a, fmt.Errorf("action is not waiting for approval")
		}
		a.Status = db.RCARemediationStatusApproved
		a.ApprovedBy = actor
		a.ApprovedAt = now
	case "start":
		if a.RequiresApproval && a.Status != db.RCARemediationStatusApproved {
			return a, fmt.Errorf("action requires approval before it can start")
		}
		if a.Status == db.RCARemediationStatusCompleted || a.Status == db.RCARemediationStatusVerified || a.Status == db.RCARemediationStatusVerificationFailed {
			return a, fmt.Errorf("action is already complete")
		}
		a.Status = db.RCARemediationStatusInProgress
		a.StartedBy = actor
		a.StartedAt = now
	case "complete":
		if a.RequiresApproval && a.Status == db.RCARemediationStatusWaitingForApproval {
			return a, fmt.Errorf("action requires approval before it can be completed")
		}
		if a.Status == db.RCARemediationStatusVerified {
			return a, fmt.Errorf("action is already verified")
		}
		a.Status = db.RCARemediationStatusCompleted
		a.CompletedBy = actor
		a.CompletedAt = now
	case "verify_pass":
		if a.Status != db.RCARemediationStatusCompleted && a.Status != db.RCARemediationStatusVerificationFailed {
			return a, fmt.Errorf("action must be completed before verification")
		}
		a.Status = db.RCARemediationStatusVerified
		a.VerificationStatus = "passed"
		a.VerificationNote = trimVerificationNote(form.VerificationNote)
		a.VerifiedBy = actor
		a.VerifiedAt = now
	case "verify_fail":
		if a.Status != db.RCARemediationStatusCompleted && a.Status != db.RCARemediationStatusVerified {
			return a, fmt.Errorf("action must be completed before verification")
		}
		a.Status = db.RCARemediationStatusVerificationFailed
		a.VerificationStatus = "failed"
		a.VerificationNote = trimVerificationNote(form.VerificationNote)
		a.VerifiedBy = actor
		a.VerifiedAt = now
	default:
		return a, fmt.Errorf("unknown remediation action: %s", form.Action)
	}
	return a, nil
}

func trimVerificationNote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 2000 {
		return s[:2000]
	}
	return s
}

func rcaActor(u *db.User) string {
	if u == nil {
		return ""
	}
	if u.Email != "" {
		return u.Email
	}
	if u.Name != "" {
		return u.Name
	}
	if u.Id > 0 {
		return fmt.Sprintf("user:%d", u.Id)
	}
	return ""
}
