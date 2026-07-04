package db

import (
	"database/sql"
	"errors"

	"github.com/coroot/coroot/model"
	"github.com/coroot/coroot/timeseries"
)

const (
	RCARemediationStatusWaitingForApproval = "waiting_for_approval"
	RCARemediationStatusApproved           = "approved"
	RCARemediationStatusRecommended        = "recommended"
	RCARemediationStatusNotStarted         = "not_started"
	RCARemediationStatusInProgress         = "in_progress"
	RCARemediationStatusCompleted          = "completed"
	RCARemediationStatusVerified           = "verified"
	RCARemediationStatusVerificationFailed = "verification_failed"
)

type RCARemediationActionState struct{}

func (s *RCARemediationActionState) Migrate(m *Migrator) error {
	return m.Exec(`
	CREATE TABLE IF NOT EXISTS rca_remediation_action (
		project_id TEXT NOT NULL REFERENCES project(id),
		incident_key TEXT NOT NULL,
		action_id TEXT NOT NULL,
		status TEXT NOT NULL,
		approved_by TEXT NOT NULL DEFAULT '',
		approved_at INT NOT NULL DEFAULT 0,
		started_by TEXT NOT NULL DEFAULT '',
		started_at INT NOT NULL DEFAULT 0,
		completed_by TEXT NOT NULL DEFAULT '',
		completed_at INT NOT NULL DEFAULT 0,
		verification_status TEXT NOT NULL DEFAULT '',
		verification_note TEXT NOT NULL DEFAULT '',
		verified_by TEXT NOT NULL DEFAULT '',
		verified_at INT NOT NULL DEFAULT 0,
		updated_at INT NOT NULL,
		PRIMARY KEY (project_id, incident_key, action_id)
	);
	CREATE INDEX IF NOT EXISTS rca_remediation_project_updated ON rca_remediation_action (project_id, updated_at);
`)
}

func (db *DB) GetRCARemediationActionStates(projectId ProjectId, incidentKey string) (map[string]model.RCARemediationAction, error) {
	rows, err := db.db.Query(
		`SELECT action_id, status, approved_by, approved_at, started_by, started_at, completed_by, completed_at,
		        verification_status, verification_note, verified_by, verified_at, updated_at
		   FROM rca_remediation_action
		  WHERE project_id = $1 AND incident_key = $2`,
		projectId, incidentKey)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	res := map[string]model.RCARemediationAction{}
	for rows.Next() {
		var a model.RCARemediationAction
		if err := rows.Scan(
			&a.Id, &a.Status, &a.ApprovedBy, &a.ApprovedAt, &a.StartedBy, &a.StartedAt, &a.CompletedBy, &a.CompletedAt,
			&a.VerificationStatus, &a.VerificationNote, &a.VerifiedBy, &a.VerifiedAt, &a.UpdatedAt,
		); err != nil {
			return nil, err
		}
		res[a.Id] = a
	}
	return res, rows.Err()
}

func (db *DB) SaveRCARemediationActionState(projectId ProjectId, incidentKey string, a model.RCARemediationAction) error {
	if a.Id == "" {
		return ErrInvalid
	}
	if a.UpdatedAt.IsZero() {
		a.UpdatedAt = timeseries.Now()
	}
	_, err := db.db.Exec(
		`INSERT INTO rca_remediation_action (
			project_id, incident_key, action_id, status, approved_by, approved_at, started_by, started_at,
			completed_by, completed_at, verification_status, verification_note, verified_by, verified_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		ON CONFLICT (project_id, incident_key, action_id) DO UPDATE SET
			status = $4,
			approved_by = $5,
			approved_at = $6,
			started_by = $7,
			started_at = $8,
			completed_by = $9,
			completed_at = $10,
			verification_status = $11,
			verification_note = $12,
			verified_by = $13,
			verified_at = $14,
			updated_at = $15`,
		projectId, incidentKey, a.Id, a.Status, a.ApprovedBy, a.ApprovedAt, a.StartedBy, a.StartedAt,
		a.CompletedBy, a.CompletedAt, a.VerificationStatus, a.VerificationNote, a.VerifiedBy, a.VerifiedAt, a.UpdatedAt)
	return err
}

func ApplyRCARemediationActionStates(rca *model.RCA, states map[string]model.RCARemediationAction) {
	if rca == nil || len(rca.Remediation) == 0 || len(states) == 0 {
		return
	}
	for i := range rca.Remediation {
		state, ok := states[rca.Remediation[i].Id]
		if !ok {
			continue
		}
		if rca.Remediation[i].Status == RCARemediationStatusRecommended {
			continue
		}
		if state.Status != "" {
			rca.Remediation[i].Status = state.Status
		}
		rca.Remediation[i].ApprovedBy = state.ApprovedBy
		rca.Remediation[i].ApprovedAt = state.ApprovedAt
		rca.Remediation[i].StartedBy = state.StartedBy
		rca.Remediation[i].StartedAt = state.StartedAt
		rca.Remediation[i].CompletedBy = state.CompletedBy
		rca.Remediation[i].CompletedAt = state.CompletedAt
		rca.Remediation[i].VerificationStatus = state.VerificationStatus
		rca.Remediation[i].VerificationNote = state.VerificationNote
		rca.Remediation[i].VerifiedBy = state.VerifiedBy
		rca.Remediation[i].VerifiedAt = state.VerifiedAt
		rca.Remediation[i].UpdatedAt = state.UpdatedAt
	}
}
