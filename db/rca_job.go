package db

import (
	"database/sql"
	"errors"

	"github.com/coroot/coroot/model"
	"github.com/coroot/coroot/timeseries"
)

const (
	RCAJobStatusQueued    = "queued"
	RCAJobStatusRunning   = "running"
	RCAJobStatusSucceeded = "succeeded"
	RCAJobStatusFailed    = "failed"
	RCAJobStatusCancelled = "cancelled"
)

type RCAJob struct {
	ProjectId     ProjectId           `json:"project_id"`
	IncidentKey   string              `json:"incident_key"`
	ApplicationId model.ApplicationId `json:"application_id"`
	Status        string              `json:"status"`
	Reason        string              `json:"reason"`
	Attempts      int                 `json:"attempts"`
	CreatedAt     timeseries.Time     `json:"created_at"`
	UpdatedAt     timeseries.Time     `json:"updated_at"`
	StartedAt     timeseries.Time     `json:"started_at"`
	FinishedAt    timeseries.Time     `json:"finished_at"`
}

func (j *RCAJob) Migrate(m *Migrator) error {
	return m.Exec(`
	CREATE TABLE IF NOT EXISTS rca_job (
		project_id TEXT NOT NULL REFERENCES project(id),
		incident_key TEXT NOT NULL,
		application_id TEXT NOT NULL,
		status TEXT NOT NULL,
		reason TEXT NOT NULL DEFAULT '',
		attempts INT NOT NULL DEFAULT 0,
		created_at INT NOT NULL,
		updated_at INT NOT NULL,
		started_at INT NOT NULL DEFAULT 0,
		finished_at INT NOT NULL DEFAULT 0,
		PRIMARY KEY (project_id, incident_key)
	);
	CREATE INDEX IF NOT EXISTS rca_job_project_status_updated ON rca_job (project_id, status, updated_at);
`)
}

func (db *DB) EnqueueRCAJob(projectId ProjectId, incidentKey string, appId model.ApplicationId, reason string, force bool) (*RCAJob, error) {
	existing, err := db.GetRCAJob(projectId, incidentKey)
	if err == nil {
		if !force && (existing.Status == RCAJobStatusQueued || existing.Status == RCAJobStatusRunning) {
			return existing, nil
		}
		now := timeseries.Now()
		_, err = db.db.Exec(
			"UPDATE rca_job SET application_id = $1, status = $2, reason = $3, updated_at = $4, started_at = 0, finished_at = 0 WHERE project_id = $5 AND incident_key = $6",
			appId, RCAJobStatusQueued, reason, now, projectId, incidentKey)
		if err != nil {
			return nil, err
		}
		return db.GetRCAJob(projectId, incidentKey)
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}

	now := timeseries.Now()
	_, err = db.db.Exec(
		"INSERT INTO rca_job (project_id, incident_key, application_id, status, reason, attempts, created_at, updated_at, started_at, finished_at) VALUES ($1, $2, $3, $4, $5, 0, $6, $6, 0, 0)",
		projectId, incidentKey, appId, RCAJobStatusQueued, reason, now)
	if err != nil {
		if db.IsUniqueViolationError(err) {
			return db.EnqueueRCAJob(projectId, incidentKey, appId, reason, force)
		}
		return nil, err
	}
	return db.GetRCAJob(projectId, incidentKey)
}

func (db *DB) StartRCAJob(projectId ProjectId, incidentKey string) error {
	now := timeseries.Now()
	_, err := db.db.Exec(
		"UPDATE rca_job SET status = $1, attempts = attempts + 1, updated_at = $2, started_at = $2, finished_at = 0 WHERE project_id = $3 AND incident_key = $4",
		RCAJobStatusRunning, now, projectId, incidentKey)
	return err
}

func (db *DB) FinishRCAJob(projectId ProjectId, incidentKey string, status string, reason string) error {
	now := timeseries.Now()
	_, err := db.db.Exec(
		"UPDATE rca_job SET status = $1, reason = $2, updated_at = $3, finished_at = $3 WHERE project_id = $4 AND incident_key = $5",
		status, reason, now, projectId, incidentKey)
	return err
}

func (db *DB) GetRCAJob(projectId ProjectId, incidentKey string) (*RCAJob, error) {
	j := &RCAJob{}
	err := db.db.QueryRow(
		"SELECT project_id, incident_key, application_id, status, reason, attempts, created_at, updated_at, started_at, finished_at FROM rca_job WHERE project_id = $1 AND incident_key = $2",
		projectId, incidentKey).
		Scan(&j.ProjectId, &j.IncidentKey, &j.ApplicationId, &j.Status, &j.Reason, &j.Attempts, &j.CreatedAt, &j.UpdatedAt, &j.StartedAt, &j.FinishedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return j, err
}
