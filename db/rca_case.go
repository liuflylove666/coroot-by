package db

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/coroot/coroot/model"
	"github.com/coroot/coroot/timeseries"
)

type RCACase struct{}

func (c *RCACase) Migrate(m *Migrator) error {
	return m.Exec(`
	CREATE TABLE IF NOT EXISTS rca_case (
		id TEXT PRIMARY KEY,
		project_id TEXT NOT NULL REFERENCES project(id),
		incident_key TEXT NOT NULL,
		application_id TEXT NOT NULL,
		signature_hash TEXT NOT NULL,
		scenario TEXT NOT NULL,
		root_cause_component TEXT NOT NULL,
		evidence_fingerprint TEXT NOT NULL,
		fix_summary TEXT NOT NULL,
		outcome TEXT NOT NULL,
		created_at INT NOT NULL
	);
	CREATE INDEX IF NOT EXISTS rca_case_project_scenario_created ON rca_case (project_id, scenario, created_at);
`)
}

func (db *DB) SaveRCACase(projectId ProjectId, incidentKey string, appId model.ApplicationId, rca *model.RCA) error {
	if rca == nil || rca.Status != "OK" || len(rca.Candidates) == 0 {
		return nil
	}
	top := rca.Candidates[0]
	if top.Scenario == "" || top.Component == "" || top.RootCauseReason == "" {
		return nil
	}
	evidence := strings.Join(top.EvidenceRefs, "|")
	signature := rcaCaseSignature(top.Scenario, top.Component, top.RootCauseReason, evidence)
	id := rcaCaseSignature(string(projectId), incidentKey, signature)
	_, err := db.db.Exec(
		`INSERT INTO rca_case (id, project_id, incident_key, application_id, signature_hash, scenario, root_cause_component, evidence_fingerprint, fix_summary, outcome, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		 ON CONFLICT (id) DO UPDATE SET signature_hash = $5, scenario = $6, root_cause_component = $7, evidence_fingerprint = $8, fix_summary = $9, outcome = $10`,
		id, projectId, incidentKey, appId, signature, top.Scenario, top.Component, evidence, rca.ImmediateFixes, "unknown", timeseries.Now())
	return err
}

func (db *DB) FindSimilarRCACases(projectId ProjectId, rca *model.RCA, limit int) ([]model.RCAHistoricalContext, error) {
	if rca == nil || len(rca.Candidates) == 0 || rca.Candidates[0].Scenario == "" {
		return nil, nil
	}
	if limit <= 0 {
		limit = 3
	}
	top := rca.Candidates[0]
	rows, err := db.db.Query(
		`SELECT incident_key, scenario, root_cause_component, fix_summary, outcome
		 FROM rca_case WHERE project_id = $1 AND scenario = $2
		 ORDER BY created_at DESC LIMIT $3`,
		projectId, top.Scenario, limit)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var res []model.RCAHistoricalContext
	for rows.Next() {
		var c model.RCAHistoricalContext
		if err := rows.Scan(&c.IncidentKey, &c.Scenario, &c.Component, &c.FixSummary, &c.Outcome); err != nil {
			return nil, err
		}
		c.Similarity = 0.75
		if c.Component == top.Component {
			c.Similarity = 0.95
		}
		res = append(res, c)
	}
	return res, rows.Err()
}

func rcaCaseSignature(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:])
}
