package api

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coroot/coroot/cache"
	"github.com/coroot/coroot/db"
	"github.com/coroot/coroot/model"
	"github.com/coroot/coroot/timeseries"
	"github.com/coroot/coroot/utils"
	"github.com/gorilla/mux"
	"k8s.io/klog"
)

const (
	defaultRCAWorkers = 1
	rcaJobTimeout     = 5 * time.Minute
	maxRCARetries     = 2
	rcaRetryBaseDelay = 5 * time.Second
)

type RCAQueue struct {
	api    *Api
	queue  chan *queuedRCAJob
	mu     sync.Mutex
	active map[string]struct{}
}

type queuedRCAJob struct {
	project  *db.Project
	world    *model.World
	incident *model.ApplicationIncident
	force    bool
}

func newRCAQueue(api *Api) *RCAQueue {
	workers := defaultRCAWorkers
	if v := os.Getenv("AI_RCA_WORKERS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			workers = n
		}
	}
	if workers > 8 {
		workers = 8
	}
	q := &RCAQueue{
		api:    api,
		queue:  make(chan *queuedRCAJob, 100),
		active: map[string]struct{}{},
	}
	for i := 0; i < workers; i++ {
		go q.worker(i + 1)
	}
	return q
}

func (api *Api) EnqueueIncidentRCA(ctx context.Context, project *db.Project, world *model.World, incident *model.ApplicationIncident) {
	if api.rcaQueue == nil {
		go api.IncidentRCA(ctx, project, world, incident)
		return
	}
	if _, err := api.rcaQueue.Enqueue(ctx, project, world, incident, "auto", false); err != nil {
		klog.Warningln("failed to enqueue RCA job:", err)
	}
}

func (q *RCAQueue) Enqueue(ctx context.Context, project *db.Project, world *model.World, incident *model.ApplicationIncident, reason string, force bool) (*db.RCAJob, error) {
	if project == nil || world == nil || incident == nil {
		return nil, fmt.Errorf("invalid RCA job context")
	}
	if !force && incident.RCA != nil && incident.RCA.Status == "OK" {
		job, err := q.api.db.GetRCAJob(project.Id, incident.Key)
		if err == db.ErrNotFound {
			return nil, nil
		}
		return job, err
	}

	job, err := q.api.db.EnqueueRCAJob(project.Id, incident.Key, incident.ApplicationId, reason, force)
	if err != nil {
		return nil, err
	}

	key := rcaQueueKey(project.Id, incident.Key)
	q.mu.Lock()
	if _, ok := q.active[key]; ok {
		q.mu.Unlock()
		return job, nil
	}
	q.active[key] = struct{}{}
	q.mu.Unlock()

	if force || incident.RCA == nil || incident.RCA.Status == "" || incident.RCA.Status == "Failed" || incident.RCA.Status == "AI disabled" {
		if err := q.api.db.UpdateIncidentRCA(project.Id, incident, &model.RCA{Status: "In progress"}); err != nil {
			klog.Warningln("failed to mark incident RCA as in progress:", err)
		}
	}

	select {
	case q.queue <- &queuedRCAJob{project: project, world: world, incident: incident, force: force}:
		return job, nil
	case <-ctx.Done():
		q.release(project.Id, incident.Key)
		_ = q.api.db.FinishRCAJob(project.Id, incident.Key, db.RCAJobStatusFailed, ctx.Err().Error())
		return nil, ctx.Err()
	default:
		q.release(project.Id, incident.Key)
		_ = q.api.db.FinishRCAJob(project.Id, incident.Key, db.RCAJobStatusFailed, "RCA queue is full")
		return nil, fmt.Errorf("RCA queue is full")
	}
}

func (q *RCAQueue) worker(n int) {
	for job := range q.queue {
		q.run(n, job)
	}
}

func (q *RCAQueue) run(worker int, job *queuedRCAJob) {
	key := rcaQueueKey(job.project.Id, job.incident.Key)
	defer q.release(job.project.Id, job.incident.Key)

	status, reason := db.RCAJobStatusFailed, ""
	for attempt := 0; attempt <= maxRCARetries; attempt++ {
		klog.Infof("rca worker %d started job %s attempt %d", worker, key, attempt+1)
		if err := q.api.db.StartRCAJob(job.project.Id, job.incident.Key); err != nil {
			klog.Warningln("failed to start RCA job:", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), rcaJobTimeout)
		q.api.IncidentRCA(ctx, job.project, job.world, job.incident)
		status, reason = rcaJobResult(ctx, job.incident)
		cancel()

		if status != db.RCAJobStatusFailed || attempt == maxRCARetries || !retryableRCAFailure(reason) {
			break
		}
		delay := rcaRetryBaseDelay << attempt
		klog.Warningf("rca job %s failed attempt %d/%d: %s; retrying in %s", key, attempt+1, maxRCARetries+1, reason, delay)
		time.Sleep(delay)
	}
	if err := q.api.db.FinishRCAJob(job.project.Id, job.incident.Key, status, reason); err != nil {
		klog.Warningln("failed to finish RCA job:", err)
	}
	klog.Infof("rca worker %d finished job %s: %s", worker, key, status)
}

func rcaJobResult(ctx context.Context, incident *model.ApplicationIncident) (string, string) {
	if ctx.Err() != nil {
		return db.RCAJobStatusFailed, ctx.Err().Error()
	}
	if incident.RCA == nil {
		return db.RCAJobStatusFailed, "RCA did not produce a result"
	}
	switch incident.RCA.Status {
	case "OK":
		return db.RCAJobStatusSucceeded, ""
	case "AI disabled":
		return db.RCAJobStatusCancelled, "AI incident auto RCA is disabled"
	case "Failed":
		return db.RCAJobStatusFailed, incident.RCA.Error
	default:
		return db.RCAJobStatusSucceeded, incident.RCA.Status
	}
}

func retryableRCAFailure(reason string) bool {
	reason = strings.ToLower(reason)
	if reason == "" {
		return true
	}
	fatal := []string{
		"application not found",
		"not supported",
		"metric cache is empty",
		"ai disabled",
	}
	for _, f := range fatal {
		if strings.Contains(reason, f) {
			return false
		}
	}
	return true
}

func (q *RCAQueue) release(projectId db.ProjectId, incidentKey string) {
	q.mu.Lock()
	delete(q.active, rcaQueueKey(projectId, incidentKey))
	q.mu.Unlock()
}

func rcaQueueKey(projectId db.ProjectId, incidentKey string) string {
	return string(projectId) + "/" + incidentKey
}

func (api *Api) IncidentRCATask(w http.ResponseWriter, r *http.Request, u *db.User) {
	projectId := db.ProjectId(mux.Vars(r)["project"])
	incidentKey := mux.Vars(r)["incident"]

	project, err := api.db.GetProject(projectId)
	if err != nil {
		klog.Errorln(err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	incident, err := api.db.GetIncidentByKey(projectId, incidentKey)
	if err != nil {
		klog.Warningln("incident not found:", err)
		http.Error(w, "incident not found", http.StatusNotFound)
		return
	}

	switch r.Method {
	case http.MethodGet:
		job, err := api.db.GetRCAJob(projectId, incidentKey)
		if err != nil {
			if err == db.ErrNotFound {
				http.Error(w, "RCA job not found", http.StatusNotFound)
				return
			}
			klog.Errorln(err)
			http.Error(w, "", http.StatusInternalServerError)
			return
		}
		utils.WriteJson(w, job)
	case http.MethodPost:
		world, _, err := api.loadIncidentWorld(r.Context(), project, incident)
		if err != nil {
			klog.Errorln(err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if world == nil {
			http.Error(w, "Metric cache is empty", http.StatusServiceUnavailable)
			return
		}
		job, err := api.rcaQueue.Enqueue(r.Context(), project, world, incident, "manual", true)
		if err != nil {
			klog.Errorln(err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		utils.WriteJson(w, job)
	default:
		http.Error(w, "", http.StatusMethodNotAllowed)
	}
}

func (api *Api) loadIncidentWorld(ctx context.Context, project *db.Project, incident *model.ApplicationIncident) (*model.World, *cache.Status, error) {
	from, to := api.IncidentTimeContext(project.Id, incident, timeseries.Now())
	return api.LoadWorld(ctx, project, from, to)
}
