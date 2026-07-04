package api

import (
	"context"
	"net/http"

	aiintegration "github.com/coroot/coroot/ai"
	"github.com/coroot/coroot/clickhouse"
	"github.com/coroot/coroot/cloud"
	"github.com/coroot/coroot/constructor"
	"github.com/coroot/coroot/db"
	"github.com/coroot/coroot/model"
	localrca "github.com/coroot/coroot/rca"
	"github.com/coroot/coroot/timeseries"
	"github.com/coroot/coroot/utils"
	"github.com/gorilla/mux"
	"k8s.io/klog"
)

func (api *Api) RCA(w http.ResponseWriter, r *http.Request, u *db.User) {
	rca := &model.RCA{}
	projectId := db.ProjectId(mux.Vars(r)["project"])
	q := r.URL.Query()
	from, to, incident, _ := api.getTimeContext(projectId, q.Get("from"), q.Get("to"), q.Get("incident"), q.Get("alert"))

	defer func() {
		if incident != nil {
			if err := api.db.UpdateIncidentRCA(projectId, incident, rca); err != nil {
				klog.Errorln(err)
			}
			api.saveRCACase(projectId, incident, rca)
		} else {
			utils.WriteJson(w, rca)
		}
	}()

	project, err := api.db.GetProject(projectId)
	if err != nil {
		klog.Errorln(err)
		rca.Status = "Failed"
		rca.Error = err.Error()
		return
	}

	if project.Multicluster() {
		klog.Errorln("RCA is not supported for multi-cluster projects")
		rca.Status = "Failed"
		rca.Error = "RCA is not supported for multi-cluster projects"
		return
	}

	appId, err := GetApplicationId(r)
	if err != nil {
		klog.Errorln(err)
		rca.Status = "Failed"
		rca.Error = err.Error()
		return
	}
	cacheClient := api.cache.GetCacheClient(project.Id)
	cacheTo, err := cacheClient.GetTo()
	if err != nil {
		klog.Errorln(err)
		rca.Status = "Failed"
		rca.Error = err.Error()
		return
	}
	if cacheTo.IsZero() || cacheTo.Before(from) {
		rca.Status = "Failed"
		rca.Error = "Metric cache is empty"
		return
	}
	cacheStep, err := cacheClient.GetStep(from, to)
	if err != nil {
		klog.Errorln(err)
		rca.Status = "Failed"
		rca.Error = err.Error()
		return
	}
	if cacheStep == 0 {
		rca.Status = "Failed"
		rca.Error = "Metric cache is empty"
		return
	}
	if cacheTo.Before(to) {
		to = cacheTo
	}
	step := increaseStepForBigDurations(from, to, cacheStep)

	rcaRequest := cloud.RCARequest{
		Ctx:                         timeseries.NewContext(from, to, step),
		ApplicationId:               appId,
		ApplicationCategorySettings: project.Settings.ApplicationCategorySettings,
		CustomApplications:          project.Settings.CustomApplications,
		CustomCloudPricing:          project.Settings.CustomCloudPricing,
	}
	rcaRequest.Ctx.RawStep = cacheStep
	if incident != nil {
		rcaRequest.Ctx.From, rcaRequest.Ctx.To = api.IncidentTimeContext(projectId, incident, to)
	}

	if rcaRequest.CheckConfigs, err = api.db.GetCheckConfigs(project.Id); err != nil {
		klog.Errorln(err)
		rca.Status = "Failed"
		rca.Error = err.Error()
		return
	}
	if rcaRequest.ApplicationDeployments, err = api.db.GetApplicationDeployments(project.Id); err != nil {
		klog.Errorln(err)
		rca.Status = "Failed"
		rca.Error = err.Error()
		return
	}

	ctr := constructor.New(api.db, project, map[db.ProjectId]constructor.Cache{project.Id: cacheClient}, api.pricing)
	if rcaRequest.Metrics, err = ctr.QueryCache(r.Context(), cacheClient, project, rcaRequest.Ctx.From, rcaRequest.Ctx.To, rcaRequest.Ctx.Step); err != nil {
		klog.Errorln(err)
		rca.Status = "Failed"
		rca.Error = err.Error()
		return
	}

	world, _, _, err := api.LoadWorldByRequest(r)
	if err != nil {
		klog.Errorln(err)
		rca.Status = "Failed"
		rca.Error = err.Error()
		return
	}

	var ch *clickhouse.Client
	if ch, err = api.GetClickhouseClient(project, ""); err != nil {
		klog.Errorln(err)
	}
	if ch != nil {
		defer ch.Close()
		rcaRequest.KubernetesEvents, err = ch.GetKubernetesEvents(r.Context(), from, to, 1000)
		if err != nil {
			klog.Errorln(err)
		}

		app := world.GetApplication(appId)
		if app != nil {
			rcaRequest.ErrorTrace, rcaRequest.SlowTrace, err = ch.GetTracesViolatingSLOs(r.Context(), rcaRequest.Ctx.From, rcaRequest.Ctx.To, world, app)
			if err != nil {
				klog.Errorln(err)
			}
		}
	}

	cloudAPI := cloud.API(api.db, api.deploymentUuid, api.instanceUuid, r.Referer())
	if status, statusErr := cloudAPI.RCAStatus(r.Context(), false); status == "OK" {
		rcaResponse, err := cloudAPI.RCA(r.Context(), rcaRequest)
		if err != nil {
			klog.Errorln(err)
			rca.Status = "Failed"
			rca.Error = err.Error()
			return
		}
		rca = rcaResponse
		rca.Status = "OK"
		return
	} else if statusErr != nil {
		klog.Warningln("Cloud RCA is unavailable, using built-in RCA:", statusErr)
	}
	rca = api.localRCAWithAI(r.Context(), project.Id, rcaRequest, world, incident, false)
}

func (api *Api) IncidentRCA(ctx context.Context, project *db.Project, world *model.World, incident *model.ApplicationIncident) {
	rca := incident.RCA
	if rca != nil && rca.Status == "OK" {
		return
	}
	aiSettings := aiintegration.DefaultSettings()
	if s, err := aiintegration.LoadSettings(api.db); err != nil {
		klog.Errorln(err)
	} else {
		aiSettings = s
	}
	if rca == nil {
		rca = &model.RCA{}
	}
	defer func() {
		if err := api.db.UpdateIncidentRCA(project.Id, incident, rca); err != nil {
			klog.Errorln(err)
		}
		api.saveRCACase(project.Id, incident, rca)
	}()

	if incident.RCA == nil {
		if err := api.db.UpdateIncidentRCA(project.Id, incident, &model.RCA{Status: "In progress"}); err != nil {
			klog.Errorln(err)
			return
		}
	}

	if project.Multicluster() {
		klog.Errorln("RCA is not supported for mult-cluster projects")
		rca.Status = "Failed"
		rca.Error = "RCA is not supported for mult-cluster projects"
		return
	}

	app := world.GetApplication(incident.ApplicationId)
	if app == nil {
		klog.Errorln("application not found")
		rca.Status = "Failed"
		rca.Error = "application not found"
		return
	}

	var err error
	rcaRequest := cloud.RCARequest{
		Ctx:                         world.Ctx,
		ApplicationId:               app.Id,
		CheckConfigs:                world.CheckConfigs,
		ApplicationCategorySettings: project.Settings.ApplicationCategorySettings,
		CustomApplications:          project.Settings.CustomApplications,
		CustomCloudPricing:          project.Settings.CustomCloudPricing,
	}
	rcaRequest.Ctx.From, rcaRequest.Ctx.To = api.IncidentTimeContext(project.Id, incident, world.Ctx.To)

	if rcaRequest.ApplicationDeployments, err = api.db.GetApplicationDeployments(project.Id); err != nil {
		klog.Errorln(err)
		rca.Status = "Failed"
		rca.Error = err.Error()
		return
	}

	cacheClient := api.cache.GetCacheClient(project.Id)
	ctr := constructor.New(api.db, project, map[db.ProjectId]constructor.Cache{project.Id: cacheClient}, api.pricing)
	if rcaRequest.Metrics, err = ctr.QueryCache(ctx, cacheClient, project, rcaRequest.Ctx.From, rcaRequest.Ctx.To, rcaRequest.Ctx.Step); err != nil {
		klog.Errorln(err)
		rca.Status = "Failed"
		rca.Error = err.Error()
		return
	}

	var ch *clickhouse.Client
	if ch, err = api.GetClickhouseClient(project, ""); err != nil {
		klog.Errorln(err)
	}
	if ch != nil {
		defer ch.Close()
		rcaRequest.KubernetesEvents, err = ch.GetKubernetesEvents(ctx, rcaRequest.Ctx.From, rcaRequest.Ctx.To, 1000)
		if err != nil {
			klog.Errorln(err)
		}
		rcaRequest.ErrorTrace, rcaRequest.SlowTrace, err = ch.GetTracesViolatingSLOs(ctx, rcaRequest.Ctx.From, rcaRequest.Ctx.To, world, app)
		if err != nil {
			klog.Errorln(err)
		}
	}

	cloudAPI := cloud.API(api.db, api.deploymentUuid, api.instanceUuid, "")
	if status, statusErr := cloudAPI.RCAStatus(ctx, true); status == "OK" {
		rcaResponse, err := cloudAPI.RCA(ctx, rcaRequest)
		if err != nil {
			klog.Errorln(err)
			rca.Status = "Failed"
			rca.Error = err.Error()
			return
		}
		rca = rcaResponse
		rca.Status = "OK"
		return
	} else if statusErr != nil {
		klog.Warningln("Cloud RCA is unavailable, using built-in RCA:", statusErr)
	}
	if !aiSettings.IncidentsAutoRCA {
		rca.Status = "AI disabled"
		return
	}
	rca = api.localRCAWithAI(ctx, project.Id, rcaRequest, world, incident, true)
}

func (api *Api) localRCAWithAI(ctx context.Context, projectId db.ProjectId, req cloud.RCARequest, world *model.World, incident *model.ApplicationIncident, auto bool) *model.RCA {
	res := localrca.BuiltIn(req, world, incident)
	if cases, err := api.db.FindSimilarRCACases(projectId, res, 3); err != nil {
		klog.Warningln("failed to load historical RCA cases:", err)
	} else {
		res.HistoricalContext = cases
	}
	settings, err := aiintegration.LoadSettings(api.db)
	if err != nil {
		klog.Errorln(err)
		return res
	}
	if auto && !settings.IncidentsAutoRCA {
		return res
	}
	if !settings.Enabled() {
		return res
	}
	enhanced, err := localrca.EnhanceWithAI(ctx, res, settings)
	if err != nil {
		klog.Warningln("AI RCA rendering failed, keeping built-in RCA:", err)
		res.Error = "AI RCA failed: " + err.Error()
		return res
	}
	localrca.PostProcess(enhanced)
	return enhanced
}

func (api *Api) saveRCACase(projectId db.ProjectId, incident *model.ApplicationIncident, rca *model.RCA) {
	if incident == nil || rca == nil || rca.Status != "OK" {
		return
	}
	if err := api.db.SaveRCACase(projectId, incident.Key, incident.ApplicationId, rca); err != nil {
		klog.Warningln("failed to save RCA case:", err)
	}
}

func (api *Api) IncidentTimeContext(projectId db.ProjectId, incident *model.ApplicationIncident, now timeseries.Time) (timeseries.Time, timeseries.Time) {
	from := incident.OpenedAt.Add(-model.IncidentTimeOffset)
	to := now
	if incident.Resolved() {
		to = incident.ResolvedAt
	}
	incidents, err := api.db.GetApplicationIncidents(projectId, from, incident.OpenedAt)
	if err != nil {
		klog.Errorln(err)
		return from, to
	}
	for _, i := range incidents[incident.ApplicationId] {
		if i.Key == incident.Key || !i.Resolved() {
			continue
		}
		if i.ResolvedAt.After(from) && i.ResolvedAt.Before(to) {
			from = i.ResolvedAt
		}
	}
	return from, to
}
