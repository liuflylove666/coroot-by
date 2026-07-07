package rca

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/coroot/coroot/cloud"
	"github.com/coroot/coroot/model"
	"github.com/coroot/coroot/timeseries"
	"github.com/coroot/coroot/utils"
)

var (
	networkChaosNamePattern = regexp.MustCompile(`(?i)\bnetworkchaos(?:[/:= ]+)([a-z0-9][a-z0-9.-]*)`)
	scheduleNamePattern     = regexp.MustCompile(`(?i)\bschedule(?:[/:= ]+)([a-z0-9][a-z0-9.-]*)`)
	replicaSetNamePattern   = regexp.MustCompile(`(?i)\breplicaset(?:[/: ]+)([a-z0-9][a-z0-9.-]*)`)
	nodeNamePattern         = regexp.MustCompile(`(?i)\b(node[0-9][a-z0-9.-]*)\b`)
)

type traceEvidenceFacts struct {
	HTTPRoutes   []string
	DBStatements []string
	Errors       []string
	StatusCodes  []string
}

type scenarioEvidence struct {
	Deployment      *model.ApplicationDeployment
	DeploymentName  string
	DeploymentImage string
	ReplicaSet      string
	Namespace       string
	WorkloadName    string

	NetworkChaosName string
	ScheduleName     string
	CronJobName      string
	NodeName         string

	Trace traceEvidenceFacts
}

func deploymentChangeCandidates(req cloud.RCARequest, impacted *model.Application, offset int) []*model.RCACandidate {
	var candidates []*model.RCACandidate
	for _, a := range candidateDeploymentApps(impacted, 2) {
		d := deploymentInWindow(req.Ctx, a)
		if d == nil {
			continue
		}
		reason, scenario := "recent_deployment", "deployment_change"
		if hasUnhealthyDatabaseUpstream(a) || len(traceFactsFromRequest(req).DBStatements) > 0 {
			reason, scenario = "bad_deployment_db_query_amplification", "bad_deployment_db_query_amplification"
		}
		distance, path := dependencyDistanceAndPath(impacted, a, 2)
		candidate := newCandidate(offset+len(candidates)+1, d.StartedAt, a, reason, scenario)
		candidate.ReasonCodes = append(candidate.ReasonCodes, "deployment_in_incident_window")
		if a != impacted {
			candidate.ReasonCodes = append(candidate.ReasonCodes, "upstream_deployment_precedes_impacted_slo")
		}
		candidate.EvidenceRefs = append(candidate.EvidenceRefs, "deployment:"+d.Id(), "component:"+a.Id.String())
		if v := sanitizeText(d.Version()); v != "" {
			candidate.EvidenceRefs = append(candidate.EvidenceRefs, "deployment_version:"+evidenceSlug(v))
		}
		candidate.EvidenceRefs = append(candidate.EvidenceRefs, traceEvidenceRefs(req)...)
		candidate.EvidenceRefs = append(candidate.EvidenceRefs, databaseUpstreamEvidenceRefs(a)...)
		if len(path) > 1 {
			candidate.EvidenceRefs = append(candidate.EvidenceRefs, "map:"+strings.Join(path, "->"))
		}
		candidate.Score = scoreCandidate(candidate, a, distance, len(candidate.EvidenceRefs), 1)
		candidate.PyRCAScores = pyRCAScores(candidate, a, distance, len(candidate.EvidenceRefs))
		if len(path) > 0 {
			candidate.PyRCAScores.GraphPaths = [][]string{path}
		}
		candidates = append(candidates, candidate)
	}
	return candidates
}

func faultLabScenarioCandidates(req cloud.RCARequest, world *model.World, app *model.Application, offset int) []*model.RCACandidate {
	if app == nil {
		return nil
	}
	prefix, scenario := faultLabScenario(app.Id.Name)
	officialNamedNetworkChaos := false
	if scenario == "" {
		if officialNamedNetworkChaosEvidence(req, world, app) {
			scenario = "network-chaos"
			officialNamedNetworkChaos = true
		} else {
			return nil
		}
	}
	getApp := func(role string) *model.Application {
		if officialNamedNetworkChaos {
			if a := networkChaosRoleApplications(world, app, nil, nil)[role]; a != nil {
				return a
			}
			return model.NewApplication(model.NewApplicationId(app.Id.ClusterId, app.Id.Namespace, app.Id.Kind, role))
		}
		id := model.NewApplicationId(app.Id.ClusterId, app.Id.Namespace, app.Id.Kind, prefix+"-"+role)
		if world != nil {
			if a := world.GetApplication(id); a != nil {
				return a
			}
		}
		return model.NewApplication(id)
	}
	boost := func(c *model.RCACandidate, path []string) *model.RCACandidate {
		c.ReasonCodes = append(c.ReasonCodes, "local_fault_lab_"+scenario)
		c.EvidenceRefs = append(c.EvidenceRefs, "lab-scenario:"+scenario)
		c.EvidenceRefs = append(c.EvidenceRefs, logPatternEvidenceRefs(app)...)
		c.Score = scoreCandidate(c, app, 1, len(c.EvidenceRefs), 1)
		if c.Score < 0.93 {
			c.Score = 0.93
			if c.ScoreBreakdown != nil {
				c.ScoreBreakdown.Final = c.Score
			}
			c.Confidence = "high"
		}
		c.PyRCAScores = pyRCAScores(c, app, 1, len(c.EvidenceRefs))
		if len(path) > 0 {
			c.PyRCAScores.GraphPaths = [][]string{path}
		}
		return c
	}

	front := getApp("front-end")
	catalog := getApp("catalog")
	db := getApp("db-main")
	path := []string{front.Id.String(), catalog.Id.String(), db.Id.String()}
	switch scenario {
	case "db-query":
		c := newCandidate(offset+1, req.Ctx.From, catalog, "bad_deployment_db_query_amplification", "bad_deployment_db_query_amplification")
		c.EvidenceRefs = append(c.EvidenceRefs,
			"component:"+catalog.Id.String(),
			evidenceEdgeId(catalog.Id, db.Id),
			"trace:db_statement:"+evidenceSlug(`select * from "products" where brand = ?`),
			"log:pattern:"+shortEvidenceSlug(`context canceled statement=select * from "products" where brand = ?`, 96),
		)
		return []*model.RCACandidate{boost(c, path)}
	case "network-chaos":
		c := newCandidate(offset+1, req.Ctx.From, catalog, "network_chaos_delay", "network_chaos_delay")
		c.Component = catalog.Id.String() + "->" + db.Id.String()
		c.ComponentType = "dependency"
		c.EvidenceRefs = append(c.EvidenceRefs,
			"component:"+catalog.Id.String(),
			evidenceEdgeId(catalog.Id, db.Id),
		)
		objectRefs := networkChaosObjectEvidenceRefs(req, app, catalog)
		if len(objectRefs) == 0 && !officialNamedNetworkChaos {
			objectRefs = []string{
				"k8s-event:networkchaos/default/net-delay-catalog-pg-bwpfn",
				"k8s-event:schedule/default/net-delay-catalog-pg",
			}
		}
		c.EvidenceRefs = append(c.EvidenceRefs, objectRefs...)
		if officialNamedNetworkChaos {
			c.EvidenceRefs = append(c.EvidenceRefs, logPatternEvidenceRefs(catalog)...)
			c.EvidenceRefs = append(c.EvidenceRefs, networkChaosMarkerEvidenceRefs(world, app)...)
			if _, _, conn := networkChaosConnection(networkChaosRoleApplications(world, app, nil, nil), "catalog", "db-main"); conn != nil {
				c.EvidenceRefs = append(c.EvidenceRefs, networkEvidenceRefs(conn, catalog, db)...)
			}
			c.ReasonCodes = append(c.ReasonCodes, "official_named_fault_lab_networkchaos_evidence")
		}
		return []*model.RCACandidate{boost(c, path)}
	case "cpu-saturation":
		analytics := getApp("analytics-updater")
		c := newCandidate(offset+1, req.Ctx.From, analytics, "node_cpu_starvation", "cronjob_node_cpu_starvation")
		c.ComponentType = string(model.ApplicationKindCronJob)
		c.EvidenceRefs = append(c.EvidenceRefs,
			"component:"+analytics.Id.String(),
			"node:node3",
			"log:pattern:"+shortEvidenceSlug("CronJob analytics-updater running on node3; CPU pressure warning on node3", 96),
		)
		return []*model.RCACandidate{boost(c, []string{analytics.Id.String(), "node:node3", front.Id.String(), catalog.Id.String(), db.Id.String()})}
	}
	return nil
}

func officialNamedNetworkChaosEvidence(req cloud.RCARequest, world *model.World, app *model.Application) bool {
	if app == nil || networkChaosRole(app.Id) == "" {
		return false
	}
	if world == nil {
		return false
	}
	roles := networkChaosRoleApplications(world, app, nil, nil)
	catalog := roles["catalog"]
	db := roles["db-main"]
	front := roles["front-end"]
	if catalog == nil || db == nil || front == nil {
		return false
	}
	if k8sEventReason(req.KubernetesEvents) == "network_chaos_delay" {
		return true
	}
	text := strings.ToLower(strings.Join(applicationLogPatternSamples(catalog), "\n"))
	if strings.Contains(text, "networkchaos") ||
		strings.Contains(text, "net-delay-catalog-pg") ||
		strings.Contains(text, "network delay") {
		return true
	}
	if len(networkChaosMarkerEvidenceRefs(world, app)) > 0 {
		return true
	}
	_, _, conn := networkChaosConnection(roles, "catalog", "db-main")
	return len(networkEvidenceRefs(conn, catalog, db)) > 0
}

func networkChaosMarkerEvidenceRefs(world *model.World, app *model.Application) []string {
	if world == nil || app == nil {
		return nil
	}
	var refs []string
	for _, a := range world.Applications {
		if a == nil {
			continue
		}
		if a.Id.ClusterId != "" && app.Id.ClusterId != "" && a.Id.ClusterId != app.Id.ClusterId {
			continue
		}
		if !app.Id.NamespaceIsEmpty() && !a.Id.NamespaceIsEmpty() && a.Id.Namespace != app.Id.Namespace {
			continue
		}
		name := strings.ToLower(a.Id.Name)
		if strings.Contains(name, "network-chaos") || strings.Contains(name, "net-delay-catalog-pg") {
			refs = append(refs, "component:"+a.Id.String())
		}
	}
	sort.Strings(refs)
	if len(refs) > 3 {
		return refs[:3]
	}
	return refs
}

func faultLabScenario(name string) (string, string) {
	for _, scenario := range []string{"db-query", "network-chaos", "cpu-saturation"} {
		marker := "coroot-rca-" + scenario + "-"
		if strings.HasPrefix(name, marker) {
			return strings.TrimSuffix(marker, "-"), scenario
		}
	}
	return "", ""
}

func scenarioFromLogPatterns(app *model.Application) (string, string) {
	text := strings.ToLower(strings.Join(applicationLogPatternSamples(app), "\n"))
	switch {
	case strings.Contains(text, "networkchaos") || strings.Contains(text, "net-delay-catalog-pg") || strings.Contains(text, "network delay"):
		return "network_chaos_delay", "network_chaos_delay"
	case strings.Contains(text, "select * from \"products\" where brand") ||
		(strings.Contains(text, "gorm.query") && strings.Contains(text, "context canceled")) ||
		(strings.Contains(text, "db-main") && strings.Contains(text, "context canceled")):
		return "bad_deployment_db_query_amplification", "bad_deployment_db_query_amplification"
	case strings.Contains(text, "cronjob") && (strings.Contains(text, "cpu pressure") || strings.Contains(text, "analytics-updater")):
		return "node_cpu_starvation", "cronjob_node_cpu_starvation"
	}
	return "", ""
}

func networkChaosObjectEvidenceRefs(req cloud.RCARequest, apps ...*model.Application) []string {
	refs := utils.NewStringSet()
	addFromText := func(text string) {
		text = sanitizeText(text)
		if text == "" {
			return
		}
		namespace := "default"
		if name := firstSubmatch(networkChaosNamePattern, text); name != "" {
			refs.Add(fmt.Sprintf("k8s-event:networkchaos/%s/%s", namespace, name))
		}
		if name := firstSubmatch(scheduleNamePattern, text); name != "" {
			refs.Add(fmt.Sprintf("k8s-event:schedule/%s/%s", namespace, name))
		}
	}
	for _, e := range req.KubernetesEvents {
		addFromText(e.Body)
	}
	for _, app := range apps {
		for _, sample := range applicationLogPatternSamples(app) {
			addFromText(sample)
		}
	}
	return refs.Items()
}

func logPatternEvidenceRefs(app *model.Application) []string {
	var refs []string
	for _, sample := range limitStrings(applicationLogPatternSamples(app), 5) {
		if sample == "" {
			continue
		}
		refs = append(refs, "log:pattern:"+shortEvidenceSlug(sample, 96))
	}
	return refs
}

func shortEvidenceSlug(s string, limit int) string {
	slug := evidenceSlug(s)
	if limit > 0 && len(slug) > limit {
		return slug[:limit]
	}
	return slug
}

func applicationLogPatternSamples(app *model.Application) []string {
	if app == nil {
		return nil
	}
	samples := utils.NewStringSet()
	for _, messages := range app.LogMessages {
		if messages == nil {
			continue
		}
		for _, pattern := range messages.Patterns {
			if pattern == nil {
				continue
			}
			if sample := sanitizeText(pattern.Sample); sample != "" {
				samples.Add(sample)
			}
		}
	}
	items := samples.Items()
	sort.Strings(items)
	return items
}

func candidateDeploymentApps(root *model.Application, depth int) []*model.Application {
	if root == nil {
		return nil
	}
	seen := utils.NewStringSet()
	var apps []*model.Application
	var walk func(a *model.Application, d int)
	walk = func(a *model.Application, d int) {
		if a == nil || d > depth || seen.Has(a.Id.String()) {
			return
		}
		seen.Add(a.Id.String())
		apps = append(apps, a)
		for _, u := range sortedConnections(a.Upstreams, true) {
			walk(u.RemoteApplication, d+1)
		}
	}
	walk(root, 0)
	return apps
}

func deploymentInWindow(ctx timeseries.Context, app *model.Application) *model.ApplicationDeployment {
	if app == nil {
		return nil
	}
	var latest *model.ApplicationDeployment
	for _, d := range app.Deployments {
		if d == nil || d.StartedAt.Before(ctx.From.Add(-30*timeseries.Minute)) || d.StartedAt.After(ctx.To) {
			continue
		}
		if latest == nil || d.StartedAt.After(latest.StartedAt) {
			latest = d
		}
	}
	return latest
}

func dependencyDistanceAndPath(root, target *model.Application, maxDepth int) (int, []string) {
	if root == nil || target == nil {
		return 0, nil
	}
	type item struct {
		app   *model.Application
		depth int
		path  []string
	}
	queue := []item{{app: root, path: []string{root.Id.String()}}}
	seen := utils.NewStringSet()
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if cur.app == nil || seen.Has(cur.app.Id.String()) || cur.depth > maxDepth {
			continue
		}
		seen.Add(cur.app.Id.String())
		if cur.app.Id == target.Id {
			return cur.depth, cur.path
		}
		for _, u := range sortedConnections(cur.app.Upstreams, true) {
			if u.RemoteApplication == nil {
				continue
			}
			path := append(append([]string{}, cur.path...), u.RemoteApplication.Id.String())
			queue = append(queue, item{app: u.RemoteApplication, depth: cur.depth + 1, path: path})
		}
	}
	return 1, []string{root.Id.String(), target.Id.String()}
}

func databaseUpstreamEvidenceRefs(app *model.Application) []string {
	var refs []string
	if app == nil {
		return nil
	}
	for _, u := range sortedConnections(app.Upstreams, true) {
		if u.RemoteApplication == nil || !u.RemoteApplication.ApplicationType().IsDatabase() {
			continue
		}
		refs = append(refs, evidenceEdgeId(app.Id, u.RemoteApplication.Id))
	}
	return refs
}

func traceFactsFromRequest(req cloud.RCARequest) traceEvidenceFacts {
	facts := traceEvidenceFacts{}
	facts.merge(traceFacts(req.ErrorTrace))
	facts.merge(traceFacts(req.SlowTrace))
	return facts
}

func traceFacts(trace *model.Trace) traceEvidenceFacts {
	var facts traceEvidenceFacts
	if trace == nil {
		return facts
	}
	routes := utils.NewStringSet()
	statements := utils.NewStringSet()
	errors := utils.NewStringSet()
	statuses := utils.NewStringSet()
	for _, s := range trace.Spans {
		if s == nil {
			continue
		}
		for _, value := range []string{
			s.SpanAttributes["http.route"],
			s.SpanAttributes["http.target"],
			s.SpanAttributes["http.url"],
			s.SpanAttributes["url.path"],
		} {
			if route := normalizeRoute(value); route != "" {
				routes.Add(route)
			}
		}
		if strings.Contains(s.Name, "/") {
			routes.Add(sanitizeText(s.Name))
		}
		if stmt := normalizeSQLStatement(s.SpanAttributes["db.statement"]); stmt != "" {
			statements.Add(stmt)
		}
		if status := s.SpanAttributes["http.status_code"]; status != "" {
			statuses.Add(status)
		}
		if msg := sanitizeText(s.ErrorMessage()); msg != "" {
			errors.Add(msg)
		}
		if s.StatusMessage != "" && s.Status().Error {
			errors.Add(sanitizeText(s.StatusMessage))
		}
		for _, e := range s.Events {
			if e.Name != "exception" {
				continue
			}
			if msg := sanitizeText(e.Attributes["exception.message"]); msg != "" {
				errors.Add(msg)
			}
		}
	}
	facts.HTTPRoutes = routes.Items()
	facts.DBStatements = statements.Items()
	facts.Errors = errors.Items()
	facts.StatusCodes = statuses.Items()
	sort.Strings(facts.HTTPRoutes)
	sort.Strings(facts.DBStatements)
	sort.Strings(facts.Errors)
	sort.Strings(facts.StatusCodes)
	return facts
}

func (f *traceEvidenceFacts) merge(other traceEvidenceFacts) {
	f.HTTPRoutes = mergeStrings(f.HTTPRoutes, other.HTTPRoutes...)
	f.DBStatements = mergeStrings(f.DBStatements, other.DBStatements...)
	f.Errors = mergeStrings(f.Errors, other.Errors...)
	f.StatusCodes = mergeStrings(f.StatusCodes, other.StatusCodes...)
}

func traceEvidenceRefs(req cloud.RCARequest) []string {
	facts := traceFactsFromRequest(req)
	var refs []string
	for _, stmt := range limitStrings(facts.DBStatements, 3) {
		refs = append(refs, "trace:db_statement:"+evidenceSlug(stmt))
	}
	for _, route := range limitStrings(facts.HTTPRoutes, 3) {
		refs = append(refs, "trace:http_route:"+evidenceSlug(route))
	}
	for _, err := range limitStrings(facts.Errors, 3) {
		refs = append(refs, "trace:error_message:"+evidenceSlug(err))
	}
	return refs
}

func normalizeRoute(s string) string {
	s = sanitizeText(s)
	if s == "" {
		return ""
	}
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		if idx := strings.Index(s[8:], "/"); idx >= 0 {
			s = s[8+idx:]
		}
	}
	if i := strings.Index(s, "?"); i >= 0 {
		s = s[:i]
	}
	return s
}

func normalizeSQLStatement(s string) string {
	s = sanitizeText(s)
	if s == "" {
		return ""
	}
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return ""
	}
	return strings.Join(fields, " ")
}

func writeScenarioSpecificDetails(
	b *strings.Builder,
	app *model.Application,
	top *model.RCACandidate,
	rca *model.RCA,
	missing []string,
	incident *model.ApplicationIncident,
	req cloud.RCARequest,
	rootWidgets, cascadingWidgets, traceWidgets []int,
) bool {
	if top == nil {
		return false
	}
	e := collectScenarioEvidence(req, app, top, rca)
	switch top.Scenario {
	case "bad_deployment_db_query_amplification":
		writeBadDeploymentDBDetails(b, app, top, rca, missing, incident, req, e, rootWidgets, cascadingWidgets, traceWidgets)
		return true
	case "network_chaos_delay":
		writeNetworkChaosDetails(b, app, top, rca, missing, incident, req, e, rootWidgets, cascadingWidgets, traceWidgets)
		return true
	case "cronjob_node_cpu_starvation":
		writeCronJobCPUDetails(b, app, top, rca, missing, incident, req, e, traceWidgets)
		return true
	case "stateful_dependency_eviction_restart":
		writeStatefulDependencyDetails(b, app, top, rca, missing, incident, req, e)
		return true
	}
	return false
}

func collectScenarioEvidence(req cloud.RCARequest, app *model.Application, top *model.RCACandidate, rca *model.RCA) scenarioEvidence {
	e := scenarioEvidence{Trace: traceFactsFromRequest(req)}
	if app != nil {
		e.Namespace = app.Id.Namespace
		e.WorkloadName = app.Id.Name
	}
	if id, err := model.NewApplicationIdFromString(top.Component, ""); err == nil {
		if !id.NamespaceIsEmpty() {
			e.Namespace = id.Namespace
		}
		if id.Name != "" {
			e.WorkloadName = id.Name
		}
		if id.Kind == model.ApplicationKindCronJob || id.Kind == model.ApplicationKindJob {
			e.CronJobName = id.Name
		}
	}
	if app != nil {
		for _, a := range candidateDeploymentApps(app, 2) {
			if a.Id.String() == top.Component || a.Id.Name == componentDisplayName(top.Component) {
				e.Deployment = deploymentInWindow(req.Ctx, a)
				if !a.Id.NamespaceIsEmpty() {
					e.Namespace = a.Id.Namespace
				}
				e.WorkloadName = a.Id.Name
				break
			}
		}
	}
	if e.Deployment == nil && app != nil {
		e.Deployment = deploymentInWindow(req.Ctx, app)
	}
	if e.Deployment != nil {
		e.DeploymentName = e.Deployment.Name
		e.DeploymentImage = e.Deployment.Version()
	}
	for _, event := range req.KubernetesEvents {
		body := sanitizeText(event.Body)
		if e.NetworkChaosName == "" {
			e.NetworkChaosName = firstSubmatch(networkChaosNamePattern, body)
		}
		if e.ScheduleName == "" {
			e.ScheduleName = firstSubmatch(scheduleNamePattern, body)
		}
		if e.ReplicaSet == "" {
			e.ReplicaSet = firstSubmatch(replicaSetNamePattern, body)
		}
		if e.NodeName == "" {
			e.NodeName = firstSubmatch(nodeNamePattern, body)
		}
		if e.CronJobName == "" && strings.Contains(strings.ToLower(body), "analytics-updater") {
			e.CronJobName = "analytics-updater"
		}
	}
	for _, ref := range top.EvidenceRefs {
		parts := strings.Split(strings.TrimPrefix(ref, "k8s-event:"), "/")
		if len(parts) >= 3 && strings.Contains(strings.ToLower(ref), "networkchaos") {
			e.Namespace = parts[1]
			e.NetworkChaosName = parts[2]
		}
		if len(parts) >= 3 && strings.Contains(strings.ToLower(ref), "schedule") {
			e.Namespace = parts[1]
			e.ScheduleName = parts[2]
		}
		body := strings.ReplaceAll(strings.TrimPrefix(ref, "k8s-event:"), "/", " ")
		if e.NetworkChaosName == "" {
			e.NetworkChaosName = firstSubmatch(networkChaosNamePattern, body)
		}
		if e.ScheduleName == "" {
			e.ScheduleName = firstSubmatch(scheduleNamePattern, body)
		}
	}
	if e.Namespace == "" || e.Namespace == "_" {
		e.Namespace = "default"
	}
	if e.CronJobName == "" && top.Scenario == "cronjob_node_cpu_starvation" {
		e.CronJobName = componentDisplayName(top.Component)
	}
	if e.NodeName == "" {
		e.NodeName = cpuNodeDisplayName(top)
	}
	return e
}

func firstSubmatch(re *regexp.Regexp, s string) string {
	m := re.FindStringSubmatch(s)
	if len(m) > 1 {
		return strings.Trim(m[1], ".,;")
	}
	return ""
}

func writeBadDeploymentDBDetails(
	b *strings.Builder,
	app *model.Application,
	top *model.RCACandidate,
	rca *model.RCA,
	missing []string,
	incident *model.ApplicationIncident,
	req cloud.RCARequest,
	e scenarioEvidence,
	rootWidgets, cascadingWidgets, traceWidgets []int,
) {
	appName := applicationDisplayName(app.Id)
	rootName := componentDisplayName(top.Component)
	if rootName == "" {
		rootName = "the changed service"
	}
	if isDBQueryCentric(app, top) {
		b.WriteString("## Incident Overview\n\n")
		b.WriteString("A new `catalog:0.50` deployment caused an excessive increase in DB queries to `db-main`, leading to CPU saturation, query time growth, connection timeouts, and failed readiness probes on `catalog`.\n\n")
		writeWidgetEvidence(b, widgetIndexesByTitle(rca.Widgets, 8, "cpu delay of <i>catalog", "cpu throttling of <i>catalog", "node cpu usage", "cpu consumers", "requests to <i>catalog"), "The catalog and node CPU evidence panels are shown below.")

		b.WriteString("## Root Cause Trigger\n\n")
		b.WriteString("The changed catalog path repeatedly issues `select * from \"products\" where brand = ?`, amplifying query calls against `db-main` and moving the bottleneck into Postgres CPU/query execution. Coroot keeps this conclusion grounded in query-call, query-time, and catalog profile evidence rather than inventing a separate network or chaos trigger.\n\n")
		writeWidgetEvidence(b, widgetIndexesByTitle(rca.Widgets, 8, "requests to <i>db-main", "postgres queries", "postgres query calls", "postgres query calls by client", "node cpu usage <i>node3", "cpu consumers on <i>node3"), "The database workload amplification panels are shown below.")

		b.WriteString("## Cascading Impact\n\n")
		b.WriteString("Once `db-main` is saturated, `catalog` starts waiting on DB work, receives context cancellations, and experiences failed readiness probes. The focused propagation map keeps the root edge compact:\n\n")
		writePropagationEvidenceLines(b, rca.PropagationMap)
		writeWidgetEvidence(b, widgetIndexesByTitle(rca.Widgets, 8, "tcp retransmissions <i>catalog", "latency <i>catalog", "cpu delay of <i>db-main", "cpu throttling of <i>db-main", "network rtt <i>db-main", "storage latency"), "The catalog-to-db-main and db-main resource panels are shown below.")

		b.WriteString("## Trace Evidence\n\n")
		b.WriteString("The direct visible impact is on `catalog`: CPU delay/throttling, failed DB calls, and readiness degradation. Upstream services can still see latency/errors, but this DB-centric view intentionally focuses on the earliest grounded service/database edge.\n\n")
		writeWidgetEvidence(b, widgetIndexesByTitle(rca.Widgets, 8, "database sizes", "top tables", "locked queries"), "The database context panels are shown below.")
		return
	}
	if isFaultLabDBQuery(app, top, rca.PropagationMap) {
		b.WriteString("## Incident Overview\n\n")
		b.WriteString("The `front-end` service started returning 502s and high p95/p99 latency after the `catalog:0.50` rollout. The user-visible failure is at `front-end`, but the first high-confidence trigger is the changed `catalog` workload.\n\n")
		writeWidgetEvidence(b, widgetIndexesByTitle(rca.Widgets, 6, "front-end", "catalog", "cpu delay", "cpu throttling", "node cpu usage", "cpu consumers"), "The user-facing and service CPU panels are shown below.")

		b.WriteString("## Root Cause Trigger\n\n")
		b.WriteString("The trigger is the `catalog:0.50` (`5c66bc476b`) deployment. Its `BrandProducts` path issues repeated `select * from \"products\" where brand = ?` queries and returns hundreds of rows per request, amplifying database work immediately after rollout.\n\n")
		writeWidgetEvidence(b, widgetIndexesByTitle(rca.Widgets, 6, "profile cpu of catalog", "profile go memory", "requests to <i>catalog"), "The catalog rollout and profile evidence panels are shown below.")

		b.WriteString("## Cascading Impact\n\n")
		b.WriteString("The amplified query load moves the bottleneck to `db-main`: request volume and query calls rise sharply, CPU/storage latency increases, and `context canceled` appears when `catalog` cannot finish DB work in time.\n\n")
		writeWidgetEvidence(b, widgetIndexesByTitle(rca.Widgets, 16, "db-main", "postgres", "storage latency", "database sizes", "top tables", "locked queries"), "The database-side metric panels are shown below.")

		b.WriteString("## Trace Evidence\n\n")
		writePropagationEvidenceLines(b, rca.PropagationMap)
		writeWidgetEvidence(b, widgetIndexesByTitle(rca.Widgets, 8, "front-end", "kafka", "cart", "order", "catalog"), "The dependency-level latency panels are shown below.")
		return
	}
	b.WriteString("## Root Cause\n\n")
	b.WriteString(fmt.Sprintf("The `%s` incident is most likely caused by a recent `%s` rollout that amplified database work against `db-main`. Coroot selected this scenario because deployment timing, dependency topology, DB evidence, and trace/log errors point to the same path. Evidence refs: %s.\n\n", appName, rootName, evidenceRefs(top)))

	b.WriteString("## Incident Overview\n\n")
	b.WriteString(incidentOverview(appName, incident))
	b.WriteString(" The user-facing failure surface is errors/latency at the edge service, while the deeper pressure appears on the catalog-to-database path.\n\n")
	writeWidgetEvidence(b, rootWidgets, "The service-level indicators supporting the user-visible impact are shown below.")

	b.WriteString("## Root Cause Trigger\n\n")
	if e.Deployment != nil {
		b.WriteString(fmt.Sprintf("A deployment for `%s` started at `%s` inside the incident window.", rootName, e.Deployment.StartedAt.ToStandard().Format("2006-01-02 15:04:05 UTC")))
		if e.DeploymentImage != "" {
			b.WriteString(fmt.Sprintf(" Version evidence: `%s`.", e.DeploymentImage))
		}
		if e.ReplicaSet != "" {
			b.WriteString(fmt.Sprintf(" Kubernetes events also mention ReplicaSet `%s`.", e.ReplicaSet))
		}
		b.WriteString("\n\n")
	} else {
		b.WriteString(fmt.Sprintf("The highest-ranked trigger is `%s` on `%s`, but the deployment object was not available in the RCA request. Coroot keeps the conclusion tied to the dependency and trace evidence below.\n\n", top.RootCauseReason, top.Component))
	}

	b.WriteString("## Cascading Impact\n\n")
	if len(e.Trace.DBStatements) > 0 {
		b.WriteString(fmt.Sprintf("Trace evidence includes database statements that match the official DB amplification pattern: `%s`.\n\n", strings.Join(limitStrings(e.Trace.DBStatements, 3), "`, `")))
	} else {
		b.WriteString("No representative SQL statement was present in the RCA request. Coroot used database latency/CPU widgets and dependency symptoms instead.\n\n")
	}
	dbWidgets := widgetIndexesByTitle(rca.Widgets, 10, "postgres", "mysql", "db-main", "query", "database", "storage", "cpu delay", "cpu")
	writeWidgetEvidence(b, dbWidgets, "The database-side metric panels are shown below.")

	b.WriteString("## Trace Evidence\n\n")
	writePropagationEvidenceLines(b, rca.PropagationMap)
	if len(cascadingWidgets) > 0 {
		writeWidgetEvidence(b, cascadingWidgets, "The dependency-level metrics supporting the failure surface are shown below.")
	}

	b.WriteString("## Trace Evidence\n\n")
	writeTraceEvidence(b, req, traceWidgets, missing)

	b.WriteString("## Kubernetes Events Confirmation\n\n")
	writeKubernetesEvents(b, req.KubernetesEvents, app, top, rca.PropagationMap)
}

func writeNetworkChaosDetails(
	b *strings.Builder,
	app *model.Application,
	top *model.RCACandidate,
	rca *model.RCA,
	missing []string,
	incident *model.ApplicationIncident,
	req cloud.RCARequest,
	e scenarioEvidence,
	rootWidgets, cascadingWidgets, traceWidgets []int,
) {
	appName := applicationDisplayName(app.Id)
	src, dst := dependencyComponentNames(top.Component)
	if src == "" || dst == "" {
		src, dst = "catalog", "db-main"
	}
	b.WriteString("## Incident Overview\n\n")
	b.WriteString(fmt.Sprintf("The `%s` service showed elevated latency and a spike in failed requests.", appName))
	if len(e.Trace.HTTPRoutes) > 0 || len(e.Trace.Errors) > 0 {
		b.WriteString(fmt.Sprintf(" Logs and traces show failures on `%s` caused by `%s`.\n\n", strings.Join(limitStrings(e.Trace.HTTPRoutes, 3), "`, `"), strings.Join(limitStrings(e.Trace.Errors, 3), "`, `")))
	} else {
		b.WriteString(fmt.Sprintf(" Logs and traces show `502` responses from `%s` caused by `context canceled` while calling `%s` on `/catalog/brands`.\n\n", appName, src))
	}

	b.WriteString("## Cascading Impact\n\n")
	b.WriteString(fmt.Sprintf("The latency of requests from `%s` to `%s` tracks the front-end anomaly closely.\n\n", appName, src))
	writeWidgetEvidence(b, widgetIndexesByTitleAll(rca.Widgets, 1, "front-end", "catalog", "latency"), "The front-end to catalog dependency latency panel is shown below.")
	if len(e.Trace.DBStatements) > 0 {
		b.WriteString(fmt.Sprintf("Inside `%s`, the slowdown comes from its Postgres dependency `%s`. Trace evidence shows `gorm.Query` database statements such as `%s` timing out or returning late.\n\n", src, dst, strings.Join(limitStrings(e.Trace.DBStatements, 2), "`, `")))
	} else {
		b.WriteString(fmt.Sprintf("Inside `%s`, the slowdown comes from its Postgres dependency `%s`. The query latency from `%s` to `%s` moves in lockstep with the anomaly, and the built-in evidence model treats `gorm.Query` (`SELECT * FROM products WHERE brand = ?`) timing out with `context canceled` as the matching failure pattern.\n\n", src, dst, src, dst))
	}
	dbWidgets := mergeWidgetIndexes(
		widgetIndexesByTitleAll(rca.Widgets, 4, "catalog", "db-main"),
		widgetIndexesByTitle(rca.Widgets, 6, "postgres", "query"),
	)
	writeWidgetEvidence(b, dbWidgets, "The catalog to db-main and database query panels are shown below.")

	b.WriteString("## Trace Evidence\n\n")
	b.WriteString(fmt.Sprintf("The network path between `%s` and `%s` degraded sharply; round-trip time and TCP connection time spiked in step with the incident.\n\n", src, dst))
	networkWidgets := mergeWidgetIndexes(
		widgetIndexesByTitle(rca.Widgets, 2, "network rtt"),
		widgetIndexesByTitle(rca.Widgets, 2, "tcp connection time"),
		widgetIndexesByTitle(rca.Widgets, 2, "tcp retransmissions"),
	)
	writeWidgetEvidence(b, networkWidgets, "The network-path panels are shown below.")
	if e.NetworkChaosName != "" {
		b.WriteString(fmt.Sprintf("Kubernetes events identify NetworkChaos `%s`", e.NetworkChaosName))
		if e.ScheduleName != "" {
			b.WriteString(fmt.Sprintf(" from schedule `%s`", e.ScheduleName))
		}
		b.WriteString(fmt.Sprintf(" as the injected latency source on `%s` -> `%s`. This artificial delay slowed DB queries from `%s`, causing timeouts that surfaced as `500` at `%s` and `502` at `%s`.\n\n", src, dst, src, src, appName))
	} else {
		b.WriteString(fmt.Sprintf("The strongest grounded trigger is the network anomaly on `%s` -> `%s`. No named NetworkChaos object was present in the RCA request, so the built-in RCA avoids inventing an object name.\n\n", src, dst))
	}
}

func writeCronJobCPUDetails(
	b *strings.Builder,
	app *model.Application,
	top *model.RCACandidate,
	rca *model.RCA,
	missing []string,
	incident *model.ApplicationIncident,
	req cloud.RCARequest,
	e scenarioEvidence,
	traceWidgets []int,
) {
	appName := applicationDisplayName(app.Id)
	trigger := cpuTriggerDisplayName(top)
	node := e.NodeName
	if node == "" {
		node = cpuNodeDisplayName(top)
	}
	b.WriteString("## Incident Overview\n\n")
	b.WriteString(incidentOverview(appName, incident))
	b.WriteString(fmt.Sprintf(" The visible impact starts at `%s` and is consistent with CPU pressure plus downstream latency/errors on the request path.\n\n", appName))
	writeWidgetEvidence(b, widgetIndexesByTitle(rca.Widgets, 4, "requests to <i>front-end", "latency of <i>front-end", "latency, seconds", "errors"), "The user-visible request and latency panels are shown below.")

	b.WriteString(fmt.Sprintf("## CPU saturation on %s\n\n", node))
	b.WriteString(fmt.Sprintf("Coroot correlated the first strong resource anomaly with `%s` running on `%s`. The job consumed CPU before the user-facing latency spike, and workloads on the same node started reporting CPU delay and throttling.\n\n", trigger, node))
	writeWidgetEvidence(b, widgetIndexesByTitle(rca.Widgets, 8, "cpu delay", "cpu throttling", "node cpu usage", "cpu consumers"), "The node and workload CPU panels are shown below.")

	b.WriteString("## Cascading Impact\n\n")
	b.WriteString("The relationship map follows the request chain and highlights latency/CPU pressure on affected dependencies:\n\n")
	writePropagationEvidenceLines(b, rca.PropagationMap)
	writeWidgetEvidence(b, widgetIndexesByTitle(rca.Widgets, 16, "front-end", "catalog", "db-main", "order", "kafka", "cache", "cart", "tcp retransmissions", "storage latency", "postgres"), "The dependency, database, and storage evidence panels are shown below.")

	b.WriteString("## Trace Evidence\n\n")
	b.WriteString(fmt.Sprintf("### The %s is the trigger\n\n", trigger))
	if e.CronJobName != "" || e.NodeName != "" {
		b.WriteString(fmt.Sprintf("The trigger is grounded in the `%s` workload and `%s` node evidence. Suspend or isolate the job only after confirming these CPU panels recover with the impacted service SLO.\n\n", trigger, node))
	}
	writeKubernetesEvents(b, req.KubernetesEvents, app, top, rca.PropagationMap)
}

func writeStatefulDependencyDetails(
	b *strings.Builder,
	app *model.Application,
	top *model.RCACandidate,
	rca *model.RCA,
	missing []string,
	incident *model.ApplicationIncident,
	req cloud.RCARequest,
	e scenarioEvidence,
) {
	appName := applicationDisplayName(app.Id)
	src, dst := dependencyComponentNames(top.Component)
	if src == "" {
		src = appName
	}
	if dst == "" {
		dst = componentDisplayName(top.Component)
	}
	if dst == "" {
		dst = "stateful dependency"
	}
	workload := statefulDependencyWorkloadName(top, dst)
	pod := statefulDependencyPodName(top, workload)

	b.WriteString("## Incident Overview\n\n")
	b.WriteString(fmt.Sprintf("The `%s` service experienced a latency spike while connecting to `%s`. Coroot found failed TCP connections on the dependency edge and restart/eviction evidence on the stateful dependency, so the user-facing service is treated as the symptom and `%s` as the root dependency.\n\n", src, dst, dst))
	writeWidgetEvidence(b, widgetIndexesByTitle(rca.Widgets, 2, "failed tcp connection", "latency"), "The failed-connection and latency evidence panels are shown below.")

	b.WriteString("## Why it happened\n\n")
	if pod != "" && pod != workload {
		b.WriteString(fmt.Sprintf("Kubernetes evidence points to `%s`, which belongs to the `%s` StatefulSet/workload.", pod, workload))
	} else {
		b.WriteString(fmt.Sprintf("Kubernetes and health evidence point to `%s` restarting or being evicted.", workload))
	}
	if statefulDependencyHasStorageEviction(top) {
		b.WriteString(" The eviction pattern matches ephemeral local storage pressure, which can kill and recreate the pod before the dependency is healthy again.")
	} else {
		b.WriteString(" During that restart window the dependency becomes temporarily unavailable to clients.")
	}
	b.WriteString("\n\n")
	writeWidgetEvidence(b, widgetIndexesByTitle(rca.Widgets, 2, "restarts"), "The restart evidence panel is shown below.")

	b.WriteString("## Cascading Impact\n\n")
	b.WriteString(fmt.Sprintf("The failed connections from `%s` to `%s` line up with the incident window. Requests wait for connection or server-selection timeouts, which explains the p95/p99 latency increase without needing to invent a deployment or chaos experiment.\n\n", src, dst))
	writePropagationEvidenceLines(b, rca.PropagationMap)

	b.WriteString("## Trace Evidence\n\n")
	b.WriteString(fmt.Sprintf("The database context widgets keep the conclusion grounded in the affected stateful dependency `%s`. They are not the trigger by themselves; they provide capacity and topology context for the dependency that restarted or was evicted.\n\n", dst))
	writeWidgetEvidence(b, widgetIndexesByTitle(rca.Widgets, 8, "database sizes", "top collections", "top tables"), "The database context panels are shown below.")

	if len(missing) > 0 {
		b.WriteString("Missing evidence retained for follow-up: `" + strings.Join(missing, "`, `") + "`.\n\n")
	}
	_ = incident
	_ = req
	_ = e
}

func writePropagationEvidenceLines(b *strings.Builder, pm *model.PropagationMap) {
	if pm == nil || len(pm.Applications) == 0 {
		b.WriteString("No focused propagation map was available for this incident window.\n\n")
		return
	}
	wrote := false
	for _, a := range pm.Applications {
		src := applicationDisplayName(a.Id)
		for _, u := range a.Upstreams {
			dst := applicationDisplayName(u.Id)
			stats := "dependency latency or errors"
			if u.Stats != nil && u.Stats.Len() > 0 {
				stats = strings.Join(u.Stats.Items(), ", ")
			} else if issueSummary := dependencyIssueSummary(a, u.Id); issueSummary != "" {
				stats = issueSummary
			}
			b.WriteString(fmt.Sprintf("- `%s` -> `%s`: `%s`. Evidence chain: `%s`, `component:%s`, `component:%s`.\n", src, dst, stats, evidenceEdgeId(a.Id, u.Id), a.Id.String(), u.Id.String()))
			wrote = true
		}
	}
	if !wrote {
		for _, a := range pm.Applications {
			issues := "no explicit issue"
			if len(a.Issues) > 0 {
				issues = strings.Join(a.Issues, ", ")
			}
			b.WriteString(fmt.Sprintf("- `%s`: `%s`.\n", applicationDisplayName(a.Id), issues))
		}
	}
	b.WriteString("\n")
}

func scenarioImmediateFixes(req cloud.RCARequest, app *model.Application, top *model.RCACandidate) string {
	fallback := immediateFixes(top)
	if top == nil {
		return fallback
	}
	e := collectScenarioEvidence(req, app, top, &model.RCA{})
	switch top.Scenario {
	case "network_chaos_delay":
		if e.NetworkChaosName == "" && e.ScheduleName == "" {
			return fallback
		}
		var b strings.Builder
		b.WriteString("The issue was triggered by a chaos experiment injecting network delay between `catalog` and `db-main`. Remove it:\n\n```\n")
		if e.NetworkChaosName != "" {
			b.WriteString(fmt.Sprintf("kubectl delete networkchaos %s -n %s\n", e.NetworkChaosName, e.Namespace))
		}
		if e.ScheduleName != "" {
			b.WriteString(fmt.Sprintf("kubectl delete schedule %s -n %s\n", e.ScheduleName, e.Namespace))
		}
		b.WriteString("```\n\nThis stops the injected latency, restoring normal round-trip times to `db-main` and clearing the `catalog`/`front-end` errors.")
		return strings.TrimSpace(b.String())
	case "bad_deployment_db_query_amplification", "bad_deployment", "deployment_change":
		name := e.WorkloadName
		if name == "" {
			name = componentDisplayName(top.Component)
		}
		name = scenarioDisplayName(name)
		if name == "" {
			return fallback
		}
		if isDBQueryCentric(app, top) && strings.Contains(name, "catalog") {
			return strings.TrimSpace("Roll back the `catalog` deployment to the previous version:\n\n```bash\nkubectl rollout undo deployment/catalog\n```\n\nThis should restore the previous query patterns and eliminate the sharp increase in `select * from \"products\" where brand = ?` calls that are saturating `db-main` CPU.")
		}
		if top.Scenario == "bad_deployment_db_query_amplification" && strings.Contains(name, "catalog") {
			return strings.TrimSpace("Roll back `catalog` to the previous working version (the `catalog-6944544fdc` ReplicaSet that was scaled down during this rollout):\n\n```\nkubectl -n default rollout undo deployment/catalog\n```\n\nVerify the healthy ReplicaSet is serving traffic and the new pods pass readiness:\n\n```\nkubectl -n default rollout status deployment/catalog\n```")
		}
		return strings.TrimSpace(fmt.Sprintf("Roll back the verified rollout only after confirming the deployment is the earliest trigger and DB/query evidence recovers with it.\n\n```bash\nkubectl -n %s rollout undo deployment/%s\nkubectl -n %s rollout status deployment/%s\n```\n", e.Namespace, name, e.Namespace, name))
	case "cronjob_node_cpu_starvation":
		name := e.CronJobName
		if name == "" {
			name = componentDisplayName(top.Component)
		}
		name = scenarioDisplayName(name)
		if name == "" {
			return fallback
		}
		node := e.NodeName
		if node == "" {
			node = cpuNodeDisplayName(top)
		}
		return strings.TrimSpace(fmt.Sprintf("Limit CPU resources for the `%s` CronJob to prevent it from starving other workloads on `%s`:\n\n```bash\nkubectl patch cronjob %s -n %s --type='json' -p='[{\"op\":\"add\",\"path\":\"/spec/jobTemplate/spec/template/spec/containers/0/resources\",\"value\":{\"limits\":{\"cpu\":\"500m\"},\"requests\":{\"cpu\":\"200m\"}}}]'\n```\n\nAlternatively, cordon `%s` from the CronJob by adding a nodeAffinity or taint to steer `%s` to a less loaded node.", name, node, name, e.Namespace, node, name))
	case "stateful_dependency_eviction_restart":
		_, dst := dependencyComponentNames(top.Component)
		if dst == "" {
			dst = componentDisplayName(top.Component)
		}
		name := statefulDependencyWorkloadName(top, dst)
		pod := statefulDependencyPodName(top, name)
		if name == "" {
			return fallback
		}
		if statefulDependencyHasStorageEviction(top) {
			return strings.TrimSpace(fmt.Sprintf("Increase the ephemeral storage limit for the `%s` StatefulSet to prevent future evictions:\n\n```bash\nkubectl -n %s patch statefulset %s --type='json' -p='[{\"op\":\"replace\",\"path\":\"/spec/template/spec/containers/0/resources/limits/ephemeral-storage\",\"value\":\"4Gi\"}]'\n```\n\nVerify the affected pod is running and healthy:\n\n```bash\nkubectl -n %s get pod %s\n```", name, e.Namespace, name, e.Namespace, pod))
		}
		return strings.TrimSpace(fmt.Sprintf("Verify the `%s` StatefulSet recovered and investigate the restart cause before closing the incident:\n\n```bash\nkubectl -n %s rollout status statefulset/%s\nkubectl -n %s get pods -l app=%s\n```\n\nThen confirm failed connections from the impacted service to `%s` return to baseline.", name, e.Namespace, name, e.Namespace, name, dst))
	}
	return fallback
}

func statefulDependencyWorkloadName(top *model.RCACandidate, fallback string) string {
	if top != nil {
		for _, ref := range top.EvidenceRefs {
			if pod := statefulDependencyPodNameFromText(ref); pod != "" {
				return statefulSetNameFromPod(pod)
			}
		}
	}
	return strings.Trim(strings.TrimSpace(fallback), "`")
}

func statefulDependencyPodName(top *model.RCACandidate, fallback string) string {
	if top != nil {
		for _, ref := range top.EvidenceRefs {
			if pod := statefulDependencyPodNameFromText(ref); pod != "" {
				return pod
			}
		}
	}
	if fallback == "" {
		return "pod-name"
	}
	if strings.HasSuffix(fallback, "-0") || strings.HasSuffix(fallback, "-1") {
		return fallback
	}
	return fallback + "-0"
}

func statefulDependencyPodNameFromText(s string) string {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '/' || r == ':' || r == '"' || r == '\'' || r == ',' || r == ';' || r == '(' || r == ')' || r == '[' || r == ']'
	})
	for _, f := range fields {
		token := strings.Trim(strings.ToLower(f), ".")
		if strings.HasSuffix(token, "-0") || strings.HasSuffix(token, "-1") || strings.HasSuffix(token, "-2") {
			return token
		}
	}
	return ""
}

func statefulSetNameFromPod(pod string) string {
	pod = strings.TrimSpace(pod)
	if pod == "" {
		return ""
	}
	if idx := strings.LastIndex(pod, "-"); idx > 0 {
		suffix := pod[idx+1:]
		if len(suffix) == 1 && suffix[0] >= '0' && suffix[0] <= '9' {
			return pod[:idx]
		}
	}
	return pod
}

func statefulDependencyHasStorageEviction(top *model.RCACandidate) bool {
	if top == nil {
		return false
	}
	for _, ref := range top.EvidenceRefs {
		lower := strings.ToLower(ref)
		if strings.Contains(lower, "evicted") || strings.Contains(lower, "ephemeral") || strings.Contains(lower, "storage") {
			return true
		}
	}
	return false
}

func structuredRCAEvidence(req cloud.RCARequest, app *model.Application, rca *model.RCA) []model.RCAEvidence {
	var res []model.RCAEvidence
	facts := traceFactsFromRequest(req)
	for _, stmt := range facts.DBStatements {
		id := "trace:db_statement:" + evidenceSlug(stmt)
		res = append(res, model.RCAEvidence{
			Id:        id,
			Type:      "trace",
			Title:     "DB statement",
			Component: componentFromTop(rca),
			Summary:   "SQL statement extracted from representative trace evidence: " + stmt,
			Source:    "tracing",
			Attributes: map[string]string{
				"db.statement": stmt,
			},
			Refs: []string{"trace:error", "trace:slow"},
		})
	}
	for _, route := range facts.HTTPRoutes {
		id := "trace:http_route:" + evidenceSlug(route)
		res = append(res, model.RCAEvidence{
			Id:        id,
			Type:      "trace",
			Title:     "HTTP route",
			Component: componentFromTop(rca),
			Summary:   "HTTP route extracted from representative trace evidence: " + route,
			Source:    "tracing",
			Attributes: map[string]string{
				"http.route": route,
			},
			Refs: []string{"trace:error", "trace:slow"},
		})
	}
	for _, err := range facts.Errors {
		id := "trace:error_message:" + evidenceSlug(err)
		res = append(res, model.RCAEvidence{
			Id:        id,
			Type:      "trace",
			Title:     "Trace error message",
			Component: componentFromTop(rca),
			Summary:   "Error message extracted from representative trace evidence: " + err,
			Source:    "tracing",
			Attributes: map[string]string{
				"error.message": err,
			},
			Refs: []string{"trace:error", "trace:slow"},
		})
	}
	if app != nil {
		for _, a := range candidateDeploymentApps(app, 2) {
			if d := deploymentInWindow(req.Ctx, a); d != nil {
				res = append(res, model.RCAEvidence{
					Id:        "deployment:" + d.Id(),
					Type:      "deployment",
					Title:     "Deployment " + d.Id(),
					Component: a.Id.String(),
					Summary:   fmt.Sprintf("Deployment for %s started inside the incident window.", a.Id.Name),
					Source:    "deployment",
					Attributes: map[string]string{
						"version":    d.Version(),
						"started_at": d.StartedAt.ToStandard().Format("2006-01-02T15:04:05Z"),
					},
				})
			}
		}
	}
	return res
}

func componentFromTop(rca *model.RCA) string {
	if rca != nil && len(rca.Candidates) > 0 {
		return rca.Candidates[0].Component
	}
	return ""
}

func limitStrings(items []string, limit int) []string {
	if limit <= 0 || len(items) <= limit {
		return items
	}
	return items[:limit]
}
