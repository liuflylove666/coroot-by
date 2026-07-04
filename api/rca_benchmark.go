package api

import (
	"net/http"

	"github.com/coroot/coroot/db"
	"github.com/coroot/coroot/rbac"
	localrca "github.com/coroot/coroot/rca"
	"github.com/coroot/coroot/utils"
)

func (api *Api) RCABenchmark(w http.ResponseWriter, r *http.Request, u *db.User) {
	if !api.IsAllowed(u, rbac.Actions.Settings().Edit()) {
		http.Error(w, "You are not allowed to view RCA benchmark reports.", http.StatusForbidden)
		return
	}
	utils.WriteJson(w, localrca.DemoParityBenchmarkReport())
}
