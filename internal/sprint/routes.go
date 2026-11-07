package sprint

import (
	"github.com/Hesham127/flwnBackend/internal/auth"
	"github.com/Hesham127/flwnBackend/internal/platform/secure"
)

func RegisterRoutes(rg *secure.Router, svc *Service) {
	h := &handler{svc: svc}

	sprints := rg.Group("/workspaces/:workspace_id/projects/:project_id/sprints")
	sprints.POST("", secure.Write(auth.ScopePlanningWrite), h.create)
	sprints.GET("", secure.Read(auth.ScopePlanningRead), h.list)
	sprints.GET("/:sprint_id", secure.Read(auth.ScopePlanningRead), h.get)
	sprints.PATCH("/:sprint_id", secure.Write(auth.ScopePlanningWrite), h.update)
	sprints.DELETE("/:sprint_id", secure.Write(auth.ScopePlanningWrite), h.delete)
}
