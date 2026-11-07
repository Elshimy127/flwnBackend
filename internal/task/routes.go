package task

import (
	"github.com/Hesham127/flwnBackend/internal/auth"
	"github.com/Hesham127/flwnBackend/internal/platform/secure"
)

func RegisterRoutes(rg *secure.Router, svc *Service) {
	h := &handler{svc: svc}

	tasks := rg.Group("/workspaces/:workspace_id/projects/:project_id/tasks")
	tasks.POST("", secure.Write(auth.ScopePlanningWrite), h.create)
	tasks.GET("", secure.Read(auth.ScopePlanningRead), h.list)
	tasks.GET("/:task_id", secure.Read(auth.ScopePlanningRead), h.get)
	tasks.PATCH("/:task_id", secure.Write(auth.ScopePlanningWrite), h.update)
	tasks.DELETE("/:task_id", secure.Write(auth.ScopePlanningWrite), h.delete)

	rg.GET("/workspaces/:workspace_id/tasks/by-key/:key", secure.Read(auth.ScopePlanningRead), h.getByKey)
	rg.GET("/workspaces/:workspace_id/members/:member_id/tasks", secure.Read(auth.ScopePlanningRead), h.listForMember)
}
