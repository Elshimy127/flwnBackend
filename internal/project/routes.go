package project

import (
	"github.com/Hesham127/flwnBackend/internal/auth"
	"github.com/Hesham127/flwnBackend/internal/platform/secure"
)

func RegisterRoutes(rg *secure.Router, svc *Service) {
	h := &handler{svc: svc}

	projects := rg.Group("/workspaces/:workspace_id/projects")
	projects.POST("", secure.Write(auth.ScopePlanningWrite), h.create)
	projects.GET("", secure.Read(auth.ScopePlanningRead), h.list)
	projects.GET("/:project_id", secure.Read(auth.ScopePlanningRead), h.get)
	projects.PATCH("/:project_id", secure.Write(auth.ScopePlanningWrite), h.update)
	projects.DELETE("/:project_id", secure.Write(auth.ScopePlanningWrite), h.delete)

	rg.GET("/workspaces/:workspace_id/members/:member_id/projects", secure.Read(auth.ScopePlanningRead), h.listForMember)
}
