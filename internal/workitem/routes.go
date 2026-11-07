package workitem

import (
	"github.com/Hesham127/flwnBackend/internal/auth"
	"github.com/Hesham127/flwnBackend/internal/platform/secure"
)

func RegisterRoutes(rg *secure.Router, svc *Service) {
	h := &handler{svc: svc}

	items := rg.Group("/workspaces/:workspace_id/projects/:project_id/work-items")
	items.POST("", secure.Write(auth.ScopePlanningWrite), h.create)
	items.GET("", secure.Read(auth.ScopePlanningRead), h.list)
	items.GET("/:work_item_id", secure.Read(auth.ScopePlanningRead), h.get)
	items.PATCH("/:work_item_id", secure.Write(auth.ScopePlanningWrite), h.update)
	items.DELETE("/:work_item_id", secure.Write(auth.ScopePlanningWrite), h.delete)
}
