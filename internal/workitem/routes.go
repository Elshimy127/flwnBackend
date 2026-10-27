package workitem

import "github.com/gin-gonic/gin"

func RegisterRoutes(rg *gin.RouterGroup, svc *Service) {
	h := &handler{svc: svc}

	items := rg.Group("/workspaces/:workspace_id/projects/:project_id/work-items")
	items.POST("", h.create)
	items.GET("", h.list)
	items.GET("/:work_item_id", h.get)
	items.PATCH("/:work_item_id", h.update)
	items.DELETE("/:work_item_id", h.delete)
}
