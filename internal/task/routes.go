package task

import "github.com/gin-gonic/gin"

func RegisterRoutes(rg *gin.RouterGroup, svc *Service) {
	h := &handler{svc: svc}

	tasks := rg.Group("/workspaces/:workspace_id/projects/:project_id/tasks")
	tasks.POST("", h.create)
	tasks.GET("", h.list)
	tasks.GET("/:task_id", h.get)
	tasks.PATCH("/:task_id", h.update)
	tasks.DELETE("/:task_id", h.delete)

	rg.GET("/workspaces/:workspace_id/tasks/by-key/:key", h.getByKey)
	rg.GET("/workspaces/:workspace_id/members/:member_id/tasks", h.listForMember)
}
