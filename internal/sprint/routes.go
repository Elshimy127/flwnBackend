package sprint

import "github.com/gin-gonic/gin"

func RegisterRoutes(rg *gin.RouterGroup, svc *Service) {
	h := &handler{svc: svc}

	sprints := rg.Group("/workspaces/:workspace_id/projects/:project_id/sprints")
	sprints.POST("", h.create)
	sprints.GET("", h.list)
	sprints.GET("/:sprint_id", h.get)
	sprints.PATCH("/:sprint_id", h.update)
	sprints.DELETE("/:sprint_id", h.delete)
}
