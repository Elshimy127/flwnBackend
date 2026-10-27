package project

import "github.com/gin-gonic/gin"

func RegisterRoutes(rg *gin.RouterGroup, svc *Service) {
	h := &handler{svc: svc}

	projects := rg.Group("/workspaces/:workspace_id/projects")
	projects.POST("", h.create)
	projects.GET("", h.list)
	projects.GET("/:project_id", h.get)
	projects.PATCH("/:project_id", h.update)
	projects.DELETE("/:project_id", h.delete)

	rg.GET("/workspaces/:workspace_id/members/:member_id/projects", h.listForMember)
}
