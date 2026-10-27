package team

import "github.com/gin-gonic/gin"

func RegisterRoutes(rg *gin.RouterGroup, svc *Service) {
	h := &handler{svc: svc}

	teams := rg.Group("/workspaces/:workspace_id/teams")
	teams.POST("", h.create)
	teams.GET("", h.list)
	teams.GET("/:team_id", h.get)
	teams.PATCH("/:team_id", h.update)
	teams.DELETE("/:team_id", h.delete)
	teams.PUT("/:team_id/members", h.replaceMembers)
}
