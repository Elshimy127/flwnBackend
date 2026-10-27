package workspace

import "github.com/gin-gonic/gin"

func RegisterRoutes(rg *gin.RouterGroup, svc *Service) {
	h := &handler{svc: svc}

	workspaces := rg.Group("/workspaces")
	workspaces.POST("", h.create)
	workspaces.GET("", h.list)
	workspaces.GET("/:workspace_id", h.get)
	workspaces.PATCH("/:workspace_id", h.update)
	workspaces.DELETE("/:workspace_id", h.delete)
}
