package member

import "github.com/gin-gonic/gin"

func RegisterRoutes(rg *gin.RouterGroup, svc *Service) {
	h := &handler{svc: svc}

	members := rg.Group("/workspaces/:workspace_id/members")
	members.POST("", h.create)
	members.GET("", h.list)
	members.GET("/:member_id", h.get)
	members.PATCH("/:member_id", h.update)
	members.DELETE("/:member_id", h.delete)
}
