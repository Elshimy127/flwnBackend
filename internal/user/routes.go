package user

import "github.com/gin-gonic/gin"

func RegisterRoutes(rg *gin.RouterGroup, svc *Service) {
	h := &handler{svc: svc}

	users := rg.Group("/users")
	users.POST("", h.create)
	users.GET("", h.list)
	users.GET("/:user_id", h.get)
	users.PATCH("/:user_id", h.update)
	users.DELETE("/:user_id", h.delete)
}
