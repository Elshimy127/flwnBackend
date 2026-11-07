package team

import (
	"github.com/Hesham127/flwnBackend/internal/auth"
	"github.com/Hesham127/flwnBackend/internal/platform/secure"
)

func RegisterRoutes(rg *secure.Router, svc *Service) {
	h := &handler{svc: svc}

	teams := rg.Group("/workspaces/:workspace_id/teams")
	teams.POST("", secure.Admin(auth.ScopeIdentityWrite), h.create)
	teams.GET("", secure.Read(auth.ScopeIdentityRead), h.list)
	teams.GET("/:team_id", secure.Read(auth.ScopeIdentityRead), h.get)
	teams.PATCH("/:team_id", secure.Admin(auth.ScopeIdentityWrite), h.update)
	teams.DELETE("/:team_id", secure.Admin(auth.ScopeIdentityWrite), h.delete)
	teams.PUT("/:team_id/members", secure.Admin(auth.ScopeIdentityWrite), h.replaceMembers)
}
