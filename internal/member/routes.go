package member

import (
	"github.com/Hesham127/flwnBackend/internal/auth"
	"github.com/Hesham127/flwnBackend/internal/platform/secure"
)

func RegisterRoutes(rg *secure.Router, svc *Service) {
	h := &handler{svc: svc}

	members := rg.Group("/workspaces/:workspace_id/members")
	members.POST("", secure.Admin(auth.ScopeIdentityWrite), h.create)
	members.GET("", secure.Read(auth.ScopeIdentityRead), h.list)
	members.GET("/:member_id", secure.Read(auth.ScopeIdentityRead), h.get)
	members.PATCH("/:member_id", secure.Admin(auth.ScopeIdentityWrite), h.update)
	members.DELETE("/:member_id", secure.Admin(auth.ScopeIdentityWrite), h.delete)
}
