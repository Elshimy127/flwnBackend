package workspace

import (
	"time"

	"github.com/Hesham127/flwnBackend/internal/auth"
	"github.com/Hesham127/flwnBackend/internal/platform/secure"
)

func RegisterRoutes(rg *secure.Router, svc *Service) {
	h := &handler{svc: svc}
	authSvc := rg.Service()

	workspaces := rg.Group("/workspaces")
	// Any signed-in member may create another workspace (they become its owner); retries with the
	// same Idempotency-Key return the same workspace.
	workspaces.POST("", secure.Policy{Mode: secure.Access},
		secure.Idempotent(authSvc.Store(), func() time.Time { return time.Now().UTC() }), h.create)
	// Only the caller's own memberships, never every workspace the service key can see.
	workspaces.GET("", secure.Policy{Mode: secure.Access}, h.list)
	workspaces.GET("/:workspace_id", secure.Read(auth.ScopeIdentityRead), h.get)
	workspaces.PATCH("/:workspace_id", secure.Admin(auth.ScopeIdentityWrite), h.update)
	workspaces.DELETE("/:workspace_id", secure.Policy{Mode: secure.Recent, MinRole: auth.RoleOwner}, h.delete)
	workspaces.POST("/:workspace_id/ownership/transfer", secure.Policy{Mode: secure.Recent, MinRole: auth.RoleOwner}, h.transfer)
}
