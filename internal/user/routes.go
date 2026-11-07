package user

import "github.com/Hesham127/flwnBackend/internal/platform/secure"

// RegisterRoutes mounts the profile routes. Accounts are created and deleted only through
// /auth (registration, DELETE /auth/account), and listing users is not exposed: users are
// global, so a caller sees and edits only their own profile (docs/AUTH.md §8, §14).
func RegisterRoutes(rg *secure.Router, svc *Service) {
	h := &handler{svc: svc}

	self := secure.Policy{Mode: secure.Access}
	users := rg.Group("/users")
	users.GET("/:user_id", self, h.get)
	users.PATCH("/:user_id", self, h.update)
}
