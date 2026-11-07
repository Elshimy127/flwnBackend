// Package secure is the only way to register an HTTP route: every route declares its
// authentication mode and authorization requirements (docs/AUTH.md §8), and a test fails if any
// registered route has no policy.
package secure

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/Hesham127/flwnBackend/internal/auth"
	"github.com/Hesham127/flwnBackend/internal/platform/dataengine"
)

// Mode is how a route authenticates.
type Mode int

const (
	// Public routes take no credential (rate limited).
	Public Mode = iota + 1
	// Ticket routes take a single-use login ticket in the body; the handler consumes it.
	Ticket
	// Refresh routes take a refresh token: cookie (browser, CSRF + Origin checked) or body (native).
	Refresh
	// Access routes take a Bearer human access token with full live checks.
	Access
	// Recent is Access plus a password check within the recent-auth window.
	Recent
)

func (m Mode) String() string {
	return [...]string{"?", "PUBLIC", "TICKET", "REFRESH", "ACCESS", "RECENT"}[m]
}

// Policy is a route's authentication and authorization requirement.
type Policy struct {
	Mode    Mode
	Scope   string    // required effective scope (Access/Recent); empty = none beyond the mode
	MinRole auth.Role // required live role, e.g. auth.RoleOwner; empty = any
}

// Registry records every route's policy, for the coverage test and docs.
type Registry struct {
	mu       sync.Mutex
	policies map[string]Policy
}

func NewRegistry() *Registry { return &Registry{policies: map[string]Policy{}} }

func (r *Registry) add(method, path string, p Policy) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := method + " " + path
	if _, dup := r.policies[key]; dup {
		panic("secure: route registered twice: " + key)
	}
	r.policies[key] = p
}

// Lookup returns a route's policy.
func (r *Registry) Lookup(method, path string) (Policy, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.policies[method+" "+path]
	return p, ok
}

// Router wraps a gin group so a route cannot be added without a Policy.
type Router struct {
	g   *gin.RouterGroup
	svc *auth.Service
	reg *Registry
}

func NewRouter(g *gin.RouterGroup, svc *auth.Service, reg *Registry) *Router {
	return &Router{g: g, svc: svc, reg: reg}
}

// Group returns a sub-router; extra middleware applies to its routes.
func (r *Router) Group(path string, mw ...gin.HandlerFunc) *Router {
	return &Router{g: r.g.Group(path, mw...), svc: r.svc, reg: r.reg}
}

// Service returns the auth service (for handlers that need it).
func (r *Router) Service() *auth.Service { return r.svc }

// Handle registers a route with its policy.
func (r *Router) Handle(method, path string, p Policy, h ...gin.HandlerFunc) {
	if p.Mode < Public || p.Mode > Recent {
		panic("secure: route " + method + " " + path + " has no auth mode")
	}
	if p.Mode != Access && p.Mode != Recent && (p.Scope != "" || p.MinRole != "") {
		panic("secure: scope/role need Access or Recent mode: " + method + " " + path)
	}
	if p.Scope != "" && !auth.EngineScopes[p.Scope] {
		panic("secure: unknown scope " + p.Scope)
	}
	full := joinPath(r.g.BasePath(), path)
	r.reg.add(method, full, p)
	chain := append(r.middleware(p, full), h...)
	r.g.Handle(method, path, chain...)
}

func (r *Router) GET(path string, p Policy, h ...gin.HandlerFunc) {
	r.Handle(http.MethodGet, path, p, h...)
}
func (r *Router) POST(path string, p Policy, h ...gin.HandlerFunc) {
	r.Handle(http.MethodPost, path, p, h...)
}
func (r *Router) PATCH(path string, p Policy, h ...gin.HandlerFunc) {
	r.Handle(http.MethodPatch, path, p, h...)
}
func (r *Router) PUT(path string, p Policy, h ...gin.HandlerFunc) {
	r.Handle(http.MethodPut, path, p, h...)
}
func (r *Router) DELETE(path string, p Policy, h ...gin.HandlerFunc) {
	r.Handle(http.MethodDelete, path, p, h...)
}

func joinPath(base, p string) string {
	if p == "" {
		return base
	}
	return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(p, "/")
}

func (r *Router) middleware(p Policy, fullPath string) []gin.HandlerFunc {
	if p.Mode != Access && p.Mode != Recent {
		return nil
	}
	checkWS := strings.Contains(fullPath, ":workspace_id")
	return []gin.HandlerFunc{func(c *gin.Context) {
		raw, ok := bearer(c)
		if !ok {
			abort(c, auth.ErrUnauthenticated)
			return
		}
		write := c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead
		// Writes and every identity route (members, teams, workspace settings) read the live
		// membership; only other reads may use the short read cache (docs/AUTH.md §6).
		live := write || strings.HasPrefix(p.Scope, "identity:") || p.MinRole != "" || p.Mode == Recent
		pr, err := r.svc.Authenticate(c.Request.Context(), raw, live)
		if err != nil {
			abort(c, err)
			return
		}
		if checkWS {
			ws, err := uuid.Parse(c.Param("workspace_id"))
			if err != nil || ws != pr.WorkspaceID {
				abortStatus(c, http.StatusForbidden, "token_not_valid_for_workspace")
				return
			}
		}
		if write && !bodyWorkspaceMatches(c, pr.WorkspaceID) {
			abortStatus(c, http.StatusForbidden, "token_not_valid_for_workspace")
			return
		}
		if p.Scope != "" && !pr.HasScope(p.Scope) {
			abortStatus(c, http.StatusForbidden, "missing_scope:"+p.Scope)
			return
		}
		if p.MinRole != "" && !pr.Role.AtLeast(p.MinRole) {
			abortStatus(c, http.StatusForbidden, "role_required:"+string(p.MinRole))
			return
		}
		if p.Mode == Recent {
			if err := r.svc.RequireRecent(pr); err != nil {
				abort(c, err)
				return
			}
		}
		c.Set(principalKey, pr)
		c.Request = c.Request.WithContext(dataengine.WithActingMember(c.Request.Context(), pr.MemberID))
		c.Next()
	}}
}

// bodyWorkspaceMatches rejects a JSON body whose top-level workspace_id is not the token's.
func bodyWorkspaceMatches(c *gin.Context, ws uuid.UUID) bool {
	if c.Request.Body == nil || !strings.HasPrefix(c.ContentType(), "application/json") {
		return true
	}
	b, err := io.ReadAll(io.LimitReader(c.Request.Body, 1<<20+1))
	c.Request.Body = io.NopCloser(bytes.NewReader(b))
	if err != nil || len(b) == 0 {
		return true // the handler reports bad JSON
	}
	var probe struct {
		WorkspaceID *string `json:"workspace_id"`
	}
	if json.Unmarshal(b, &probe) != nil || probe.WorkspaceID == nil {
		return true
	}
	id, err := uuid.Parse(*probe.WorkspaceID)
	return err == nil && id == ws
}

func bearer(c *gin.Context) (string, bool) {
	h := c.GetHeader("Authorization")
	if len(h) < 8 || !strings.EqualFold(h[:7], "bearer ") {
		return "", false
	}
	return strings.TrimSpace(h[7:]), true
}

// BearerToken returns the request's bearer token, if any.
func BearerToken(c *gin.Context) string {
	t, _ := bearer(c)
	return t
}

const principalKey = "flwn.principal"

// PrincipalFrom returns the authenticated caller; it panics on a route without Access/Recent,
// which is a programming error caught by tests.
func PrincipalFrom(c *gin.Context) auth.Principal {
	v, ok := c.Get(principalKey)
	if !ok {
		panic("secure: no principal on this route")
	}
	return v.(auth.Principal)
}

// abort maps an auth error to a response. Causes are logged, never returned.
func abort(c *gin.Context, err error) {
	status, code := ErrorStatus(err)
	if status == http.StatusUnauthorized {
		c.Header("WWW-Authenticate", `Bearer realm="flwn"`)
	}
	if status >= 500 {
		log.Printf("auth dependency error: %v", err)
	}
	abortStatus(c, status, code)
}

func abortStatus(c *gin.Context, status int, code string) {
	c.AbortWithStatusJSON(status, gin.H{"error": code})
}

// Abort writes an auth error response (for handlers).
func Abort(c *gin.Context, err error) { abort(c, err) }

// ErrorStatus maps service errors to HTTP status and a stable error code.
func ErrorStatus(err error) (int, string) {
	var lo *auth.LastOwnerError
	switch {
	case errors.As(err, &lo):
		return http.StatusConflict, "last_owner"
	case errors.Is(err, auth.ErrReauthRequired):
		return http.StatusUnauthorized, "reauth_required"
	case errors.Is(err, auth.ErrRefreshReused):
		return http.StatusUnauthorized, "refresh_reused"
	case errors.Is(err, auth.ErrUnauthenticated):
		return http.StatusUnauthorized, "unauthenticated"
	case errors.Is(err, auth.ErrInvalidCredentials):
		return http.StatusUnauthorized, "invalid_credentials"
	case errors.Is(err, auth.ErrForbidden):
		return http.StatusForbidden, "forbidden"
	case errors.Is(err, auth.ErrNotMember):
		return http.StatusForbidden, "not_a_member"
	case errors.Is(err, auth.ErrTooManyAttempts):
		return http.StatusTooManyRequests, "too_many_attempts"
	case errors.Is(err, auth.ErrAccountProvisioning):
		return http.StatusConflict, "account_provisioning"
	case errors.Is(err, auth.ErrInvalidLink):
		return http.StatusBadRequest, "invalid_or_expired_link"
	case errors.Is(err, auth.ErrEmailTaken):
		return http.StatusConflict, "email_taken"
	case errors.Is(err, auth.ErrInvalidInput):
		return http.StatusBadRequest, "invalid_input"
	default:
		return http.StatusServiceUnavailable, "unavailable"
	}
}

// Read and Write are the common Access policies for a scope.
func Read(scope string) Policy  { return Policy{Mode: Access, Scope: scope} }
func Write(scope string) Policy { return Policy{Mode: Access, Scope: scope} }

// Admin requires a write scope and at least the admin role.
func Admin(scope string) Policy { return Policy{Mode: Access, Scope: scope, MinRole: auth.RoleAdmin} }
