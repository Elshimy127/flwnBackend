// Package server wires every domain's routes into one Gin engine behind secure.Router.
package server

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/Hesham127/flwnBackend/internal/auth"
	"github.com/Hesham127/flwnBackend/internal/auth/authhttp"
	"github.com/Hesham127/flwnBackend/internal/member"
	"github.com/Hesham127/flwnBackend/internal/platform/dataengine"
	"github.com/Hesham127/flwnBackend/internal/platform/secure"
	"github.com/Hesham127/flwnBackend/internal/project"
	"github.com/Hesham127/flwnBackend/internal/sprint"
	"github.com/Hesham127/flwnBackend/internal/task"
	"github.com/Hesham127/flwnBackend/internal/team"
	"github.com/Hesham127/flwnBackend/internal/user"
	"github.com/Hesham127/flwnBackend/internal/workitem"
	"github.com/Hesham127/flwnBackend/internal/workspace"
)

const (
	apiPrefix    = "/api/v1"
	authPrefix   = apiPrefix + "/auth"
	nativePrefix = authPrefix + "/native"
)

// Deps are the router's collaborators.
type Deps struct {
	Engine         *dataengine.Client // request-scoped: always carries the acting member
	System         auth.Engine        // system identity: auth service and workspace creation only
	Auth           *auth.Service
	Origins        []string
	CookieSecure   bool
	CSRFKey        []byte
	HSTS           bool
	TrustedProxies []string
	// Ready reports whether dependencies are reachable (auth DB, engine).
	Ready func(context.Context) error
}

// NewRouter builds the engine and returns it with the route policy registry.
func NewRouter(d Deps) (*gin.Engine, *secure.Registry) {
	r := gin.New()
	_ = r.SetTrustedProxies(d.TrustedProxies) // nil = trust none; ClientIP is the socket peer
	r.Use(gin.Recovery(), secure.Logger(), secure.SecurityHeaders(d.HSTS), secure.StripInternalHeaders(),
		secure.CORS(d.Origins, authPrefix, nativePrefix))

	reg := secure.NewRegistry()
	root := secure.NewRouter(&r.RouterGroup, d.Auth, reg)
	root.GET("/healthz", secure.Policy{Mode: secure.Public}, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	root.GET("/readyz", secure.Policy{Mode: secure.Public}, func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
		defer cancel()
		if d.Ready != nil {
			if err := d.Ready(ctx); err != nil {
				c.JSON(http.StatusServiceUnavailable, gin.H{"status": "not_ready"})
				return
			}
		}
		c.JSON(http.StatusOK, gin.H{"status": "ready"})
	})

	authRoutes := root.Group(authPrefix, secure.NoStore())
	authhttp.Register(authRoutes, d.Auth, authhttp.Config{
		CookiePath: authPrefix, CookieSecure: d.CookieSecure, CSRFKey: d.CSRFKey, Origins: d.Origins,
	}, secure.NewRateLimiter(30, 10))

	v1 := root.Group(apiPrefix)
	user.RegisterRoutes(v1, user.NewService(d.Engine))
	workspace.RegisterRoutes(v1, workspace.NewService(d.Engine, d.System, d.Auth))
	member.RegisterRoutes(v1, member.NewService(d.Engine, d.Auth))
	team.RegisterRoutes(v1, team.NewService(d.Engine))
	project.RegisterRoutes(v1, project.NewService(d.Engine))
	workitem.RegisterRoutes(v1, workitem.NewService(d.Engine))
	sprint.RegisterRoutes(v1, sprint.NewService(d.Engine))
	task.RegisterRoutes(v1, task.NewService(d.Engine))

	return r, reg
}
