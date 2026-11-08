// Package authhttp exposes the auth service over HTTP: browser routes (refresh token in an
// HttpOnly cookie, CSRF + Origin checked) and native routes (refresh token in the body, never
// cookies). docs/AUTH.md §8, §9.
package authhttp

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/Hesham127/flwnBackend/internal/auth"
	"github.com/Hesham127/flwnBackend/internal/platform/secure"
)

// Config for the browser cookie model.
type Config struct {
	CookiePath   string   // "/api/v1/auth"
	CookieSecure bool     // false only for local http development
	CSRFKey      []byte   // >= 32 bytes
	Origins      []string // exact allowed Origins for cookie routes
}

type Handlers struct {
	svc     *auth.Service
	cfg     Config
	origins map[string]bool
	account *secure.RateLimiter // per (client IP, account) on top of the per-IP limiter
}

const (
	refreshCookiePrefix = "__Secure-flwn_rt_"
	csrfCookie          = "__Host-flwn_csrf"
	csrfHeader          = "X-CSRF-Token"
	workspaceHeader     = "X-Workspace-Id"
)

// Register mounts every auth route on r (which should be /api/v1/auth).
func Register(r *secure.Router, svc *auth.Service, cfg Config, limiter *secure.RateLimiter) {
	h := &Handlers{svc: svc, cfg: cfg, origins: map[string]bool{}, account: secure.NewRateLimiter(10, 5)}
	for _, o := range cfg.Origins {
		h.origins[strings.TrimRight(o, "/")] = true
	}
	pub := secure.Policy{Mode: secure.Public}
	limited := secure.LimitByIP(limiter)

	r.POST("/register", pub, limited, h.register)
	r.POST("/verify-email", pub, limited, h.verifyEmail)
	r.POST("/login", pub, limited, h.login)
	r.POST("/password/forgot", pub, limited, h.forgotPassword)
	r.POST("/password/reset", pub, limited, h.resetPassword)
	r.POST("/email/confirm", pub, limited, h.confirmEmail)

	ticket := secure.Policy{Mode: secure.Ticket}
	r.POST("/session", ticket, limited, h.session(true))
	r.POST("/workspaces", ticket, limited, h.firstWorkspace(true))
	r.POST("/account/delete", ticket, limited, h.deleteAccountWithTicket)

	refresh := secure.Policy{Mode: secure.Refresh}
	r.POST("/csrf", refresh, limited, h.csrf)
	r.POST("/refresh", refresh, h.cookieGuard, h.refresh(true))
	r.POST("/logout", refresh, h.cookieGuard, h.logout(true))
	r.POST("/switch", refresh, h.cookieGuard, h.switchWorkspace(true))

	access := secure.Policy{Mode: secure.Access}
	recent := secure.Policy{Mode: secure.Recent}
	r.GET("/me", access, h.me)
	r.GET("/workspaces", access, h.memberships)
	r.POST("/reauth", access, limited, h.reauth)
	r.POST("/password", access, limited, h.changePassword)
	r.POST("/logout-device", access, h.logoutDevice)
	r.POST("/logout-all", recent, h.logoutAll)
	r.POST("/email", recent, h.requestEmailChange)
	r.DELETE("/account", recent, h.deleteAccount)

	native := r.Group("/native")
	native.POST("/session", ticket, limited, h.session(false))
	native.POST("/workspaces", ticket, limited, h.firstWorkspace(false))
	native.POST("/refresh", refresh, h.refresh(false))
	native.POST("/logout", refresh, h.logout(false))
	native.POST("/switch", refresh, h.switchWorkspace(false))
}

// ---------------------------------------------------------------------------------------------
// Request decoding: strict JSON, 1 MB cap, unknown fields rejected.

func decode(c *gin.Context, v any) bool {
	dec := json.NewDecoder(io.LimitReader(c.Request.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_json"})
		return false
	}
	if dec.More() {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_json"})
		return false
	}
	return true
}

func fail(c *gin.Context, err error) {
	if errors.Is(err, auth.ErrTooManyAttempts) {
		c.Header("Retry-After", "60")
	}
	if errors.Is(err, auth.ErrInvalidInput) {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_input", "detail": strings.TrimPrefix(err.Error(), auth.ErrInvalidInput.Error()+": ")})
		return
	}
	var lo *auth.LastOwnerError
	if errors.As(err, &lo) {
		c.AbortWithStatusJSON(http.StatusConflict, gin.H{"error": "last_owner", "workspaces": lo.Workspaces})
		return
	}
	secure.Abort(c, err)
}

var accepted = gin.H{"status": "accepted"}

// limitAccount applies the per (client IP, account) limit. The account is the canonical email
// when it parses (else the raw lowercased input), or the user id for signed-in routes.
func (h *Handlers) limitAccount(c *gin.Context, account string) bool {
	if canon, err := auth.CanonicalEmail(account); err == nil {
		account = canon
	} else {
		account = strings.ToLower(strings.TrimSpace(account))
	}
	if !h.account.Allow(c.ClientIP() + "|" + account) {
		c.Header("Retry-After", "60")
		c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "too_many_requests"})
		return false
	}
	return true
}

// ---------------------------------------------------------------------------------------------
// Public

func (h *Handlers) register(c *gin.Context) {
	var in struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Name     string `json:"name"`
	}
	if !decode(c, &in) || !h.limitAccount(c, in.Email) {
		return
	}
	if err := h.svc.Register(c.Request.Context(), in.Email, in.Password, in.Name); err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusAccepted, accepted)
}

func (h *Handlers) verifyEmail(c *gin.Context) {
	var in struct {
		Token string `json:"token"`
	}
	if !decode(c, &in) {
		return
	}
	if err := h.svc.VerifyEmail(c.Request.Context(), in.Token); err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "verified"})
}

func (h *Handlers) login(c *gin.Context) {
	var in struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !decode(c, &in) || !h.limitAccount(c, in.Email) {
		return
	}
	res, err := h.svc.Login(c.Request.Context(), in.Email, in.Password)
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, res)
}

func (h *Handlers) forgotPassword(c *gin.Context) {
	var in struct {
		Email string `json:"email"`
	}
	if !decode(c, &in) || !h.limitAccount(c, in.Email) {
		return
	}
	_ = h.svc.ForgotPassword(c.Request.Context(), in.Email) // same answer whatever happened
	c.JSON(http.StatusAccepted, accepted)
}

func (h *Handlers) resetPassword(c *gin.Context) {
	var in struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if !decode(c, &in) {
		return
	}
	if err := h.svc.ResetPassword(c.Request.Context(), in.Token, in.Password); err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "password_reset"})
}

func (h *Handlers) confirmEmail(c *gin.Context) {
	var in struct {
		Token string `json:"token"`
	}
	if !decode(c, &in) {
		return
	}
	if err := h.svc.ConfirmEmailChange(c.Request.Context(), in.Token); err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "email_changed"})
}

// ---------------------------------------------------------------------------------------------
// Session issuance

func (h *Handlers) session(browser bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		var in struct {
			Ticket      string    `json:"login_ticket"`
			WorkspaceID uuid.UUID `json:"workspace_id"`
		}
		if !decode(c, &in) {
			return
		}
		pair, err := h.svc.CreateSession(c.Request.Context(), in.Ticket, in.WorkspaceID)
		if err != nil {
			fail(c, err)
			return
		}
		h.respondPair(c, http.StatusOK, pair, browser, nil)
	}
}

func (h *Handlers) firstWorkspace(browser bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		var in struct {
			Ticket string `json:"login_ticket"`
			Name   string `json:"name"`
			Slug   string `json:"slug"`
		}
		if !decode(c, &in) {
			return
		}
		ws, pair, err := h.svc.CreateFirstWorkspace(c.Request.Context(), in.Ticket, in.Name, in.Slug)
		if err != nil {
			fail(c, err)
			return
		}
		h.respondPair(c, http.StatusCreated, pair, browser, gin.H{"workspace": ws})
	}
}

// respondPair writes a token pair. Browser: refresh token only in an HttpOnly cookie named per
// workspace (several workspace sessions can be open in different tabs), CSRF cookie bound to the
// login session. Native: refresh token in the body.
func (h *Handlers) respondPair(c *gin.Context, status int, p auth.TokenPair, browser bool, extra gin.H) {
	body := gin.H{
		"access_token": p.AccessToken, "token_type": p.TokenType, "expires_at": p.ExpiresAt,
		"refresh_expires_at": p.RefreshExpiresAt, "workspace_id": p.WorkspaceID,
		"member_id": p.MemberID, "role": p.Role, "scope": p.Scope,
	}
	if browser {
		maxAge := int(time.Until(p.RefreshExpiresAt).Seconds())
		http.SetCookie(c.Writer, &http.Cookie{
			Name: h.refreshCookieName(p.WorkspaceID), Value: p.RefreshToken, Path: h.cfg.CookiePath,
			MaxAge: maxAge, HttpOnly: true, Secure: h.cfg.CookieSecure, SameSite: http.SameSiteStrictMode,
		})
		body["csrf_token"] = h.setCSRFCookie(c, p.LoginSessionID, maxAge)
	} else {
		body["refresh_token"] = p.RefreshToken
	}
	for k, v := range extra {
		body[k] = v
	}
	c.JSON(status, body)
}

// setCSRFCookie sets the readable CSRF cookie for a login session and returns its value.
func (h *Handlers) setCSRFCookie(c *gin.Context, loginSession uuid.UUID, maxAge int) string {
	csrf := h.csrfToken(loginSession)
	http.SetCookie(c.Writer, &http.Cookie{
		Name: h.csrfCookieName(), Value: csrf, Path: "/", MaxAge: maxAge,
		HttpOnly: false, Secure: h.cfg.CookieSecure, SameSite: http.SameSiteStrictMode,
	})
	return csrf
}

// refreshCookieName drops the __Secure- prefix in local http development: browsers reject a
// __Secure- cookie that lacks the Secure flag, which would silently break refresh.
func (h *Handlers) refreshCookieName(ws uuid.UUID) string {
	name := refreshCookiePrefix
	if !h.cfg.CookieSecure {
		name = strings.TrimPrefix(name, "__Secure-")
	}
	return name + strings.ReplaceAll(ws.String(), "-", "")
}

// csrfCookieName drops the __Host- prefix in local http development, where browsers refuse it.
func (h *Handlers) csrfCookieName() string {
	if h.cfg.CookieSecure {
		return csrfCookie
	}
	return "flwn_csrf"
}

func (h *Handlers) csrfToken(loginSession uuid.UUID) string {
	m := hmac.New(sha256.New, h.cfg.CSRFKey)
	m.Write([]byte("csrf:" + loginSession.String()))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (h *Handlers) clearCookies(c *gin.Context, ws uuid.UUID) {
	http.SetCookie(c.Writer, &http.Cookie{Name: h.refreshCookieName(ws), Value: "", Path: h.cfg.CookiePath,
		MaxAge: -1, HttpOnly: true, Secure: h.cfg.CookieSecure, SameSite: http.SameSiteStrictMode})
}

// ---------------------------------------------------------------------------------------------
// Refresh-mode routes

const refreshKey = "flwn.refresh"

// cookieGuard (browser refresh routes) reads the refresh cookie for the X-Workspace-Id
// workspace and enforces: allowed Origin, and X-CSRF-Token == csrf cookie == HMAC(login session).
func (h *Handlers) cookieGuard(c *gin.Context) {
	ck, ws, ls, ok := h.refreshCookie(c)
	if !ok {
		return
	}
	header := c.GetHeader(csrfHeader)
	cookie, _ := c.Request.Cookie(h.csrfCookieName())
	want := h.csrfToken(ls)
	if header == "" || cookie == nil ||
		subtle.ConstantTimeCompare([]byte(header), []byte(want)) != 1 ||
		subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(want)) != 1 {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "csrf_failed"})
		return
	}
	c.Set(refreshKey, ck.Value)
	c.Set("flwn.cookie_ws", ws)
	c.Next()
}

// refreshCookie checks the Origin and reads the X-Workspace-Id workspace's refresh cookie,
// returning it with its login session. It writes the error response when ok is false.
func (h *Handlers) refreshCookie(c *gin.Context) (ck *http.Cookie, ws, loginSession uuid.UUID, ok bool) {
	if !h.origins[strings.TrimRight(c.GetHeader("Origin"), "/")] {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "origin_not_allowed"})
		return nil, uuid.Nil, uuid.Nil, false
	}
	ws, err := uuid.Parse(c.GetHeader(workspaceHeader))
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "workspace_header_required"})
		return nil, uuid.Nil, uuid.Nil, false
	}
	ck, err = c.Request.Cookie(h.refreshCookieName(ws))
	if err != nil || ck.Value == "" {
		secure.Abort(c, auth.ErrUnauthenticated)
		return nil, uuid.Nil, uuid.Nil, false
	}
	ls, err := h.svc.LoginSessionForRefresh(c.Request.Context(), ck.Value)
	if err != nil {
		h.clearCookies(c, ws)
		secure.Abort(c, auth.ErrUnauthenticated)
		return nil, uuid.Nil, uuid.Nil, false
	}
	return ck, ws, ls, true
}

// csrf returns the CSRF token for the browser's refresh cookie, so a SPA on another host of the
// same site (which cannot read the API host's CSRF cookie) can recover it after a page reload.
// It changes no state; the allowlisted Origin plus CORS keep other sites from reading it.
func (h *Handlers) csrf(c *gin.Context) {
	_, _, ls, ok := h.refreshCookie(c)
	if !ok {
		return
	}
	// The refresh expiry is unknown here, so the re-set CSRF cookie lasts for the browser
	// session (MaxAge 0); the next refresh sets it again with the real lifetime.
	c.JSON(http.StatusOK, gin.H{"csrf_token": h.setCSRFCookie(c, ls, 0)})
}

// refreshToken returns the refresh token from the guarded cookie (browser) or the body (native).
func refreshToken(c *gin.Context, browser bool, body *struct {
	RefreshToken string     `json:"refresh_token"`
	WorkspaceID  *uuid.UUID `json:"workspace_id"`
}) bool {
	if browser {
		// Body is optional for browser refresh/logout; switch needs workspace_id.
		if c.Request.ContentLength != 0 {
			if !decode(c, body) {
				return false
			}
			if body.RefreshToken != "" {
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "use_cookie"})
				return false
			}
		}
		body.RefreshToken = c.GetString(refreshKey)
		return true
	}
	if !decode(c, body) {
		return false
	}
	if body.RefreshToken == "" {
		secure.Abort(c, auth.ErrUnauthenticated)
		return false
	}
	return true
}

type refreshBody = struct {
	RefreshToken string     `json:"refresh_token"`
	WorkspaceID  *uuid.UUID `json:"workspace_id"`
}

func (h *Handlers) refresh(browser bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		var in refreshBody
		if !refreshToken(c, browser, &in) {
			return
		}
		pair, err := h.svc.Refresh(c.Request.Context(), in.RefreshToken)
		if err != nil {
			if browser {
				if ws, ok := c.Get("flwn.cookie_ws"); ok {
					h.clearCookies(c, ws.(uuid.UUID))
				}
			}
			fail(c, err)
			return
		}
		h.respondPair(c, http.StatusOK, pair, browser, nil)
	}
}

func (h *Handlers) logout(browser bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		var in refreshBody
		if !refreshToken(c, browser, &in) {
			return
		}
		if err := h.svc.Logout(c.Request.Context(), in.RefreshToken, secure.BearerToken(c)); err != nil {
			fail(c, err)
			return
		}
		if browser {
			if ws, ok := c.Get("flwn.cookie_ws"); ok {
				h.clearCookies(c, ws.(uuid.UUID))
			}
		}
		c.Status(http.StatusNoContent)
	}
}

func (h *Handlers) switchWorkspace(browser bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		var in refreshBody
		if !refreshToken(c, browser, &in) {
			return
		}
		if in.WorkspaceID == nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "workspace_id_required"})
			return
		}
		pair, err := h.svc.Switch(c.Request.Context(), in.RefreshToken, *in.WorkspaceID)
		if err != nil {
			fail(c, err)
			return
		}
		h.respondPair(c, http.StatusOK, pair, browser, nil)
	}
}

// ---------------------------------------------------------------------------------------------
// Access-mode routes

func (h *Handlers) me(c *gin.Context) {
	p := secure.PrincipalFrom(c)
	c.JSON(http.StatusOK, gin.H{
		"user_id": p.UserID, "member_id": p.MemberID, "workspace_id": p.WorkspaceID, "role": p.Role,
		"scope": auth.JoinScopes(p.Scopes), "auth_time": p.AuthTime, "expires_at": p.ExpiresAt,
	})
}

func (h *Handlers) memberships(c *gin.Context) {
	p := secure.PrincipalFrom(c)
	ms, err := h.svc.Memberships(c.Request.Context(), p.UserID)
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": ms})
}

func (h *Handlers) reauth(c *gin.Context) {
	var in struct {
		Password string `json:"password"`
	}
	p := secure.PrincipalFrom(c)
	if !decode(c, &in) || !h.limitAccount(c, "user:"+p.UserID.String()) {
		return
	}
	if err := h.svc.Reauth(c.Request.Context(), p, in.Password); err != nil {
		fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *Handlers) changePassword(c *gin.Context) {
	var in struct {
		Current string `json:"current_password"`
		New     string `json:"new_password"`
	}
	if !decode(c, &in) {
		return
	}
	pair, err := h.svc.ChangePassword(c.Request.Context(), secure.PrincipalFrom(c), in.Current, in.New)
	if err != nil {
		fail(c, err)
		return
	}
	// A browser has the workspace's refresh cookie; a native client does not.
	_, cookieErr := c.Request.Cookie(h.refreshCookieName(pair.WorkspaceID))
	h.respondPair(c, http.StatusOK, pair, cookieErr == nil, nil)
}

func (h *Handlers) logoutDevice(c *gin.Context) {
	if err := h.svc.RevokeLoginSession(c.Request.Context(), secure.PrincipalFrom(c)); err != nil {
		fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *Handlers) logoutAll(c *gin.Context) {
	if err := h.svc.LogoutAll(c.Request.Context(), secure.PrincipalFrom(c)); err != nil {
		fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *Handlers) requestEmailChange(c *gin.Context) {
	var in struct {
		Email string `json:"email"`
	}
	if !decode(c, &in) {
		return
	}
	if err := h.svc.RequestEmailChange(c.Request.Context(), secure.PrincipalFrom(c), in.Email); err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusAccepted, accepted)
}

func (h *Handlers) deleteAccountWithTicket(c *gin.Context) {
	var in struct {
		Ticket string `json:"login_ticket"`
	}
	if !decode(c, &in) {
		return
	}
	if err := h.svc.DeleteAccountWithTicket(c.Request.Context(), in.Ticket); err != nil {
		fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *Handlers) deleteAccount(c *gin.Context) {
	if err := h.svc.DeleteAccount(c.Request.Context(), secure.PrincipalFrom(c)); err != nil {
		fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}
