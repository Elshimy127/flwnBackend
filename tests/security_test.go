package tests

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hesham127/flwnBackend/internal/auth"
	"github.com/Hesham127/flwnBackend/internal/platform/secure"
)

// Every registered route must have a policy, and only the allowlisted routes may be public.
func TestEveryRouteHasAPolicy(t *testing.T) {
	f := newFakeEngine(t)
	public := map[string]bool{
		"GET /healthz": true, "GET /readyz": true,
		"POST /api/v1/auth/register": true, "POST /api/v1/auth/verify-email": true,
		"POST /api/v1/auth/login": true, "POST /api/v1/auth/password/forgot": true,
		"POST /api/v1/auth/password/reset": true, "POST /api/v1/auth/email/confirm": true,
	}
	routes := f.r.Routes()
	if len(routes) < 40 {
		t.Fatalf("only %d routes registered", len(routes))
	}
	for _, rt := range routes {
		key := rt.Method + " " + rt.Path
		p, ok := f.reg.Lookup(rt.Method, rt.Path)
		if !ok {
			t.Errorf("%s has no policy", key)
			continue
		}
		if p.Mode == secure.Public && !public[key] {
			t.Errorf("%s is public but not allowlisted", key)
		}
		if strings.Contains(rt.Path, ":workspace_id") && p.Mode != secure.Access && p.Mode != secure.Recent {
			t.Errorf("%s is workspace-scoped but mode %s", key, p.Mode)
		}
	}
	for key := range public {
		if _, ok := f.reg.Lookup(strings.SplitN(key, " ", 2)[0], strings.SplitN(key, " ", 2)[1]); !ok {
			t.Errorf("allowlisted %s not registered", key)
		}
	}
	// Removed routes stay removed.
	for _, gone := range []string{"POST /api/v1/users", "GET /api/v1/users", "DELETE /api/v1/users/:user_id"} {
		parts := strings.SplitN(gone, " ", 2)
		if _, ok := f.reg.Lookup(parts[0], parts[1]); ok {
			t.Errorf("%s must not exist", gone)
		}
	}
}

func TestProtectedRoutesNeedAToken(t *testing.T) {
	f := newFakeEngine(t)
	ws := uuid.NewString()
	for _, path := range []string{"/api/v1/workspaces/" + ws + "/projects", "/api/v1/auth/me", "/api/v1/workspaces"} {
		w := do(t, f, http.MethodGet, path, "", nil)
		if w.Code != http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") == "" {
			t.Errorf("%s: %d", path, w.Code)
		}
		w = do(t, f, http.MethodGet, path, "", map[string]string{"Authorization": "Bearer garbage"})
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s with garbage token: %d", path, w.Code)
		}
	}
	// The old dev header grants nothing.
	w := do(t, f, http.MethodGet, "/api/v1/workspaces/"+ws+"/projects", "", map[string]string{"X-Member-Id": uuid.NewString()})
	if w.Code != http.StatusUnauthorized {
		t.Errorf("X-Member-Id accepted: %d", w.Code)
	}
	if f.lastRequest().Method != "" {
		t.Error("engine called for unauthenticated request")
	}
}

func TestTokenOnlyValidForItsWorkspace(t *testing.T) {
	f := newFakeEngine(t)
	ws := uuid.New()
	me := f.signIn(t, ws, "owner")
	other := uuid.New()

	w := do(t, f, http.MethodGet, "/api/v1/workspaces/"+other.String()+"/projects", "", me.bearer())
	if w.Code != http.StatusForbidden {
		t.Errorf("cross-workspace path: %d", w.Code)
	}
	w = do(t, f, http.MethodPost, "/api/v1/workspaces/"+ws.String()+"/projects",
		`{"key":"X","name":"x","workspace_id":"`+other.String()+`"}`, me.bearer())
	if w.Code != http.StatusForbidden {
		t.Errorf("body workspace_id mismatch: %d", w.Code)
	}
	if f.lastRequest().Method != "" {
		t.Error("engine called for a foreign workspace")
	}
}

func TestScopesAndRoles(t *testing.T) {
	f := newFakeEngine(t)
	ws := uuid.New()
	viewer := f.signIn(t, ws, "viewer")
	member := f.signIn(t, ws, "member")
	admin := f.signIn(t, ws, "admin")
	wsPath := "/api/v1/workspaces/" + ws.String()

	cases := []struct {
		who          caller
		method, path string
		body         string
		want         int
	}{
		{viewer, http.MethodGet, wsPath + "/projects", "", http.StatusOK},
		{viewer, http.MethodPost, wsPath + "/projects", `{"key":"A","name":"a"}`, http.StatusForbidden},
		{member, http.MethodPost, wsPath + "/projects", `{"key":"A","name":"a"}`, http.StatusCreated},
		{member, http.MethodPost, wsPath + "/teams", `{"key":"t","name":"t"}`, http.StatusForbidden},
		{member, http.MethodPatch, wsPath, `{"name":"x"}`, http.StatusForbidden},
		{admin, http.MethodPatch, wsPath, `{"name":"x"}`, http.StatusOK},
		{admin, http.MethodDelete, wsPath, "", http.StatusForbidden}, // owner only
	}
	for _, tc := range cases {
		f.respond(http.StatusOK, `{}`)
		w := do(t, f, tc.method, tc.path, tc.body, tc.who.bearer())
		if w.Code != tc.want {
			t.Errorf("%s %s as %s: %d, want %d (%s)", tc.method, tc.path, tc.who.pair.Role, w.Code, tc.want, w.Body)
		}
	}
}

func TestDemotionAppliesOnNextRequest(t *testing.T) {
	f := newFakeEngine(t)
	ws := uuid.New()
	me := f.signIn(t, ws, "member")
	path := "/api/v1/workspaces/" + ws.String() + "/projects"
	f.respond(http.StatusOK, `{}`)
	if w := do(t, f, http.MethodPost, path, `{"key":"A","name":"a"}`, me.bearer()); w.Code != http.StatusCreated {
		t.Fatalf("before: %d", w.Code)
	}
	f.env.Engine.SetMember(me.member, "viewer", "")
	if w := do(t, f, http.MethodPost, path, `{"key":"A","name":"a"}`, me.bearer()); w.Code != http.StatusForbidden {
		t.Fatalf("after demotion: %d", w.Code)
	}
	// Changed directly in the engine (not through the backend): writes see it at once, reads
	// within the 5s read-cache window.
	f.env.Engine.SetMember(me.member, "", "suspended")
	if w := do(t, f, http.MethodPost, path, `{"key":"A","name":"a"}`, me.bearer()); w.Code != http.StatusUnauthorized {
		t.Fatalf("write after suspension: %d", w.Code)
	}
	f.env.Clock.Advance(6 * time.Second)
	if w := do(t, f, http.MethodGet, path, "", me.bearer()); w.Code != http.StatusUnauthorized {
		t.Fatalf("read after suspension: %d", w.Code)
	}
}

func TestEngineDownFailsClosed(t *testing.T) {
	f := newFakeEngine(t)
	ws := uuid.New()
	me := f.signIn(t, ws, "member")
	f.env.Engine.Down = true
	w := do(t, f, http.MethodGet, "/api/v1/workspaces/"+ws.String()+"/projects", "", me.bearer())
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status %d, want 503", w.Code)
	}
}

func TestRecentAuthRequired(t *testing.T) {
	f := newFakeEngine(t)
	ws := uuid.New()
	me := f.signIn(t, ws, "owner")
	f.env.Clock.Advance(11 * time.Minute)
	p2, err := f.env.Svc.Refresh(t.Context(), me.pair.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	me.pair = p2
	w := do(t, f, http.MethodPost, "/api/v1/auth/logout-all", "", me.bearer())
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "reauth_required") {
		t.Fatalf("logout-all without recent auth: %d %s", w.Code, w.Body)
	}
	w = do(t, f, http.MethodDelete, "/api/v1/workspaces/"+ws.String(), "", me.bearer())
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("workspace delete without recent auth: %d", w.Code)
	}
	w = do(t, f, http.MethodPost, "/api/v1/auth/reauth", `{"password":"`+testPW+`"}`, me.bearer())
	if w.Code != http.StatusNoContent {
		t.Fatalf("reauth: %d %s", w.Code, w.Body)
	}
	w = do(t, f, http.MethodPost, "/api/v1/auth/logout-all", "", me.bearer())
	if w.Code != http.StatusNoContent {
		t.Fatalf("logout-all after reauth: %d %s", w.Code, w.Body)
	}
	w = do(t, f, http.MethodGet, "/api/v1/auth/me", "", me.bearer())
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("token still valid after logout-all: %d", w.Code)
	}
}

func TestUserProfileSelfOnly(t *testing.T) {
	f := newFakeEngine(t)
	ws := uuid.New()
	me := f.signIn(t, ws, "admin")
	other := f.signIn(t, ws, "member")
	f.respond(http.StatusOK, `{}`)
	if w := do(t, f, http.MethodGet, "/api/v1/users/"+other.user.String(), "", me.bearer()); w.Code != http.StatusForbidden {
		t.Errorf("read other user: %d", w.Code)
	}
	if w := do(t, f, http.MethodGet, "/api/v1/users/"+me.user.String(), "", me.bearer()); w.Code != http.StatusOK {
		t.Errorf("read self: %d", w.Code)
	}
	if w := do(t, f, http.MethodPatch, "/api/v1/users/"+me.user.String(), `{"email":"x@example.com"}`, me.bearer()); w.Code != http.StatusBadRequest {
		t.Errorf("email via profile: %d", w.Code)
	}
}

func TestMemberOwnerRules(t *testing.T) {
	f := newFakeEngine(t)
	ws := uuid.New()
	admin := f.signIn(t, ws, "admin")
	owner := f.signIn(t, ws, "owner")
	path := "/api/v1/workspaces/" + ws.String() + "/members/"

	memberJSON := func(role string) string {
		return `{"id":"` + owner.member.String() + `","workspace_id":"` + ws.String() + `","role":"` + role +
			`","status":"active","type":"HUMAN","settings":{},"created_at":"2026-11-07T00:00:00Z","updated_at":"2026-11-07T00:00:00Z",
			"agent_kind":null,"avatar_url":null,"email":null,"name":null,"user_id":null}`
	}
	// Admin may not touch an owner or grant owner.
	f.respond(http.StatusOK, memberJSON("owner"))
	if w := do(t, f, http.MethodPatch, path+owner.member.String(), `{"role":"member"}`, admin.bearer()); w.Code != http.StatusForbidden {
		t.Errorf("admin demoting owner: %d %s", w.Code, w.Body)
	}
	if w := do(t, f, http.MethodPost, strings.TrimSuffix(path, "/"), `{"type":"HUMAN","role":"owner","email":"o@example.com","name":"O"}`, admin.bearer()); w.Code != http.StatusForbidden {
		t.Errorf("admin adding owner: %d", w.Code)
	}
	if w := do(t, f, http.MethodPatch, path+owner.member.String(), `{"email":"x@example.com"}`, owner.bearer()); w.Code != http.StatusBadRequest {
		t.Errorf("member email change: %d", w.Code)
	}
	// Owner suspends the admin: the admin's sessions end immediately.
	f.respond(http.StatusOK, strings.Replace(memberJSON("admin"), `"status":"active"`, `"status":"suspended"`, 1))
	if w := do(t, f, http.MethodPatch, path+admin.member.String(), `{"status":"suspended"}`, owner.bearer()); w.Code != http.StatusOK {
		t.Fatalf("owner suspending admin: %d %s", w.Code, w.Body)
	}
	if w := do(t, f, http.MethodGet, "/api/v1/auth/me", "", admin.bearer()); w.Code != http.StatusUnauthorized {
		t.Errorf("suspended admin still authenticated: %d", w.Code)
	}
}

func TestInternalHeadersAreStripped(t *testing.T) {
	f := newFakeEngine(t)
	ws := uuid.New()
	me := f.signIn(t, ws, "member")
	h := me.bearer()
	h["X-Acting-Member-Id"] = uuid.NewString()
	h["X-Data-API-Key"] = "attacker"
	f.respond(http.StatusOK, `{}`)
	do(t, f, http.MethodGet, "/api/v1/workspaces/"+ws.String()+"/projects", "", h)
	got := f.lastRequest().Header
	if got.Get("X-Acting-Member-Id") != me.member.String() || got.Get("X-Data-API-Key") != testAPIKey {
		t.Fatalf("client headers reached the engine: %v", got)
	}
}

// --- Browser flow: cookies, CSRF, Origin, CORS -------------------------------------------------

func browserReq(method, path, body string, cookies []*http.Cookie, hdr map[string]string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return req
}

func TestBrowserLoginRefreshCSRF(t *testing.T) {
	f := newFakeEngine(t)
	ws := uuid.New()
	me := f.signIn(t, ws, "member") // creates the account; now log in again through HTTP

	w := httptest.NewRecorder()
	f.r.ServeHTTP(w, browserReq(http.MethodPost, "/api/v1/auth/login", `{"email":"`+me.email+`","password":"`+testPW+`"}`, nil, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("login: %d %s", w.Code, w.Body)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Error("auth response cacheable")
	}
	var login struct {
		Ticket string `json:"login_ticket"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &login)

	w = httptest.NewRecorder()
	f.r.ServeHTTP(w, browserReq(http.MethodPost, "/api/v1/auth/session",
		`{"login_ticket":"`+login.Ticket+`","workspace_id":"`+ws.String()+`"}`, nil, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("session: %d %s", w.Code, w.Body)
	}
	var sess map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &sess)
	if _, leaked := sess["refresh_token"]; leaked {
		t.Fatal("browser response carries the refresh token in the body")
	}
	cookies := w.Result().Cookies()
	var rt, csrf *http.Cookie
	for _, c := range cookies {
		if strings.HasPrefix(c.Name, "__Secure-flwn_rt_") {
			rt = c
		}
		if c.Name == "__Host-flwn_csrf" {
			csrf = c
		}
	}
	if rt == nil || !rt.HttpOnly || !rt.Secure || rt.SameSite != http.SameSiteStrictMode || rt.Path != "/api/v1/auth" {
		t.Fatalf("refresh cookie attributes wrong: %+v", rt)
	}
	if csrf == nil || csrf.HttpOnly || csrf.Path != "/" || csrf.Value != sess["csrf_token"] {
		t.Fatalf("csrf cookie wrong: %+v", csrf)
	}

	good := map[string]string{"Origin": testOrigin, "X-CSRF-Token": csrf.Value, "X-Workspace-Id": ws.String()}
	cases := []struct {
		name string
		hdr  map[string]string
		want int
	}{
		{"no origin", map[string]string{"X-CSRF-Token": csrf.Value, "X-Workspace-Id": ws.String()}, http.StatusForbidden},
		{"evil origin", map[string]string{"Origin": "https://evil.test", "X-CSRF-Token": csrf.Value, "X-Workspace-Id": ws.String()}, http.StatusForbidden},
		{"no csrf", map[string]string{"Origin": testOrigin, "X-Workspace-Id": ws.String()}, http.StatusForbidden},
		{"wrong csrf", map[string]string{"Origin": testOrigin, "X-CSRF-Token": "forged", "X-Workspace-Id": ws.String()}, http.StatusForbidden},
	}
	for _, tc := range cases {
		w = httptest.NewRecorder()
		f.r.ServeHTTP(w, browserReq(http.MethodPost, "/api/v1/auth/refresh", "", []*http.Cookie{rt, csrf}, tc.hdr))
		if w.Code != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, w.Code, tc.want)
		}
	}
	w = httptest.NewRecorder()
	f.r.ServeHTTP(w, browserReq(http.MethodPost, "/api/v1/auth/refresh", "", []*http.Cookie{rt, csrf}, good))
	if w.Code != http.StatusOK {
		t.Fatalf("good refresh: %d %s", w.Code, w.Body)
	}
	// Replaying the old cookie is reuse: the family is revoked.
	w = httptest.NewRecorder()
	f.r.ServeHTTP(w, browserReq(http.MethodPost, "/api/v1/auth/refresh", "", []*http.Cookie{rt, csrf}, good))
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "refresh_reused") {
		t.Fatalf("replayed refresh cookie: %d %s", w.Code, w.Body)
	}
}

func TestNativeRoutesIgnoreCookiesAndCORS(t *testing.T) {
	f := newFakeEngine(t)
	ws := uuid.New()
	me := f.signIn(t, ws, "member")
	// A cookie alone does nothing on native routes.
	w := httptest.NewRecorder()
	f.r.ServeHTTP(w, browserReq(http.MethodPost, "/api/v1/auth/native/refresh", `{}`,
		[]*http.Cookie{{Name: "__Secure-flwn_rt_x", Value: me.pair.RefreshToken}}, map[string]string{"Origin": testOrigin}))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("native refresh with cookie only: %d", w.Code)
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("native route sent CORS headers")
	}
	w = httptest.NewRecorder()
	f.r.ServeHTTP(w, browserReq(http.MethodPost, "/api/v1/auth/native/refresh", `{"refresh_token":"`+me.pair.RefreshToken+`"}`, nil, nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "refresh_token") {
		t.Errorf("native refresh: %d %s", w.Code, w.Body)
	}
}

func TestCORSAllowlist(t *testing.T) {
	f := newFakeEngine(t)
	pre := func(origin, path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		f.r.ServeHTTP(w, browserReq(http.MethodOptions, path, "", nil, map[string]string{"Origin": origin, "Access-Control-Request-Method": "POST"}))
		return w
	}
	if w := pre("https://evil.test", "/api/v1/auth/refresh"); w.Code != http.StatusForbidden || w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("evil origin preflight: %d %v", w.Code, w.Header())
	}
	w := pre(testOrigin, "/api/v1/auth/refresh")
	if w.Header().Get("Access-Control-Allow-Origin") != testOrigin || w.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Errorf("auth preflight: %v", w.Header())
	}
	w = pre(testOrigin, "/api/v1/workspaces")
	if w.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Error("credentials allowed outside /auth")
	}
}

// Passwords, tokens and cookies never reach the logs.
func TestLogsHaveNoSecrets(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	f := newFakeEngine(t)
	ws := uuid.New()
	me := f.signIn(t, ws, "member")
	do(t, f, http.MethodPost, "/api/v1/auth/login", `{"email":"`+me.email+`","password":"`+testPW+`"}`, nil)
	do(t, f, http.MethodGet, "/api/v1/auth/me", "", me.bearer())
	do(t, f, http.MethodPost, "/api/v1/auth/native/refresh", `{"refresh_token":"`+me.pair.RefreshToken+`"}`, nil)

	out := buf.String()
	if !strings.Contains(out, "/api/v1/auth/me") {
		t.Fatalf("request log missing: %q", out)
	}
	for _, secret := range []string{testPW, me.pair.AccessToken, me.pair.RefreshToken, "Bearer "} {
		if strings.Contains(out, secret) {
			t.Errorf("log contains a secret %q", secret[:min(len(secret), 12)])
		}
	}
}

var _ = auth.RoleOwner
