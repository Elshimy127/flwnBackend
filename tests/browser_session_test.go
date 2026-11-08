package tests

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// browserSession logs in over HTTP and opens a browser session for ws, returning the refresh
// and CSRF cookies the server set.
func browserSession(t *testing.T, f *fakeEngine, ws uuid.UUID) (rt, csrf *http.Cookie) {
	t.Helper()
	me := f.signIn(t, ws, "member")
	w := httptest.NewRecorder()
	f.r.ServeHTTP(w, browserReq(http.MethodPost, "/api/v1/auth/login", `{"email":"`+me.email+`","password":"`+testPW+`"}`, nil, nil))
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
	for _, c := range w.Result().Cookies() {
		if strings.Contains(c.Name, "flwn_rt_") {
			rt = c
		}
		if strings.HasSuffix(c.Name, "flwn_csrf") {
			csrf = c
		}
	}
	if rt == nil || csrf == nil {
		t.Fatalf("session cookies missing: %v", w.Result().Cookies())
	}
	return rt, csrf
}

// Browsers reject __Secure-/__Host- cookies without the Secure flag, so local http development
// (COOKIE_SECURE=false) must use unprefixed names, and refresh must still work with them.
func TestDevCookiesHaveNoSecurePrefix(t *testing.T) {
	f := newFakeEngineCookies(t, false)
	ws := uuid.New()
	rt, csrf := browserSession(t, f, ws)
	for _, c := range []*http.Cookie{rt, csrf} {
		if strings.HasPrefix(c.Name, "__") || c.Secure {
			t.Fatalf("dev cookie %q has a secure prefix or flag", c.Name)
		}
	}
	w := httptest.NewRecorder()
	f.r.ServeHTTP(w, browserReq(http.MethodPost, "/api/v1/auth/refresh", "", []*http.Cookie{rt, csrf},
		map[string]string{"Origin": testOrigin, "X-CSRF-Token": csrf.Value, "X-Workspace-Id": ws.String()}))
	if w.Code != http.StatusOK {
		t.Fatalf("dev refresh: %d %s", w.Code, w.Body)
	}
}

// After a reload the SPA has only the HttpOnly refresh cookie; /auth/csrf hands back the CSRF
// token so it can refresh, but only to an allowlisted Origin holding a valid refresh cookie.
func TestCSRFRecoveryAfterReload(t *testing.T) {
	f := newFakeEngine(t)
	ws := uuid.New()
	rt, csrf := browserSession(t, f, ws)

	cases := []struct {
		name    string
		cookies []*http.Cookie
		hdr     map[string]string
		want    int
	}{
		{"no origin", []*http.Cookie{rt}, map[string]string{"X-Workspace-Id": ws.String()}, http.StatusForbidden},
		{"evil origin", []*http.Cookie{rt}, map[string]string{"Origin": "https://evil.test", "X-Workspace-Id": ws.String()}, http.StatusForbidden},
		{"no workspace", []*http.Cookie{rt}, map[string]string{"Origin": testOrigin}, http.StatusBadRequest},
		{"no cookie", nil, map[string]string{"Origin": testOrigin, "X-Workspace-Id": ws.String()}, http.StatusUnauthorized},
		{"bad cookie", []*http.Cookie{{Name: rt.Name, Value: "forged"}}, map[string]string{"Origin": testOrigin, "X-Workspace-Id": ws.String()}, http.StatusUnauthorized},
	}
	for _, tc := range cases {
		w := httptest.NewRecorder()
		f.r.ServeHTTP(w, browserReq(http.MethodPost, "/api/v1/auth/csrf", "", tc.cookies, tc.hdr))
		if w.Code != tc.want || strings.Contains(w.Body.String(), csrf.Value) {
			t.Errorf("%s: %d %s, want %d without a token", tc.name, w.Code, w.Body, tc.want)
		}
	}

	// Only the refresh cookie, as after a reload on another host of the same site.
	w := httptest.NewRecorder()
	f.r.ServeHTTP(w, browserReq(http.MethodPost, "/api/v1/auth/csrf", "", []*http.Cookie{rt},
		map[string]string{"Origin": testOrigin, "X-Workspace-Id": ws.String()}))
	if w.Code != http.StatusOK {
		t.Fatalf("csrf: %d %s", w.Code, w.Body)
	}
	var out struct {
		CSRF string `json:"csrf_token"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if out.CSRF != csrf.Value {
		t.Fatalf("recovered csrf %q, want %q", out.CSRF, csrf.Value)
	}

	// The recovered token works for refresh, and /auth/csrf did not rotate the refresh token.
	w = httptest.NewRecorder()
	f.r.ServeHTTP(w, browserReq(http.MethodPost, "/api/v1/auth/refresh", "", []*http.Cookie{rt, csrf},
		map[string]string{"Origin": testOrigin, "X-CSRF-Token": out.CSRF, "X-Workspace-Id": ws.String()}))
	if w.Code != http.StatusOK {
		t.Fatalf("refresh with recovered csrf: %d %s", w.Code, w.Body)
	}
}
