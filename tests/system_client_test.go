package tests

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/Hesham127/flwnBackend/internal/auth"
	"github.com/Hesham127/flwnBackend/internal/platform/dataengine"
)

// engineStub answers with the engine's real response shapes, per path.
func engineStub(t *testing.T, routes map[string]func(w http.ResponseWriter, r *http.Request)) *dataengine.SystemClient {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Data-API-Key") != testAPIKey || r.Header.Get("X-Acting-Member-Id") != "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		h, ok := routes[r.Method+" "+r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"detail":"Not Found"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	return dataengine.NewSystemClient(srv.URL, testAPIKey)
}

func reply(status int, body string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status); _, _ = io.WriteString(w, body) }
}

func TestSystemClientEngineContract(t *testing.T) {
	ctx := context.Background()
	user, ws, member := uuid.New(), uuid.New(), uuid.New()
	c := engineStub(t, map[string]func(http.ResponseWriter, *http.Request){
		// Behaves like the engine: lower(email) = lower(query). The row was stored with mixed case
		// (e.g. via the engine's own user route).
		"GET /users": func(w http.ResponseWriter, r *http.Request) {
			if strings.ToLower(r.URL.Query().Get("email")) != strings.ToLower("Sara@Example.COM") {
				_, _ = io.WriteString(w, `{"items":[],"limit":50,"offset":0,"has_more":false}`)
				return
			}
			_, _ = io.WriteString(w, `{"items":[{"id":"`+user.String()+`","email":"Sara@Example.COM","name":"S","avatar_url":null,"settings":{},"created_at":"2026-11-07T00:00:00Z","updated_at":"2026-11-07T00:00:00Z"}],"limit":50,"offset":0,"has_more":false}`)
		},
		"POST /users": reply(409, `{"detail":"user email already exists"}`),
		"GET /workspaces/" + ws.String() + "/members/" + member.String(): reply(200,
			`{"id":"`+member.String()+`","workspace_id":"`+ws.String()+`","user_id":"`+user.String()+`","type":"HUMAN","role":"admin","status":"active","agent_kind":null,"avatar_url":null,"email":"sara@x.com","name":"S","settings":{},"created_at":"2026-11-07T00:00:00Z","updated_at":"2026-11-07T00:00:00Z"}`),
		"GET /users/" + user.String() + "/memberships": reply(200,
			`{"items":[{"member_id":"`+member.String()+`","workspace_id":"`+ws.String()+`","workspace_name":"Acme","workspace_slug":"acme","user_id":"`+user.String()+`","type":"HUMAN","role":"owner","status":"active"}],"total":1}`),
		"DELETE /users/" + user.String(): reply(409, `{"detail":"last_owner"}`),
		"PATCH /users/" + user.String():  reply(409, `{"detail":"email is already in use"}`),
		"GET /healthz":                   reply(200, `{"status":"ok"}`),
	})

	// The user lookup previously compared bytes, which missed a stored mixed-case email and led
	// to a create, a 409 and a provisioning loop.
	id, found, err := c.FindUserByEmail(ctx, "sara@example.com")
	if err != nil || !found || id != user {
		t.Fatalf("FindUserByEmail: %v %v %v", id, found, err)
	}
	if _, err := c.CreateUser(ctx, "sara@x.com", "S"); !errors.Is(err, auth.ErrEngineConflict) {
		t.Errorf("CreateUser 409: %v", err)
	}
	m, err := c.Member(ctx, ws, member)
	if err != nil || m.UserID != user || m.Role != "admin" || m.Type != "HUMAN" || m.Status != "active" {
		t.Errorf("Member: %+v %v", m, err)
	}
	if _, err := c.Member(ctx, ws, uuid.New()); !errors.Is(err, auth.ErrEngineNotFound) {
		t.Errorf("missing member: %v", err)
	}
	ms, err := c.Memberships(ctx, user)
	if err != nil || len(ms) != 1 || ms[0].MemberID != member || ms[0].Role != "owner" {
		t.Errorf("Memberships: %+v %v", ms, err)
	}
	if err := c.DeleteUser(ctx, user); !errors.Is(err, auth.ErrEngineLastOwner) {
		t.Errorf("DeleteUser last owner: %v", err)
	}
	if err := c.UpdateUserEmail(ctx, user, "x@example.com"); !errors.Is(err, auth.ErrEngineConflict) {
		t.Errorf("UpdateUserEmail 409: %v", err)
	}
	if err := c.Ping(ctx); err != nil {
		t.Errorf("Ping: %v", err)
	}

	// The engine as it is today has no memberships route: login must fail closed, not open.
	today := engineStub(t, nil)
	if _, err := today.Memberships(ctx, user); !errors.Is(err, auth.ErrEngineNotFound) {
		t.Errorf("memberships on today's engine: %v", err)
	}
	// A wrong service key is never mistaken for "not found".
	bad := dataengine.NewSystemClient(strings.TrimSuffix(engineURL(t), "/"), "wrong-key")
	if _, err := bad.Member(ctx, ws, member); !errors.Is(err, auth.ErrEngineUnavailable) {
		t.Errorf("bad key: %v", err)
	}
}

func engineURL(t *testing.T) string {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) }))
	t.Cleanup(srv.Close)
	return srv.URL
}
