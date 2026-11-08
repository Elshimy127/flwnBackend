package tests

import (
	"crypto/sha256"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hesham127/flwnBackend/internal/auth"
)

// Identity routes always read the live membership; other reads may use the 5s cache.
func TestIdentityRoutesSkipReadCache(t *testing.T) {
	f := newFakeEngine(t)
	ws := uuid.New()
	me := f.signIn(t, ws, "admin")
	base := "/api/v1/workspaces/" + ws.String()
	f.respond(http.StatusOK, `{"items":[],"limit":50,"offset":0,"has_more":false}`)
	if w := do(t, f, http.MethodGet, base+"/projects", "", me.bearer()); w.Code != http.StatusOK {
		t.Fatalf("warm cache: %d", w.Code)
	}
	f.env.Engine.SetMember(me.member, "", "suspended") // changed outside the backend
	if w := do(t, f, http.MethodGet, base+"/members", "", me.bearer()); w.Code != http.StatusUnauthorized {
		t.Fatalf("identity read used the cache: %d", w.Code)
	}
}

func TestLoginLimitedPerIPAndAccount(t *testing.T) {
	f := newFakeEngine(t)
	body := func(email string) string { return `{"email":"` + email + `","password":"wrong password x"}` }
	victim := "victim-" + uuid.NewString()[:6] + "@example.com"
	codes := []int{}
	for i := 0; i < 6; i++ {
		codes = append(codes, do(t, f, http.MethodPost, "/api/v1/auth/login", body(victim), nil).Code)
	}
	if codes[5] != http.StatusTooManyRequests {
		t.Fatalf("6th attempt for one account: %v", codes)
	}
	// Same IP, same account in another spelling: still limited (canonical email).
	if w := do(t, f, http.MethodPost, "/api/v1/auth/login", body(strings.ToUpper(victim)), nil); w.Code != http.StatusTooManyRequests {
		t.Fatalf("case variant bypassed the limit: %d", w.Code)
	}
	// Same IP, another account: not limited by the account bucket.
	if w := do(t, f, http.MethodPost, "/api/v1/auth/login", body("other@example.com"), nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("other account: %d", w.Code)
	}
}

func TestIdempotencyReservesKey(t *testing.T) {
	f := newFakeEngine(t)
	ws := uuid.New()
	me := f.signIn(t, ws, "member")
	h := me.bearer()
	h["Idempotency-Key"] = "create-1"
	route := "POST /api/v1/workspaces"
	before := len(f.env.Engine.Workspaces)

	// A request already in flight with this key: the duplicate does not run.
	_ = f.env.Store.ReserveIdempotency(t.Context(), auth.IdempotencyRecord{
		Key: "create-1", UserID: me.user, Route: route, RequestHash: []byte("x"), CreatedAt: time.Now().UTC(),
	})
	h2 := me.bearer()
	h2["Idempotency-Key"] = "inflight"
	inflightBody := `{"name":"A","slug":"a1"}`
	sum := sha256.Sum256([]byte(inflightBody))
	_ = f.env.Store.ReserveIdempotency(t.Context(), auth.IdempotencyRecord{Key: "inflight", UserID: me.user, Route: route, RequestHash: sum[:], CreatedAt: time.Now().UTC()})
	if w := do(t, f, http.MethodPost, "/api/v1/workspaces", inflightBody, h2); w.Code != http.StatusConflict ||
		!strings.Contains(w.Body.String(), "request_in_progress") {
		t.Fatalf("in-flight duplicate: %d %s", w.Code, w.Body)
	}
	_ = f.env.Store.ReleaseIdempotency(t.Context(), me.user, route, "create-1")

	first := do(t, f, http.MethodPost, "/api/v1/workspaces", `{"name":"Acme","slug":"acme-x"}`, h)
	if first.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", first.Code, first.Body)
	}
	again := do(t, f, http.MethodPost, "/api/v1/workspaces", `{"name":"Acme","slug":"acme-x"}`, h)
	if again.Code != http.StatusCreated || again.Body.String() != first.Body.String() {
		t.Fatalf("replay: %d %s", again.Code, again.Body)
	}
	if got := len(f.env.Engine.Workspaces) - before; got != 1 {
		t.Fatalf("%d workspaces created, want 1", got)
	}
	if w := do(t, f, http.MethodPost, "/api/v1/workspaces", `{"name":"Other","slug":"other-x"}`, h); w.Code != http.StatusConflict ||
		!strings.Contains(w.Body.String(), "idempotency_key_reused") {
		t.Fatalf("key reused with another body: %d %s", w.Code, w.Body)
	}

	// A failed request frees its key for a retry.
	h3 := me.bearer()
	h3["Idempotency-Key"] = "fails"
	if w := do(t, f, http.MethodPost, "/api/v1/workspaces", `{"name":"Dup","slug":"acme-x"}`, h3); w.Code != http.StatusConflict {
		t.Fatalf("slug conflict: %d %s", w.Code, w.Body)
	}
	if w := do(t, f, http.MethodPost, "/api/v1/workspaces", `{"name":"Dup","slug":"acme-y"}`, h3); w.Code != http.StatusCreated {
		t.Fatalf("retry after failure: %d %s", w.Code, w.Body)
	}
}
