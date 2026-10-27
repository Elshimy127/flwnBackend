package tests

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/Hesham127/flwnBackend/internal/platform/dataengine"
	"github.com/Hesham127/flwnBackend/internal/workspace"
)

func TestClientSendsServiceKeyOnly(t *testing.T) {
	f := newFakeEngine(t)
	f.respond(http.StatusOK, `{"items": [], "limit": 50, "offset": 0}`)

	if _, err := workspace.NewService(f.client(t)).List(context.Background(), dataengine.Page{}); err != nil {
		t.Fatal(err)
	}

	h := f.lastRequest().Header
	if got := h.Get("X-Data-API-Key"); got != testAPIKey {
		t.Errorf("X-Data-API-Key = %q, want %q", got, testAPIKey)
	}
	if got := h.Get("X-Acting-Member-Id"); got != "" {
		t.Errorf("X-Acting-Member-Id = %q, want none", got)
	}
	if got := h.Get("Authorization"); got != "" {
		t.Errorf("Authorization = %q, want none", got)
	}
}

func TestClientSendsActingMemberFromContext(t *testing.T) {
	f := newFakeEngine(t)
	f.respond(http.StatusOK, `{"items": [], "limit": 50, "offset": 0}`)
	member := uuid.New()

	ctx := dataengine.WithActingMember(context.Background(), member)
	if _, err := workspace.NewService(f.client(t)).List(ctx, dataengine.Page{}); err != nil {
		t.Fatal(err)
	}

	if got := f.lastRequest().Header.Get("X-Acting-Member-Id"); got != member.String() {
		t.Errorf("X-Acting-Member-Id = %q, want %q", got, member)
	}
}

func TestClientTurnsEngineErrorIntoAPIError(t *testing.T) {
	f := newFakeEngine(t)
	f.respond(http.StatusConflict, `{"detail": "slug already taken"}`)

	_, err := workspace.NewService(f.client(t)).Create(context.Background(), workspace.Create{Name: "Acme", Slug: "acme"})

	var apiErr *dataengine.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v, want *APIError", err)
	}
	if apiErr.Status != http.StatusConflict || string(apiErr.Detail) != `"slug already taken"` {
		t.Errorf("got %d %s", apiErr.Status, apiErr.Detail)
	}
}
