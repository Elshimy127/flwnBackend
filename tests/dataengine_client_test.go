package tests

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/Hesham127/flwnBackend/internal/platform/dataengine"
	"github.com/Hesham127/flwnBackend/internal/project"
)

func TestClientRefusesCallsWithoutActingMember(t *testing.T) {
	f := newFakeEngine(t)
	_, err := project.NewService(f.client(t)).Get(context.Background(), uuid.New(), uuid.New())
	if !errors.Is(err, dataengine.ErrNoActingMember) {
		t.Fatalf("err = %v, want ErrNoActingMember", err)
	}
	if f.lastRequest().Method != "" {
		t.Fatal("engine was called without an acting member")
	}
}

func TestClientSendsServiceKeyAndActingMember(t *testing.T) {
	f := newFakeEngine(t)
	f.respond(http.StatusOK, `{}`)
	member := uuid.New()

	ctx := dataengine.WithActingMember(context.Background(), member)
	_, _ = project.NewService(f.client(t)).Get(ctx, uuid.New(), uuid.New())

	h := f.lastRequest().Header
	if got := h.Get("X-Data-API-Key"); got != testAPIKey {
		t.Errorf("X-Data-API-Key = %q, want %q", got, testAPIKey)
	}
	if got := h.Get("X-Acting-Member-Id"); got != member.String() {
		t.Errorf("X-Acting-Member-Id = %q, want %q", got, member)
	}
	if got := h.Get("Authorization"); got != "" {
		t.Errorf("Authorization = %q, want none", got)
	}
}

func TestClientTurnsEngineErrorIntoAPIError(t *testing.T) {
	f := newFakeEngine(t)
	f.respond(http.StatusConflict, `{"detail": "key already taken"}`)

	ctx := dataengine.WithActingMember(context.Background(), uuid.New())
	_, err := project.NewService(f.client(t)).Get(ctx, uuid.New(), uuid.New())

	var apiErr *dataengine.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v, want *APIError", err)
	}
	if apiErr.Status != http.StatusConflict || string(apiErr.Detail) != `"key already taken"` {
		t.Errorf("got %d %s", apiErr.Status, apiErr.Detail)
	}
}
