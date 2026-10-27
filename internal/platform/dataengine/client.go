package dataengine

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// Page is the limit/offset pair every engine list endpoint takes. Nil means "engine default".
type Page struct {
	Limit  *int
	Offset *int
}

type actingMemberKey struct{}

// WithActingMember records which member the request acts for. The engine stores it as the
// author (audit log, created_by). It is attribution only; it doesn't limit what the call can do.
func WithActingMember(ctx context.Context, memberID uuid.UUID) context.Context {
	return context.WithValue(ctx, actingMemberKey{}, memberID)
}

// ActingMember returns the member set by WithActingMember, if any.
func ActingMember(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(actingMemberKey{}).(uuid.UUID)
	return id, ok
}

// New builds a client that authenticates every call with the service key.
// The key can read and write any workspace, so it must never leave the backend.
func New(baseURL, apiKey string) (*Client, error) {
	return NewClient(baseURL,
		WithHTTPClient(&http.Client{Timeout: 15 * time.Second}),
		WithRequestEditorFn(authHeaders(apiKey)),
	)
}

// authHeaders runs before every request, so callers never pass the auth params the spec
// lists on each operation.
func authHeaders(apiKey string) RequestEditorFn {
	return func(ctx context.Context, req *http.Request) error {
		req.Header.Set("X-Data-API-Key", apiKey)
		// Agent tokens are disabled on the engine; a bearer token gets 401.
		req.Header.Del("Authorization")
		if id, ok := ActingMember(ctx); ok {
			req.Header.Set("X-Acting-Member-Id", id.String())
		}
		return nil
	}
}
