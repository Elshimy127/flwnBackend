package dataengine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
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
// author (audit log, created_by) and checks the member is active in the path workspace. The
// backend sets it only from an authenticated principal (secure.Router); handlers never do.
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
		// Every request-scoped call must act for an authenticated member (docs/AUTH.md §14).
		// System calls (provisioning, membership lookups) go through SystemClient instead.
		id, ok := ActingMember(ctx)
		if !ok || id == uuid.Nil {
			return ErrNoActingMember
		}
		req.Header.Set("X-Data-API-Key", apiKey)
		// Agent tokens are disabled on the engine; a bearer token gets 401.
		req.Header.Del("Authorization")
		req.Header.Set("X-Acting-Member-Id", id.String())
		return nil
	}
}

// ErrNoActingMember is returned for a request-scoped engine call without an authenticated
// acting member: a programming error, never sent to the engine.
var ErrNoActingMember = errors.New("data engine: request-scoped call without an acting member")

// JSON calls an engine endpoint the generated client does not have yet (new auth-contract
// endpoints), with the same headers as generated calls. Use Decode/NoContent on the result.
func (c *Client) JSON(ctx context.Context, method, path string, body any) (*http.Response, error) {
	var rd *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.Server, "/")+path, rd)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if err := c.applyEditors(ctx, req, nil); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}
