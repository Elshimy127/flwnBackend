package dataengine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Hesham127/flwnBackend/internal/auth"
)

// SystemClient is the backend's own identity towards the engine: the service key with no acting
// member. Only the auth service and background jobs hold one; request handlers get *Client,
// which carries the acting member. It may call only the identity endpoints auth needs
// (docs/AUTH.md §6, §14), and every call is logged as actor=system.
type SystemClient struct {
	base   string
	apiKey string
	http   *http.Client
}

var _ auth.Engine = (*SystemClient)(nil)

// NewSystemClient builds the system client. Auth lookups time out after 2s.
func NewSystemClient(baseURL, apiKey string) *SystemClient {
	return &SystemClient{
		base:   strings.TrimRight(baseURL, "/"),
		apiKey: apiKey,
		http:   &http.Client{Timeout: 2 * time.Second},
	}
}

func (c *SystemClient) do(ctx context.Context, method, path string, body, out any) (int, error) {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return 0, err
		}
	}
	attempts := 1
	if method == http.MethodGet {
		attempts = 2 // GETs retry once with jitter; writes never retry
	}
	var lastErr error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			select {
			case <-time.After(time.Duration(50+rand.IntN(100)) * time.Millisecond):
			case <-ctx.Done():
				return 0, ctx.Err()
			}
		}
		req, err := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(payload))
		if err != nil {
			return 0, err
		}
		req.Header.Set("X-Data-API-Key", c.apiKey)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		res, err := c.http.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		status, err := c.read(res, out)
		if status >= 500 {
			lastErr = err
			continue
		}
		log.Printf("engine call actor=system %s %s -> %d", method, path, status)
		return status, err
	}
	return 0, fmt.Errorf("%w: %v", auth.ErrEngineUnavailable, lastErr)
}

func (c *SystemClient) read(res *http.Response, out any) (int, error) {
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	switch {
	case res.StatusCode >= 200 && res.StatusCode < 300:
		if out != nil && len(b) > 0 {
			if err := json.Unmarshal(b, out); err != nil {
				return res.StatusCode, fmt.Errorf("%w: decode: %v", auth.ErrEngineUnavailable, err)
			}
		}
		return res.StatusCode, nil
	case res.StatusCode == http.StatusNotFound:
		return res.StatusCode, auth.ErrEngineNotFound
	case res.StatusCode == http.StatusConflict:
		if bytes.Contains(b, []byte("last_owner")) {
			return res.StatusCode, auth.ErrEngineLastOwner
		}
		return res.StatusCode, auth.ErrEngineConflict
	case res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden:
		log.Printf("ALERT: data engine rejected the service key (%d)", res.StatusCode)
		return res.StatusCode, fmt.Errorf("%w: service key rejected", auth.ErrEngineUnavailable)
	default:
		return res.StatusCode, fmt.Errorf("%w: status %d: %s", auth.ErrEngineUnavailable, res.StatusCode, truncate(b))
	}
}

func truncate(b []byte) string {
	if len(b) > 200 {
		return string(b[:200])
	}
	return string(b)
}

type memberWire struct {
	ID          uuid.UUID  `json:"id"`
	WorkspaceID uuid.UUID  `json:"workspace_id"`
	UserID      *uuid.UUID `json:"user_id"`
	Type        string     `json:"type"`
	Role        string     `json:"role"`
	Status      string     `json:"status"`
}

func (c *SystemClient) Member(ctx context.Context, ws, id uuid.UUID) (auth.Member, error) {
	var w memberWire
	if _, err := c.do(ctx, http.MethodGet, "/workspaces/"+ws.String()+"/members/"+id.String(), nil, &w); err != nil {
		return auth.Member{}, err
	}
	m := auth.Member{ID: w.ID, WorkspaceID: w.WorkspaceID, Type: w.Type, Role: w.Role, Status: w.Status}
	if w.UserID != nil {
		m.UserID = *w.UserID
	}
	return m, nil
}

func (c *SystemClient) Memberships(ctx context.Context, user uuid.UUID) ([]auth.Membership, error) {
	var page struct {
		Items []auth.Membership `json:"items"`
	}
	_, err := c.do(ctx, http.MethodGet, "/users/"+user.String()+"/memberships?status=active&type=HUMAN", nil, &page)
	return page.Items, err
}

func (c *SystemClient) FindUserByEmail(ctx context.Context, email string) (uuid.UUID, bool, error) {
	var page struct {
		Items []struct {
			ID    uuid.UUID `json:"id"`
			Email string    `json:"email"`
		} `json:"items"`
	}
	if _, err := c.do(ctx, http.MethodGet, "/users?email="+url.QueryEscape(email), nil, &page); err != nil {
		return uuid.Nil, false, err
	}
	want, err := auth.CanonicalEmail(email)
	if err != nil {
		return uuid.Nil, false, err
	}
	for _, u := range page.Items {
		if got, err := auth.CanonicalEmail(u.Email); err == nil && got == want {
			return u.ID, true, nil
		}
	}
	return uuid.Nil, false, nil
}

func (c *SystemClient) CreateUser(ctx context.Context, email, name string) (uuid.UUID, error) {
	var out struct {
		ID uuid.UUID `json:"id"`
	}
	_, err := c.do(ctx, http.MethodPost, "/users", map[string]any{"email": email, "name": name}, &out)
	return out.ID, err
}

func (c *SystemClient) CreateWorkspace(ctx context.Context, name, slug string, owner uuid.UUID) (auth.Workspace, error) {
	var out auth.Workspace
	_, err := c.do(ctx, http.MethodPost, "/workspaces",
		map[string]any{"name": name, "slug": slug, "owner_user_id": owner}, &out)
	if errors.Is(err, auth.ErrEngineNotFound) {
		return out, fmt.Errorf("%w: owner user missing", auth.ErrEngineUnavailable)
	}
	return out, err
}

func (c *SystemClient) UpdateUserEmail(ctx context.Context, user uuid.UUID, email string) error {
	_, err := c.do(ctx, http.MethodPatch, "/users/"+user.String(), map[string]any{"email": email}, nil)
	return err
}

func (c *SystemClient) DeleteUser(ctx context.Context, user uuid.UUID) error {
	_, err := c.do(ctx, http.MethodDelete, "/users/"+user.String(), nil, nil)
	return err
}

// Ping checks the engine is up (readiness).
func (c *SystemClient) Ping(ctx context.Context) error {
	_, err := c.do(ctx, http.MethodGet, "/healthz", nil, nil)
	return err
}
