package authtest

import (
	"context"
	"strings"
	"sync"

	"github.com/google/uuid"

	"github.com/Hesham127/flwnBackend/internal/auth"
)

// Engine is an in-memory auth.Engine.
type Engine struct {
	mu         sync.Mutex
	Users      map[uuid.UUID]string // id -> email
	Members    map[uuid.UUID]*auth.Member
	Workspaces map[uuid.UUID]auth.Workspace
	Down       bool // every call fails with ErrEngineUnavailable
	FailCreate bool // CreateUser fails once (provisioning crash)
	MemberHits int
}

func NewEngine() *Engine {
	return &Engine{Users: map[uuid.UUID]string{}, Members: map[uuid.UUID]*auth.Member{}, Workspaces: map[uuid.UUID]auth.Workspace{}}
}

// AddMember adds a membership and returns its id.
func (e *Engine) AddMember(ws, user uuid.UUID, role, typ string) uuid.UUID {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.Workspaces[ws]; !ok {
		e.Workspaces[ws] = auth.Workspace{ID: ws, Name: "ws-" + ws.String()[:4], Slug: "ws-" + ws.String()[:4]}
	}
	id := uuid.New()
	e.Members[id] = &auth.Member{ID: id, WorkspaceID: ws, UserID: user, Type: typ, Role: role, Status: auth.MemberActive}
	return id
}

// SetMember changes a member's role and/or status.
func (e *Engine) SetMember(id uuid.UUID, role, status string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if role != "" {
		e.Members[id].Role = role
	}
	if status != "" {
		e.Members[id].Status = status
	}
}

func (e *Engine) RemoveMember(id uuid.UUID) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.Members, id)
}

func (e *Engine) Member(_ context.Context, ws, id uuid.UUID) (auth.Member, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.MemberHits++
	if e.Down {
		return auth.Member{}, auth.ErrEngineUnavailable
	}
	m, ok := e.Members[id]
	if !ok || m.WorkspaceID != ws {
		return auth.Member{}, auth.ErrEngineNotFound
	}
	return *m, nil
}

func (e *Engine) Memberships(_ context.Context, user uuid.UUID) ([]auth.Membership, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.Down {
		return nil, auth.ErrEngineUnavailable
	}
	if _, ok := e.Users[user]; !ok {
		return nil, auth.ErrEngineNotFound
	}
	var out []auth.Membership
	for _, m := range e.Members {
		if m.UserID == user {
			w := e.Workspaces[m.WorkspaceID]
			out = append(out, auth.Membership{MemberID: m.ID, WorkspaceID: m.WorkspaceID, WorkspaceName: w.Name,
				WorkspaceSlug: w.Slug, UserID: user, Type: m.Type, Role: m.Role, Status: m.Status})
		}
	}
	return out, nil
}

func (e *Engine) FindUserByEmail(_ context.Context, email string) (uuid.UUID, bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.Down {
		return uuid.Nil, false, auth.ErrEngineUnavailable
	}
	for id, em := range e.Users {
		if em == email {
			return id, true, nil
		}
	}
	return uuid.Nil, false, nil
}

func (e *Engine) CreateUser(_ context.Context, email, _ string) (uuid.UUID, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.Down {
		return uuid.Nil, auth.ErrEngineUnavailable
	}
	if e.FailCreate {
		e.FailCreate = false
		return uuid.Nil, auth.ErrEngineUnavailable
	}
	for _, em := range e.Users {
		if em == email {
			return uuid.Nil, auth.ErrEngineConflict
		}
	}
	id := uuid.New()
	e.Users[id] = email
	return id, nil
}

func (e *Engine) CreateWorkspace(_ context.Context, name, slug string, owner uuid.UUID) (auth.Workspace, error) {
	e.mu.Lock()
	if e.Down {
		e.mu.Unlock()
		return auth.Workspace{}, auth.ErrEngineUnavailable
	}
	for _, w := range e.Workspaces {
		if w.Slug == slug {
			e.mu.Unlock()
			return auth.Workspace{}, auth.ErrEngineConflict
		}
	}
	w := auth.Workspace{ID: uuid.New(), Name: name, Slug: slug}
	e.Workspaces[w.ID] = w
	e.mu.Unlock()
	e.AddMember(w.ID, owner, string(auth.RoleOwner), auth.MemberTypeHuman)
	return w, nil
}

func (e *Engine) UpdateUserEmail(_ context.Context, user uuid.UUID, email string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	for id, em := range e.Users {
		if em == email && id != user {
			return auth.ErrEngineConflict
		}
	}
	e.Users[user] = email
	return nil
}

func (e *Engine) DeleteUser(_ context.Context, user uuid.UUID) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, m := range e.Members {
		if m.UserID == user && m.Role == string(auth.RoleOwner) {
			owners := 0
			for _, o := range e.Members {
				if o.WorkspaceID == m.WorkspaceID && o.Role == string(auth.RoleOwner) && o.Status == auth.MemberActive {
					owners++
				}
			}
			if owners <= 1 {
				return auth.ErrEngineLastOwner
			}
		}
	}
	delete(e.Users, user)
	return nil
}

// Mailer records the last token sent per kind+address.
type Mailer struct {
	mu   sync.Mutex
	Sent map[string]string // "kind:email" -> token ("" for notices)
}

func NewMailer() *Mailer { return &Mailer{Sent: map[string]string{}} }

func (m *Mailer) put(kind, email, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Sent[kind+":"+strings.ToLower(email)] = token
	return nil
}

func (m *Mailer) Token(kind, email string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.Sent[kind+":"+email]
}

func (m *Mailer) Has(kind, email string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.Sent[kind+":"+email]
	return ok
}

func (m *Mailer) SendVerification(_ context.Context, e, t string) error { return m.put("verify", e, t) }
func (m *Mailer) SendSignupOnExisting(_ context.Context, e string) error {
	return m.put("existing", e, "")
}
func (m *Mailer) SendPasswordReset(_ context.Context, e, t string) error { return m.put("reset", e, t) }
func (m *Mailer) SendEmailChange(_ context.Context, e, t string) error   { return m.put("email", e, t) }
func (m *Mailer) SendEmailChangedNotice(_ context.Context, e string) error {
	return m.put("emailnotice", e, "")
}
