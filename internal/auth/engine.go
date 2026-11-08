package auth

import (
	"context"
	"errors"

	"github.com/google/uuid"
)

// Engine errors, mapped from data-engine responses (docs/AUTH.md §6).
var (
	ErrEngineNotFound    = errors.New("engine: not found")
	ErrEngineConflict    = errors.New("engine: conflict")
	ErrEngineLastOwner   = errors.New("engine: last owner")
	ErrEngineUnavailable = errors.New("engine: unavailable")
)

const (
	MemberTypeHuman = "HUMAN"
	MemberActive    = "active"
)

// Member is the live engine view of one membership.
type Member struct {
	ID          uuid.UUID
	WorkspaceID uuid.UUID
	UserID      uuid.UUID // uuid.Nil for AI members
	Type        string
	Role        string
	Status      string
}

// Membership is one row of GET /users/{id}/memberships.
type Membership struct {
	MemberID      uuid.UUID `json:"member_id"`
	WorkspaceID   uuid.UUID `json:"workspace_id"`
	WorkspaceName string    `json:"workspace_name"`
	WorkspaceSlug string    `json:"workspace_slug"`
	UserID        uuid.UUID `json:"user_id"`
	Type          string    `json:"type"`
	Role          string    `json:"role"`
	Status        string    `json:"status"`
}

type Workspace struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
	Slug string    `json:"slug"`
}

// Engine is what the auth service needs from the data engine. The implementation uses the
// service key and a system identity; request handlers never get it.
type Engine interface {
	Member(ctx context.Context, workspaceID, memberID uuid.UUID) (Member, error)
	Memberships(ctx context.Context, userID uuid.UUID) ([]Membership, error)
	FindUserByEmail(ctx context.Context, email string) (uuid.UUID, bool, error)
	CreateUser(ctx context.Context, email, name string) (uuid.UUID, error)
	CreateWorkspace(ctx context.Context, name, slug string, ownerUserID uuid.UUID) (Workspace, error)
	UpdateUserEmail(ctx context.Context, userID uuid.UUID, email string) error
	DeleteUser(ctx context.Context, userID uuid.UUID) error
}

// Mailer sends account emails. Links carry the raw token; only its hash is stored.
type Mailer interface {
	SendVerification(ctx context.Context, email, token string) error
	SendSignupOnExisting(ctx context.Context, email string) error
	SendPasswordReset(ctx context.Context, email, token string) error
	SendEmailChange(ctx context.Context, newEmail, token string) error
	SendEmailChangedNotice(ctx context.Context, oldEmail string) error
}
