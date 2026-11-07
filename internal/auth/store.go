package auth

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

// Store errors.
var (
	ErrNotFound       = errors.New("not found")
	ErrAccountExists  = errors.New("account already exists")
	ErrRefreshReused  = errors.New("refresh token reused")
	ErrIdempotencyHit = errors.New("idempotency key already used")
)

type CredentialStatus string

const (
	StatusProvisioning CredentialStatus = "provisioning"
	StatusActive       CredentialStatus = "active"
	StatusDisabled     CredentialStatus = "disabled"
	StatusDeleted      CredentialStatus = "deleted"
)

// Credential is a login identity. It exists only after the email was proven (docs/AUTH.md §3).
type Credential struct {
	ID                    uuid.UUID
	UserID                uuid.UUID // uuid.Nil while provisioning
	Email                 string    // canonical
	DisplayName           string
	PasswordHash          string
	Status                CredentialStatus
	AuthVersion           int
	ProvisioningAttemptID uuid.UUID
	FailedAttempts        int
	NextAllowedAt         time.Time
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

// RegistrationAttempt is one unverified sign-up. Several may exist per email; only the one whose
// link is clicked becomes the credential, with its own password.
type RegistrationAttempt struct {
	ID           uuid.UUID
	Email        string
	DisplayName  string
	PasswordHash string
	TokenHash    []byte
	CreatedAt    time.Time
	ExpiresAt    time.Time
}

// LoginTicket is the single-use, 5-minute result of a password login. It is not a JWT.
type LoginTicket struct {
	Hash         []byte
	CredentialID uuid.UUID
	UserID       uuid.UUID
	AuthVersion  int
	AuthTime     time.Time
	CreatedAt    time.Time
	ExpiresAt    time.Time
}

// LoginSession is one password login on one device. AuthTime changes only when a password is
// verified again (/auth/reauth), never on refresh or switch.
type LoginSession struct {
	ID                uuid.UUID
	CredentialID      uuid.UUID
	UserID            uuid.UUID
	AuthVersion       int
	AuthTime          time.Time
	CreatedAt         time.Time
	AbsoluteExpiresAt time.Time
	RevokedAt         *time.Time
}

// RefreshFamily is one workspace session inside a login session.
type RefreshFamily struct {
	ID             uuid.UUID
	LoginSessionID uuid.UUID
	UserID         uuid.UUID
	WorkspaceID    uuid.UUID
	MemberID       uuid.UUID
	AuthVersion    int
	CreatedAt      time.Time
	IdleExpiresAt  time.Time
	RevokedAt      *time.Time
}

type RefreshToken struct {
	ID         uuid.UUID
	FamilyID   uuid.UUID
	Generation int
	Hash       []byte
	CreatedAt  time.Time
	UsedAt     *time.Time
}

// AccessRecord registers an issued access token so every revocation level applies on the next
// request (docs/AUTH.md §1-2).
type AccessRecord struct {
	JTI         string
	FamilyID    uuid.UUID
	AuthVersion int
	IssuedAt    time.Time
	ExpiresAt   time.Time
	RevokedAt   *time.Time
}

// AccessState is everything needed to decide whether an access token is still valid, loaded
// with one indexed query.
type AccessState struct {
	Access     AccessRecord
	Family     RefreshFamily
	Session    LoginSession
	Credential Credential
}

// AccountUpdate changes a credential and, with BumpVersion, revokes every session of the account
// in the same transaction (account-wide revocation).
type AccountUpdate struct {
	PasswordHash  *string
	Email         *string
	Status        *CredentialStatus
	ResetFailures bool
	BumpVersion   bool
	Reason        string
}

type IdempotencyRecord struct {
	Key          string
	UserID       uuid.UUID
	Route        string
	RequestHash  []byte
	StatusCode   int
	ResponseJSON []byte
	CreatedAt    time.Time
}

// Store is the backend-owned auth database. Every method that must be atomic is one method, so
// implementations keep the transaction inside.
type Store interface {
	Ping(ctx context.Context) error

	// Registration (docs/AUTH.md §3, §7).
	CountAttemptsSince(ctx context.Context, email string, since time.Time) (int, error)
	CreateAttempt(ctx context.Context, a RegistrationAttempt) error
	// VerifyAttempt consumes the attempt with this token hash and, under a per-email lock,
	// creates a provisioning credential with that attempt's password, deleting the email's other
	// attempts. ErrNotFound: unknown, used or expired token. ErrAccountExists: the email already
	// has a credential.
	VerifyAttempt(ctx context.Context, tokenHash []byte, credID uuid.UUID, now time.Time) (Credential, error)
	ListProvisioning(ctx context.Context, olderThan time.Time, limit int) ([]Credential, error)
	ActivateCredential(ctx context.Context, credID, userID uuid.UUID, now time.Time) error

	// Credentials.
	CredentialByEmail(ctx context.Context, email string) (Credential, error)
	CredentialByUserID(ctx context.Context, userID uuid.UUID) (Credential, error)
	CredentialByID(ctx context.Context, id uuid.UUID) (Credential, error)
	// RecordLoginFailure atomically increments the failure counter and sets next_allowed_at from
	// LoginBackoff(new count).
	RecordLoginFailure(ctx context.Context, credID uuid.UUID, now time.Time) error
	RecordLoginSuccess(ctx context.Context, credID uuid.UUID, now time.Time) error
	// SetPasswordHash replaces the hash without revoking anything (parameter upgrade only).
	SetPasswordHash(ctx context.Context, credID uuid.UUID, hash string, now time.Time) error
	UpdateAccount(ctx context.Context, credID uuid.UUID, u AccountUpdate, now time.Time) (Credential, error)

	// Login tickets: single-use, consumed atomically.
	CreateTicket(ctx context.Context, t LoginTicket) error
	ConsumeTicket(ctx context.Context, hash []byte, now time.Time) (LoginTicket, error)

	// Sessions.
	CreateLoginSession(ctx context.Context, s LoginSession) error
	SetAuthTime(ctx context.Context, loginSessionID uuid.UUID, t time.Time) error
	CreateFamily(ctx context.Context, f RefreshFamily, rt RefreshToken, at AccessRecord) error
	RefreshByHash(ctx context.Context, hash []byte) (RefreshToken, RefreshFamily, LoginSession, Credential, error)
	// Rotate marks old used and inserts next and the new access token, only if old is unused and
	// the family is live. If old was already used (a concurrent or replayed refresh) it revokes
	// the whole family and returns ErrRefreshReused.
	Rotate(ctx context.Context, old RefreshToken, next RefreshToken, at AccessRecord, idleExpires time.Time, now time.Time) error
	RevokeFamily(ctx context.Context, familyID uuid.UUID, reason string, now time.Time) error
	RevokeLoginSession(ctx context.Context, id uuid.UUID, reason string, now time.Time) error
	RevokeMemberFamilies(ctx context.Context, workspaceID, memberID uuid.UUID, reason string, now time.Time) error
	RevokeWorkspaceFamilies(ctx context.Context, workspaceID uuid.UUID, reason string, now time.Time) error
	RevokeAccessToken(ctx context.Context, jti string, now time.Time) error
	AccessState(ctx context.Context, jti string) (AccessState, error)

	// Single-use links.
	CreatePasswordReset(ctx context.Context, hash []byte, credID uuid.UUID, now, expires time.Time) error
	ConsumePasswordReset(ctx context.Context, hash []byte, now time.Time) (uuid.UUID, error)
	CreateEmailChange(ctx context.Context, hash []byte, credID uuid.UUID, newEmail string, now, expires time.Time) error
	ConsumeEmailChange(ctx context.Context, hash []byte, now time.Time) (uuid.UUID, string, error)

	// Idempotency keys (24h). A key is reserved (StatusCode 0) before the request runs, so a
	// concurrent duplicate sees it in progress instead of running twice; it is completed with the
	// response on success and released on failure. A pending reservation older than a minute
	// (crashed request) or any record older than 24h may be reserved again.
	GetIdempotency(ctx context.Context, userID uuid.UUID, route, key string) (IdempotencyRecord, error)
	ReserveIdempotency(ctx context.Context, r IdempotencyRecord) error // ErrIdempotencyHit if held
	CompleteIdempotency(ctx context.Context, userID uuid.UUID, route, key string, status int, body []byte) error
	ReleaseIdempotency(ctx context.Context, userID uuid.UUID, route, key string) error

	Audit(ctx context.Context, kind string, userID uuid.UUID, detail map[string]any, now time.Time) error
	// Cleanup deletes expired rows in batches. Revoked or expired sessions are kept 7 days.
	Cleanup(ctx context.Context, now time.Time) (int64, error)
}

// LoginBackoff is the progressive per-account delay after n consecutive failures. There is no
// hard lockout, so nobody can lock another user out; the per-IP limiter covers volume.
func LoginBackoff(n int) time.Duration {
	if n < 5 {
		return 0
	}
	d := time.Second << uint(min(n-5, 10))
	return min(d, 15*time.Minute)
}
