package auth

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Service errors, mapped to HTTP by the handlers.
var (
	ErrInvalidCredentials  = errors.New("invalid credentials")
	ErrTooManyAttempts     = errors.New("too many attempts")
	ErrAccountProvisioning = errors.New("account setup is still finishing")
	ErrInvalidLink         = errors.New("invalid or expired link")
	ErrUnauthenticated     = errors.New("unauthenticated")
	ErrForbidden           = errors.New("forbidden")
	ErrNotMember           = errors.New("not an active member of that workspace")
	ErrReauthRequired      = errors.New("reauth required")
	ErrUnavailable         = errors.New("auth dependency unavailable")
	ErrEmailTaken          = errors.New("email already in use")
	ErrLastOwner           = errors.New("last owner of a workspace")
	ErrInvalidInput        = errors.New("invalid input")
)

// Config holds lifetimes. Zero values take the documented defaults.
type Config struct {
	RefreshIdleTTL     time.Duration // 7d
	SessionAbsoluteTTL time.Duration // 30d
	TicketTTL          time.Duration // 5m
	RecentAuthWindow   time.Duration // 10m
	AttemptTTL         time.Duration // 24h
	ResetTTL           time.Duration // 30m
	EmailChangeTTL     time.Duration // 24h
	ReadCacheTTL       time.Duration // 5s
	MaxAttemptsPerHour int           // 5
}

func (c *Config) defaults() {
	set := func(d *time.Duration, v time.Duration) {
		if *d == 0 {
			*d = v
		}
	}
	set(&c.RefreshIdleTTL, 7*24*time.Hour)
	set(&c.SessionAbsoluteTTL, 30*24*time.Hour)
	set(&c.TicketTTL, 5*time.Minute)
	set(&c.RecentAuthWindow, 10*time.Minute)
	set(&c.AttemptTTL, 24*time.Hour)
	set(&c.ResetTTL, 30*time.Minute)
	set(&c.EmailChangeTTL, 24*time.Hour)
	set(&c.ReadCacheTTL, 5*time.Second)
	if c.MaxAttemptsPerHour == 0 {
		c.MaxAttemptsPerHour = 5
	}
}

// Service is the single authority for passwords, sessions and tokens.
type Service struct {
	cfg    Config
	store  Store
	engine Engine
	tokens *TokenManager
	hasher *Hasher
	mailer Mailer
	cache  *memberCache
	Now    func() time.Time
}

func NewService(cfg Config, store Store, engine Engine, tokens *TokenManager, hasher *Hasher, mailer Mailer) *Service {
	cfg.defaults()
	return &Service{
		cfg: cfg, store: store, engine: engine, tokens: tokens, hasher: hasher, mailer: mailer,
		cache: newMemberCache(), Now: time.Now,
	}
}

func (s *Service) now() time.Time { return s.Now().UTC() }

// Store returns the auth store (idempotency middleware, jobs, readiness).
func (s *Service) Store() Store { return s.store }

// Config returns the effective lifetimes.
func (s *Service) Config() Config { return s.cfg }

// TokenPair is what a session issuance returns.
type TokenPair struct {
	AccessToken      string    `json:"access_token"`
	TokenType        string    `json:"token_type"`
	ExpiresAt        time.Time `json:"expires_at"`
	RefreshToken     string    `json:"refresh_token,omitempty"`
	RefreshExpiresAt time.Time `json:"refresh_expires_at"`
	WorkspaceID      uuid.UUID `json:"workspace_id"`
	MemberID         uuid.UUID `json:"member_id"`
	Role             Role      `json:"role"`
	Scope            string    `json:"scope"`
	FamilyID         uuid.UUID `json:"-"`
	LoginSessionID   uuid.UUID `json:"-"`
}

// Principal is the authenticated caller of one request.
type Principal struct {
	UserID         uuid.UUID
	MemberID       uuid.UUID
	WorkspaceID    uuid.UUID
	Role           Role
	Scopes         []string // token scopes ∩ live role scopes
	JTI            string
	FamilyID       uuid.UUID
	LoginSessionID uuid.UUID
	AuthTime       time.Time
	ExpiresAt      time.Time
}

func (p Principal) HasScope(scope string) bool { return HasScope(p.Scopes, scope) }

func (s *Service) audit(ctx context.Context, kind string, userID uuid.UUID, detail map[string]any) {
	if err := s.store.Audit(ctx, kind, userID, detail, s.now()); err != nil {
		log.Printf("auth audit %s: %v", kind, err)
	}
}

func storeErr(err error) error {
	if err == nil || errors.Is(err, ErrNotFound) {
		return err
	}
	return fmt.Errorf("%w: %v", ErrUnavailable, err)
}

// ---------------------------------------------------------------------------------------------
// Registration (docs/AUTH.md §3, §7)

// Register records a sign-up attempt and mails a verification link. It answers the same way
// whether or not the email is known, so it cannot be used to discover accounts.
func (s *Service) Register(ctx context.Context, rawEmail, password, name string) error {
	email, err := CanonicalEmail(rawEmail)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	if err := ValidatePassword(password); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 200 {
		return fmt.Errorf("%w: name must be 1 to 200 characters", ErrInvalidInput)
	}
	now := s.now()
	if cred, err := s.store.CredentialByEmail(ctx, email); err == nil {
		if cred.Status == StatusActive || cred.Status == StatusProvisioning {
			if err := s.mailer.SendSignupOnExisting(ctx, email); err != nil {
				log.Printf("mail signup-on-existing: %v", err)
			}
		}
		return nil
	} else if !errors.Is(err, ErrNotFound) {
		return storeErr(err)
	}
	n, err := s.store.CountAttemptsSince(ctx, email, now.Add(-time.Hour))
	if err != nil {
		return storeErr(err)
	}
	if n >= s.cfg.MaxAttemptsPerHour {
		return nil // silently dropped; same answer as success
	}
	hash, err := s.hasher.Hash(password)
	if err != nil {
		return err
	}
	token, tokenHash, err := NewOpaqueToken()
	if err != nil {
		return err
	}
	if err := s.store.CreateAttempt(ctx, RegistrationAttempt{
		ID: uuid.New(), Email: email, DisplayName: name, PasswordHash: hash, TokenHash: tokenHash,
		CreatedAt: now, ExpiresAt: now.Add(s.cfg.AttemptTTL),
	}); err != nil {
		return storeErr(err)
	}
	return s.mailer.SendVerification(ctx, email, token)
}

// VerifyEmail proves mailbox ownership: it turns that attempt into a credential and provisions
// the engine user. An engine failure leaves the credential provisioning for the reconciler.
func (s *Service) VerifyEmail(ctx context.Context, token string) error {
	cred, err := s.store.VerifyAttempt(ctx, HashToken(token), uuid.New(), s.now())
	switch {
	case errors.Is(err, ErrNotFound), errors.Is(err, ErrAccountExists):
		return ErrInvalidLink
	case err != nil:
		return storeErr(err)
	}
	s.audit(ctx, "email_verified", uuid.Nil, map[string]any{"credential_id": cred.ID})
	if err := s.provision(ctx, cred); err != nil {
		log.Printf("provision credential %s: %v (reconciler will retry)", cred.ID, err)
	}
	return nil
}

// provision links or creates the engine user for a provisioning credential. The canonical email
// is the natural key, so it is safe to repeat: find, else create, and a 409 means find again.
func (s *Service) provision(ctx context.Context, cred Credential) error {
	if cred.Status != StatusProvisioning {
		return nil
	}
	userID, found, err := s.engine.FindUserByEmail(ctx, cred.Email)
	if err != nil {
		return err
	}
	if !found {
		userID, err = s.engine.CreateUser(ctx, cred.Email, cred.DisplayName)
		if errors.Is(err, ErrEngineConflict) {
			userID, found, err = s.engine.FindUserByEmail(ctx, cred.Email)
			if err == nil && !found {
				err = fmt.Errorf("engine reported email taken but lookup found nothing")
			}
		}
		if err != nil {
			return err
		}
	}
	if err := s.store.ActivateCredential(ctx, cred.ID, userID, s.now()); err != nil {
		return err
	}
	s.audit(ctx, "account_activated", userID, map[string]any{"credential_id": cred.ID})
	return nil
}

// ReconcileProvisioning retries credentials stuck in provisioning for more than a minute.
func (s *Service) ReconcileProvisioning(ctx context.Context) error {
	creds, err := s.store.ListProvisioning(ctx, s.now().Add(-time.Minute), 50)
	if err != nil {
		return err
	}
	var errs []error
	for _, c := range creds {
		if err := s.provision(ctx, c); err != nil {
			errs = append(errs, fmt.Errorf("credential %s: %w", c.ID, err))
			if s.now().Sub(c.CreatedAt) > time.Hour {
				log.Printf("ALERT: credential %s provisioning for over 1h: %v", c.ID, err)
			}
		}
	}
	return errors.Join(errs...)
}

// ---------------------------------------------------------------------------------------------
// Login and session issuance (docs/AUTH.md §5)

// LoginResult is the answer to a password login: a single-use ticket and the workspaces it can
// open. Login never returns tokens directly.
type LoginResult struct {
	Ticket      string       `json:"login_ticket"`
	ExpiresAt   time.Time    `json:"login_ticket_expires_at"`
	Memberships []Membership `json:"memberships"`
}

// checkPassword verifies a password for an account, applying the progressive backoff.
func (s *Service) checkPassword(ctx context.Context, cred Credential, password string) error {
	now := s.now()
	if cred.NextAllowedAt.After(now) {
		return ErrTooManyAttempts
	}
	ok, rehash, err := s.hasher.Verify(password, cred.PasswordHash)
	if err != nil {
		return fmt.Errorf("verify password: %w", err)
	}
	if !ok {
		if err := s.store.RecordLoginFailure(ctx, cred.ID, now); err != nil {
			return storeErr(err)
		}
		return ErrInvalidCredentials
	}
	if err := s.store.RecordLoginSuccess(ctx, cred.ID, now); err != nil {
		return storeErr(err)
	}
	if rehash {
		if h, err := s.hasher.Hash(password); err == nil {
			_ = s.store.SetPasswordHash(ctx, cred.ID, h, now)
		}
	}
	return nil
}

func (s *Service) Login(ctx context.Context, rawEmail, password string) (LoginResult, error) {
	email, err := CanonicalEmail(rawEmail)
	if err != nil || len(password) > MaxPasswordLen {
		s.hasher.VerifyDummy(password)
		return LoginResult{}, ErrInvalidCredentials
	}
	cred, err := s.store.CredentialByEmail(ctx, email)
	if errors.Is(err, ErrNotFound) {
		s.hasher.VerifyDummy(password)
		return LoginResult{}, ErrInvalidCredentials
	}
	if err != nil {
		return LoginResult{}, storeErr(err)
	}
	if cred.Status == StatusDisabled || cred.Status == StatusDeleted {
		s.hasher.VerifyDummy(password)
		return LoginResult{}, ErrInvalidCredentials
	}
	if err := s.checkPassword(ctx, cred, password); err != nil {
		return LoginResult{}, err
	}
	if cred.Status == StatusProvisioning {
		if err := s.provision(ctx, cred); err != nil {
			return LoginResult{}, ErrAccountProvisioning
		}
		if cred, err = s.store.CredentialByID(ctx, cred.ID); err != nil {
			return LoginResult{}, storeErr(err)
		}
	}
	if cred.Status != StatusActive {
		return LoginResult{}, ErrAccountProvisioning
	}
	ms, err := s.humanMemberships(ctx, cred.UserID)
	if err != nil {
		return LoginResult{}, err
	}
	now := s.now()
	token, hash, err := NewOpaqueToken()
	if err != nil {
		return LoginResult{}, err
	}
	t := LoginTicket{
		Hash: hash, CredentialID: cred.ID, UserID: cred.UserID, AuthVersion: cred.AuthVersion,
		AuthTime: now, CreatedAt: now, ExpiresAt: now.Add(s.cfg.TicketTTL),
	}
	if err := s.store.CreateTicket(ctx, t); err != nil {
		return LoginResult{}, storeErr(err)
	}
	s.audit(ctx, "login", cred.UserID, nil)
	return LoginResult{Ticket: token, ExpiresAt: t.ExpiresAt, Memberships: ms}, nil
}

// humanMemberships lists the user's active HUMAN memberships with a known role.
func (s *Service) humanMemberships(ctx context.Context, userID uuid.UUID) ([]Membership, error) {
	all, err := s.engine.Memberships(ctx, userID)
	if err != nil {
		if errors.Is(err, ErrEngineNotFound) {
			return nil, ErrUnauthenticated
		}
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	out := make([]Membership, 0, len(all))
	for _, m := range all {
		if _, ok := ParseRole(m.Role); ok && m.Type == MemberTypeHuman && m.Status == MemberActive && m.UserID == userID {
			out = append(out, m)
		}
	}
	return out, nil
}

// consumeTicket validates a login ticket for a still-active account and opens a login session.
func (s *Service) consumeTicket(ctx context.Context, ticket string) (Credential, LoginSession, error) {
	now := s.now()
	t, err := s.store.ConsumeTicket(ctx, HashToken(ticket), now)
	if errors.Is(err, ErrNotFound) {
		return Credential{}, LoginSession{}, ErrUnauthenticated
	}
	if err != nil {
		return Credential{}, LoginSession{}, storeErr(err)
	}
	cred, err := s.store.CredentialByID(ctx, t.CredentialID)
	if err != nil {
		return Credential{}, LoginSession{}, storeErr(err)
	}
	if cred.Status != StatusActive || cred.AuthVersion != t.AuthVersion || cred.UserID != t.UserID {
		return Credential{}, LoginSession{}, ErrUnauthenticated
	}
	ls := LoginSession{
		ID: uuid.New(), CredentialID: cred.ID, UserID: cred.UserID, AuthVersion: cred.AuthVersion,
		AuthTime: t.AuthTime, CreatedAt: now, AbsoluteExpiresAt: t.AuthTime.Add(s.cfg.SessionAbsoluteTTL),
	}
	if err := s.store.CreateLoginSession(ctx, ls); err != nil {
		return Credential{}, LoginSession{}, storeErr(err)
	}
	return cred, ls, nil
}

// issueSession is the one canonical way a workspace-bound token pair is created: login ticket
// exchange, first-workspace creation, switch and password change all call it.
func (s *Service) issueSession(ctx context.Context, cred Credential, ls LoginSession, workspaceID uuid.UUID) (TokenPair, error) {
	ms, err := s.humanMemberships(ctx, cred.UserID)
	if err != nil {
		return TokenPair{}, err
	}
	var m *Membership
	for i := range ms {
		if ms[i].WorkspaceID == workspaceID {
			m = &ms[i]
			break
		}
	}
	if m == nil {
		return TokenPair{}, ErrNotMember
	}
	role, _ := ParseRole(m.Role)
	scopes := ScopesForRole(role)
	now := s.now()
	access, err := s.tokens.IssueHuman(m.MemberID.String(), workspaceID.String(), scopes)
	if err != nil {
		return TokenPair{}, err
	}
	refresh, refreshHash, err := NewOpaqueToken()
	if err != nil {
		return TokenPair{}, err
	}
	fam := RefreshFamily{
		ID: uuid.New(), LoginSessionID: ls.ID, UserID: cred.UserID, WorkspaceID: workspaceID,
		MemberID: m.MemberID, AuthVersion: cred.AuthVersion, CreatedAt: now,
		IdleExpiresAt: minTime(now.Add(s.cfg.RefreshIdleTTL), ls.AbsoluteExpiresAt),
	}
	rt := RefreshToken{ID: uuid.New(), FamilyID: fam.ID, Generation: 0, Hash: refreshHash, CreatedAt: now}
	ar := AccessRecord{JTI: access.JTI, FamilyID: fam.ID, AuthVersion: cred.AuthVersion, IssuedAt: access.IssuedAt, ExpiresAt: access.ExpiresAt}
	if err := s.store.CreateFamily(ctx, fam, rt, ar); err != nil {
		return TokenPair{}, storeErr(err)
	}
	return TokenPair{
		AccessToken: access.Token, TokenType: "Bearer", ExpiresAt: access.ExpiresAt,
		RefreshToken: refresh, RefreshExpiresAt: fam.IdleExpiresAt,
		WorkspaceID: workspaceID, MemberID: m.MemberID, Role: role, Scope: JoinScopes(scopes), FamilyID: fam.ID,
		LoginSessionID: ls.ID,
	}, nil
}

// CreateSession exchanges a login ticket for a session in one workspace.
func (s *Service) CreateSession(ctx context.Context, ticket string, workspaceID uuid.UUID) (TokenPair, error) {
	cred, ls, err := s.consumeTicket(ctx, ticket)
	if err != nil {
		return TokenPair{}, err
	}
	pair, err := s.issueSession(ctx, cred, ls, workspaceID)
	if err != nil {
		_ = s.store.RevokeLoginSession(ctx, ls.ID, "session_issue_failed", s.now())
		return TokenPair{}, err
	}
	return pair, nil
}

// CreateFirstWorkspace creates a workspace owned by the ticket's user (the engine adds the owner
// member in the same transaction) and opens a session in it.
func (s *Service) CreateFirstWorkspace(ctx context.Context, ticket, name, slug string) (Workspace, TokenPair, error) {
	cred, ls, err := s.consumeTicket(ctx, ticket)
	if err != nil {
		return Workspace{}, TokenPair{}, err
	}
	ws, err := s.engine.CreateWorkspace(ctx, name, slug, cred.UserID)
	if err != nil {
		_ = s.store.RevokeLoginSession(ctx, ls.ID, "workspace_create_failed", s.now())
		if errors.Is(err, ErrEngineConflict) {
			return Workspace{}, TokenPair{}, ErrInvalidInput
		}
		return Workspace{}, TokenPair{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	s.audit(ctx, "workspace_created", cred.UserID, map[string]any{"workspace_id": ws.ID})
	pair, err := s.issueSession(ctx, cred, ls, ws.ID)
	return ws, pair, err
}

// ---------------------------------------------------------------------------------------------
// Refresh, switch, logout (docs/AUTH.md §4, §6)

// liveRefresh loads a refresh token and checks everything except reuse.
func (s *Service) liveRefresh(ctx context.Context, token string) (RefreshToken, RefreshFamily, LoginSession, Credential, error) {
	rt, fam, ls, cred, err := s.store.RefreshByHash(ctx, HashToken(token))
	if errors.Is(err, ErrNotFound) {
		return rt, fam, ls, cred, ErrUnauthenticated
	}
	if err != nil {
		return rt, fam, ls, cred, storeErr(err)
	}
	now := s.now()
	if rt.UsedAt != nil {
		_ = s.store.RevokeFamily(ctx, fam.ID, "refresh_reused", now)
		s.audit(ctx, "refresh_reused", fam.UserID, map[string]any{"family_id": fam.ID, "generation": rt.Generation})
		return rt, fam, ls, cred, ErrRefreshReused
	}
	if fam.RevokedAt != nil || !fam.IdleExpiresAt.After(now) ||
		ls.RevokedAt != nil || !ls.AbsoluteExpiresAt.After(now) ||
		cred.Status != StatusActive || fam.AuthVersion != cred.AuthVersion || ls.AuthVersion != cred.AuthVersion {
		return rt, fam, ls, cred, ErrUnauthenticated
	}
	return rt, fam, ls, cred, nil
}

// Refresh rotates a refresh token (strict reuse detection, no grace window) and re-reads the live
// membership, so suspension or removal ends the session and role changes apply.
func (s *Service) Refresh(ctx context.Context, token string) (TokenPair, error) {
	rt, fam, ls, cred, err := s.liveRefresh(ctx, token)
	if err != nil {
		return TokenPair{}, err
	}
	member, role, err := s.checkMember(ctx, fam, false)
	if err != nil {
		return TokenPair{}, err
	}
	scopes := ScopesForRole(role)
	now := s.now()
	access, err := s.tokens.IssueHuman(member.ID.String(), fam.WorkspaceID.String(), scopes)
	if err != nil {
		return TokenPair{}, err
	}
	next, nextHash, err := NewOpaqueToken()
	if err != nil {
		return TokenPair{}, err
	}
	idle := minTime(now.Add(s.cfg.RefreshIdleTTL), ls.AbsoluteExpiresAt)
	nrt := RefreshToken{ID: uuid.New(), FamilyID: fam.ID, Generation: rt.Generation + 1, Hash: nextHash, CreatedAt: now}
	ar := AccessRecord{JTI: access.JTI, FamilyID: fam.ID, AuthVersion: cred.AuthVersion, IssuedAt: access.IssuedAt, ExpiresAt: access.ExpiresAt}
	if err := s.store.Rotate(ctx, rt, nrt, ar, idle, now); err != nil {
		if errors.Is(err, ErrRefreshReused) {
			s.audit(ctx, "refresh_reused", fam.UserID, map[string]any{"family_id": fam.ID, "generation": rt.Generation})
			return TokenPair{}, ErrRefreshReused
		}
		if errors.Is(err, ErrNotFound) {
			return TokenPair{}, ErrUnauthenticated
		}
		return TokenPair{}, storeErr(err)
	}
	return TokenPair{
		AccessToken: access.Token, TokenType: "Bearer", ExpiresAt: access.ExpiresAt,
		RefreshToken: next, RefreshExpiresAt: idle, WorkspaceID: fam.WorkspaceID, MemberID: member.ID,
		Role: role, Scope: JoinScopes(scopes), FamilyID: fam.ID, LoginSessionID: ls.ID,
	}, nil
}

// Switch opens a session in another workspace from a valid refresh token (not an access token,
// so a stolen access token alone cannot jump workspaces). The new family shares the login
// session; the old family stays usable.
func (s *Service) Switch(ctx context.Context, token string, workspaceID uuid.UUID) (TokenPair, error) {
	_, _, ls, cred, err := s.liveRefresh(ctx, token)
	if err != nil {
		return TokenPair{}, err
	}
	return s.issueSession(ctx, cred, ls, workspaceID)
}

// LoginSessionForRefresh returns the login session of a refresh token (the CSRF token is bound
// to it, so it survives rotation and switching but not a new login).
func (s *Service) LoginSessionForRefresh(ctx context.Context, token string) (uuid.UUID, error) {
	_, fam, _, _, err := s.store.RefreshByHash(ctx, HashToken(token))
	if err != nil {
		return uuid.Nil, ErrUnauthenticated
	}
	return fam.LoginSessionID, nil
}

// Logout revokes the refresh token's family. It needs only the refresh token, so it works with
// an expired access token, and it is idempotent. A still-valid access token is revoked too.
func (s *Service) Logout(ctx context.Context, refreshToken, accessToken string) error {
	now := s.now()
	if refreshToken != "" {
		if _, fam, _, _, err := s.store.RefreshByHash(ctx, HashToken(refreshToken)); err == nil {
			if err := s.store.RevokeFamily(ctx, fam.ID, "logout", now); err != nil {
				return storeErr(err)
			}
			s.audit(ctx, "logout", fam.UserID, map[string]any{"family_id": fam.ID})
		} else if !errors.Is(err, ErrNotFound) {
			return storeErr(err)
		}
	}
	if accessToken != "" {
		if c, err := s.tokens.Verify(accessToken); err == nil {
			_ = s.store.RevokeAccessToken(ctx, c.ID, now)
		}
	}
	return nil
}

// LogoutAll ends every session of the account: auth_version moves, so every access token dies on
// its next request. The route requires recent authentication.
func (s *Service) LogoutAll(ctx context.Context, p Principal) error {
	if err := s.RequireRecent(p); err != nil {
		return err
	}
	cred, err := s.store.CredentialByUserID(ctx, p.UserID)
	if err != nil {
		return storeErr(err)
	}
	if _, err := s.store.UpdateAccount(ctx, cred.ID, AccountUpdate{BumpVersion: true, Reason: "logout_all"}, s.now()); err != nil {
		return storeErr(err)
	}
	s.audit(ctx, "logout_all", p.UserID, nil)
	return nil
}

// RevokeLoginSession signs out one device (all its workspaces).
func (s *Service) RevokeLoginSession(ctx context.Context, p Principal) error {
	return storeErr(s.store.RevokeLoginSession(ctx, p.LoginSessionID, "device_logout", s.now()))
}

// ---------------------------------------------------------------------------------------------
// Per-request authentication (docs/AUTH.md §1-2, §6)

// Authenticate turns a bearer access token into a Principal. write=true bypasses the membership
// read cache. It fails closed: any dependency error is ErrUnavailable.
func (s *Service) Authenticate(ctx context.Context, raw string, write bool) (Principal, error) {
	claims, err := s.tokens.Verify(raw)
	if err != nil {
		return Principal{}, ErrUnauthenticated
	}
	st, err := s.store.AccessState(ctx, claims.ID)
	if errors.Is(err, ErrNotFound) {
		return Principal{}, ErrUnauthenticated
	}
	if err != nil {
		return Principal{}, storeErr(err)
	}
	now := s.now()
	a, fam, ls, cred := st.Access, st.Family, st.Session, st.Credential
	if a.RevokedAt != nil || !a.ExpiresAt.After(now) ||
		fam.RevokedAt != nil || ls.RevokedAt != nil || !ls.AbsoluteExpiresAt.After(now) ||
		cred.Status != StatusActive || a.AuthVersion != cred.AuthVersion ||
		fam.WorkspaceID.String() != claims.WorkspaceID || fam.MemberID.String() != claims.MemberID {
		return Principal{}, ErrUnauthenticated
	}
	member, role, err := s.checkMember(ctx, fam, !write)
	if err != nil {
		return Principal{}, err
	}
	return Principal{
		UserID: cred.UserID, MemberID: member.ID, WorkspaceID: fam.WorkspaceID, Role: role,
		Scopes: Intersect(claims.Scopes(), ScopesForRole(role)), JTI: claims.ID,
		FamilyID: fam.ID, LoginSessionID: ls.ID, AuthTime: ls.AuthTime, ExpiresAt: a.ExpiresAt,
	}, nil
}

// checkMember loads the live member and verifies it is the session's: same id, workspace and
// user, HUMAN, active, known role. A mismatch revokes the family.
func (s *Service) checkMember(ctx context.Context, fam RefreshFamily, allowCache bool) (Member, Role, error) {
	var m Member
	var err error
	if allowCache {
		if cached, ok := s.cache.get(fam.WorkspaceID, fam.MemberID, s.now()); ok {
			m = cached
		}
	}
	if m.ID == uuid.Nil {
		m, err = s.engine.Member(ctx, fam.WorkspaceID, fam.MemberID)
		if errors.Is(err, ErrEngineNotFound) {
			_ = s.store.RevokeFamily(ctx, fam.ID, "member_gone", s.now())
			return Member{}, "", ErrUnauthenticated
		}
		if err != nil {
			return Member{}, "", fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
		s.cache.put(m, s.now().Add(s.cfg.ReadCacheTTL))
	}
	if m.ID != fam.MemberID || m.WorkspaceID != fam.WorkspaceID || m.UserID != fam.UserID ||
		m.Type != MemberTypeHuman || m.Status != MemberActive {
		_ = s.store.RevokeFamily(ctx, fam.ID, "member_inactive_or_mismatch", s.now())
		s.cache.invalidate(fam.WorkspaceID, fam.MemberID)
		return Member{}, "", ErrUnauthenticated
	}
	role, ok := ParseRole(m.Role)
	if !ok {
		return Member{}, "", ErrForbidden
	}
	return m, role, nil
}

// InvalidateMember drops the cached membership. The member and workspace services call it after
// every role or status change they make, so reads see the change at once.
func (s *Service) InvalidateMember(workspaceID, memberID uuid.UUID) {
	s.cache.invalidate(workspaceID, memberID)
}

// RevokeMemberSessions ends every session bound to a member (suspension or removal).
func (s *Service) RevokeMemberSessions(ctx context.Context, workspaceID, memberID uuid.UUID, reason string) error {
	s.cache.invalidate(workspaceID, memberID)
	return storeErr(s.store.RevokeMemberFamilies(ctx, workspaceID, memberID, reason, s.now()))
}

// RevokeWorkspaceSessions ends every session bound to a workspace (workspace deleted) and drops
// its cached memberships, so even reads fail on the next request.
func (s *Service) RevokeWorkspaceSessions(ctx context.Context, workspaceID uuid.UUID, reason string) error {
	s.cache.invalidateWorkspace(workspaceID)
	return storeErr(s.store.RevokeWorkspaceFamilies(ctx, workspaceID, reason, s.now()))
}

// RequireRecent enforces docs/AUTH.md §10: the login session's password check must be newer
// than the recent-auth window. Refresh and switch never move auth_time.
func (s *Service) RequireRecent(p Principal) error {
	if p.AuthTime.IsZero() || s.now().Sub(p.AuthTime) > s.cfg.RecentAuthWindow {
		return ErrReauthRequired
	}
	return nil
}

// Memberships lists the caller's own active memberships (workspace switcher).
func (s *Service) Memberships(ctx context.Context, userID uuid.UUID) ([]Membership, error) {
	return s.humanMemberships(ctx, userID)
}

// ---------------------------------------------------------------------------------------------
// Password and account lifecycle (docs/AUTH.md §7, §10, §12)

// Reauth re-verifies the password and moves the login session's auth_time to now.
func (s *Service) Reauth(ctx context.Context, p Principal, password string) error {
	cred, err := s.store.CredentialByUserID(ctx, p.UserID)
	if err != nil {
		return storeErr(err)
	}
	if err := s.checkPassword(ctx, cred, password); err != nil {
		return err
	}
	return storeErr(s.store.SetAuthTime(ctx, p.LoginSessionID, s.now()))
}

// ChangePassword needs the current password. Every session of the account ends; the caller gets
// a fresh pair in the current workspace.
func (s *Service) ChangePassword(ctx context.Context, p Principal, current, next string) (TokenPair, error) {
	if err := ValidatePassword(next); err != nil {
		return TokenPair{}, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	cred, err := s.store.CredentialByUserID(ctx, p.UserID)
	if err != nil {
		return TokenPair{}, storeErr(err)
	}
	if err := s.checkPassword(ctx, cred, current); err != nil {
		return TokenPair{}, err
	}
	hash, err := s.hasher.Hash(next)
	if err != nil {
		return TokenPair{}, err
	}
	now := s.now()
	cred, err = s.store.UpdateAccount(ctx, cred.ID, AccountUpdate{PasswordHash: &hash, BumpVersion: true, ResetFailures: true, Reason: "password_change"}, now)
	if err != nil {
		return TokenPair{}, storeErr(err)
	}
	s.audit(ctx, "password_changed", p.UserID, nil)
	ls := LoginSession{
		ID: uuid.New(), CredentialID: cred.ID, UserID: cred.UserID, AuthVersion: cred.AuthVersion,
		AuthTime: now, CreatedAt: now, AbsoluteExpiresAt: now.Add(s.cfg.SessionAbsoluteTTL),
	}
	if err := s.store.CreateLoginSession(ctx, ls); err != nil {
		return TokenPair{}, storeErr(err)
	}
	return s.issueSession(ctx, cred, ls, p.WorkspaceID)
}

// ForgotPassword mails a reset link if the account exists. Same answer either way.
func (s *Service) ForgotPassword(ctx context.Context, rawEmail string) error {
	email, err := CanonicalEmail(rawEmail)
	if err != nil {
		return nil
	}
	cred, err := s.store.CredentialByEmail(ctx, email)
	if err != nil || cred.Status != StatusActive {
		return nil
	}
	token, hash, err := NewOpaqueToken()
	if err != nil {
		return err
	}
	now := s.now()
	if err := s.store.CreatePasswordReset(ctx, hash, cred.ID, now, now.Add(s.cfg.ResetTTL)); err != nil {
		return storeErr(err)
	}
	return s.mailer.SendPasswordReset(ctx, email, token)
}

// ResetPassword consumes a reset link, sets the password and ends every session.
func (s *Service) ResetPassword(ctx context.Context, token, next string) error {
	if err := ValidatePassword(next); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	credID, err := s.store.ConsumePasswordReset(ctx, HashToken(token), s.now())
	if errors.Is(err, ErrNotFound) {
		return ErrInvalidLink
	}
	if err != nil {
		return storeErr(err)
	}
	hash, err := s.hasher.Hash(next)
	if err != nil {
		return err
	}
	cred, err := s.store.UpdateAccount(ctx, credID, AccountUpdate{PasswordHash: &hash, BumpVersion: true, ResetFailures: true, Reason: "password_reset"}, s.now())
	if err != nil {
		return storeErr(err)
	}
	s.audit(ctx, "password_reset", cred.UserID, nil)
	return nil
}

// RequestEmailChange mails a confirmation link to the new address (route needs recent auth).
func (s *Service) RequestEmailChange(ctx context.Context, p Principal, rawEmail string) error {
	if err := s.RequireRecent(p); err != nil {
		return err
	}
	email, err := CanonicalEmail(rawEmail)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	if _, err := s.store.CredentialByEmail(ctx, email); err == nil {
		return nil // taken: same answer, no mail
	} else if !errors.Is(err, ErrNotFound) {
		return storeErr(err)
	}
	cred, err := s.store.CredentialByUserID(ctx, p.UserID)
	if err != nil {
		return storeErr(err)
	}
	token, hash, err := NewOpaqueToken()
	if err != nil {
		return err
	}
	now := s.now()
	if err := s.store.CreateEmailChange(ctx, hash, cred.ID, email, now, now.Add(s.cfg.EmailChangeTTL)); err != nil {
		return storeErr(err)
	}
	return s.mailer.SendEmailChange(ctx, email, token)
}

// ConfirmEmailChange applies a verified new address: engine first (its unique index decides),
// then the credential with an auth_version bump, then a notice to the old address.
func (s *Service) ConfirmEmailChange(ctx context.Context, token string) error {
	credID, email, err := s.store.ConsumeEmailChange(ctx, HashToken(token), s.now())
	if errors.Is(err, ErrNotFound) {
		return ErrInvalidLink
	}
	if err != nil {
		return storeErr(err)
	}
	cred, err := s.store.CredentialByID(ctx, credID)
	if err != nil {
		return storeErr(err)
	}
	if err := s.engine.UpdateUserEmail(ctx, cred.UserID, email); err != nil {
		if errors.Is(err, ErrEngineConflict) {
			return ErrEmailTaken
		}
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if _, err := s.store.UpdateAccount(ctx, credID, AccountUpdate{Email: &email, BumpVersion: true, Reason: "email_change"}, s.now()); err != nil {
		if errors.Is(err, ErrAccountExists) {
			return ErrEmailTaken
		}
		return storeErr(err)
	}
	s.audit(ctx, "email_changed", cred.UserID, nil)
	if err := s.mailer.SendEmailChangedNotice(ctx, cred.Email); err != nil {
		log.Printf("mail email-changed notice: %v", err)
	}
	return nil
}

// LastOwnerError lists the workspaces blocking an account deletion.
type LastOwnerError struct{ Workspaces []Membership }

func (e *LastOwnerError) Error() string { return ErrLastOwner.Error() }
func (e *LastOwnerError) Unwrap() error { return ErrLastOwner }

// DeleteAccount deletes the engine user (the engine refuses if they are a workspace's last owner)
// and closes the credential.
func (s *Service) DeleteAccount(ctx context.Context, p Principal) error {
	if err := s.RequireRecent(p); err != nil {
		return err
	}
	return s.deleteAccount(ctx, p.UserID)
}

// DeleteAccountWithTicket deletes the account using a fresh login ticket instead of a workspace
// session. Every access token is bound to a workspace, so a user who has no workspace left (they
// deleted their last one, or were removed everywhere) has no other way in. The ticket proves a
// password check within the last 5 minutes, which is stricter than the recent-auth window.
func (s *Service) DeleteAccountWithTicket(ctx context.Context, ticket string) error {
	t, err := s.store.ConsumeTicket(ctx, HashToken(ticket), s.now())
	if errors.Is(err, ErrNotFound) {
		return ErrUnauthenticated
	}
	if err != nil {
		return storeErr(err)
	}
	cred, err := s.store.CredentialByID(ctx, t.CredentialID)
	if err != nil {
		return storeErr(err)
	}
	if cred.Status != StatusActive || cred.AuthVersion != t.AuthVersion || cred.UserID != t.UserID {
		return ErrUnauthenticated
	}
	return s.deleteAccount(ctx, cred.UserID)
}

func (s *Service) deleteAccount(ctx context.Context, userID uuid.UUID) error {
	p := Principal{UserID: userID}
	if err := s.engine.DeleteUser(ctx, p.UserID); err != nil {
		if errors.Is(err, ErrEngineLastOwner) || errors.Is(err, ErrEngineConflict) {
			ms, _ := s.humanMemberships(ctx, p.UserID)
			var owned []Membership
			for _, m := range ms {
				if m.Role == string(RoleOwner) {
					owned = append(owned, m)
				}
			}
			return &LastOwnerError{Workspaces: owned}
		}
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	cred, err := s.store.CredentialByUserID(ctx, p.UserID)
	if err != nil {
		return storeErr(err)
	}
	deleted := StatusDeleted
	if _, err := s.store.UpdateAccount(ctx, cred.ID, AccountUpdate{Status: &deleted, BumpVersion: true, Reason: "account_deleted"}, s.now()); err != nil {
		return storeErr(err)
	}
	s.audit(ctx, "account_deleted", p.UserID, nil)
	return nil
}

// ---------------------------------------------------------------------------------------------

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

type memberKey struct{ ws, mem uuid.UUID }

type memberEntry struct {
	m   Member
	exp time.Time
}

// memberCache is the ≤5s read cache for live membership. Writes never use it, and the backend
// invalidates entries synchronously when it changes a role or status.
type memberCache struct {
	mu sync.Mutex
	m  map[memberKey]memberEntry
}

func newMemberCache() *memberCache { return &memberCache{m: map[memberKey]memberEntry{}} }

func (c *memberCache) get(ws, mem uuid.UUID, now time.Time) (Member, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[memberKey{ws, mem}]
	if !ok || !e.exp.After(now) {
		return Member{}, false
	}
	return e.m, true
}

func (c *memberCache) put(m Member, exp time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) > 10000 {
		c.m = map[memberKey]memberEntry{}
	}
	c.m[memberKey{m.WorkspaceID, m.ID}] = memberEntry{m, exp}
}

func (c *memberCache) invalidateWorkspace(ws uuid.UUID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.m {
		if k.ws == ws {
			delete(c.m, k)
		}
	}
}

func (c *memberCache) invalidate(ws, mem uuid.UUID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, memberKey{ws, mem})
}
