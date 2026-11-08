// Package authtest has in-memory fakes of the auth store, engine and mailer for tests. The
// store mirrors the Postgres store's atomic semantics with one mutex.
package authtest

import (
	"bytes"
	"context"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/Hesham127/flwnBackend/internal/auth"
)

type attempt struct {
	auth.RegistrationAttempt
	consumed bool
}

type link struct {
	credID   uuid.UUID
	email    string
	expires  time.Time
	consumed bool
}

// Store is an in-memory auth.Store.
type Store struct {
	mu          sync.Mutex
	attempts    map[uuid.UUID]*attempt
	creds       map[uuid.UUID]*auth.Credential
	tickets     map[string]*auth.LoginTicket
	ticketsUsed map[string]bool
	sessions    map[uuid.UUID]*auth.LoginSession
	families    map[uuid.UUID]*auth.RefreshFamily
	refresh     map[uuid.UUID]*auth.RefreshToken
	access      map[string]*auth.AccessRecord
	resets      map[string]*link
	emailChg    map[string]*link
	idem        map[string]auth.IdempotencyRecord
	Events      []string
	Fail        error // when set, every call returns it (simulates the DB being down)
}

func NewStore() *Store {
	return &Store{
		attempts: map[uuid.UUID]*attempt{}, creds: map[uuid.UUID]*auth.Credential{},
		tickets: map[string]*auth.LoginTicket{}, ticketsUsed: map[string]bool{},
		sessions: map[uuid.UUID]*auth.LoginSession{}, families: map[uuid.UUID]*auth.RefreshFamily{},
		refresh: map[uuid.UUID]*auth.RefreshToken{}, access: map[string]*auth.AccessRecord{},
		resets: map[string]*link{}, emailChg: map[string]*link{}, idem: map[string]auth.IdempotencyRecord{},
	}
}

func (s *Store) lock() func() { s.mu.Lock(); return s.mu.Unlock }

func (s *Store) Ping(context.Context) error { defer s.lock()(); return s.Fail }

func (s *Store) CountAttemptsSince(_ context.Context, email string, since time.Time) (int, error) {
	defer s.lock()()
	if s.Fail != nil {
		return 0, s.Fail
	}
	n := 0
	for _, a := range s.attempts {
		if a.Email == email && !a.CreatedAt.Before(since) {
			n++
		}
	}
	return n, nil
}

func (s *Store) CreateAttempt(_ context.Context, a auth.RegistrationAttempt) error {
	defer s.lock()()
	if s.Fail != nil {
		return s.Fail
	}
	s.attempts[a.ID] = &attempt{RegistrationAttempt: a}
	return nil
}

func (s *Store) credByEmail(email string) *auth.Credential {
	for _, c := range s.creds {
		if c.Email == email {
			return c
		}
	}
	return nil
}

func (s *Store) VerifyAttempt(_ context.Context, hash []byte, credID uuid.UUID, now time.Time) (auth.Credential, error) {
	defer s.lock()()
	if s.Fail != nil {
		return auth.Credential{}, s.Fail
	}
	var a *attempt
	for _, x := range s.attempts {
		if bytes.Equal(x.TokenHash, hash) {
			a = x
		}
	}
	if a == nil || a.consumed || !a.ExpiresAt.After(now) {
		return auth.Credential{}, auth.ErrNotFound
	}
	a.consumed = true
	if s.credByEmail(a.Email) != nil {
		return auth.Credential{}, auth.ErrAccountExists
	}
	for id, x := range s.attempts {
		if x.Email == a.Email && id != a.ID {
			delete(s.attempts, id)
		}
	}
	c := &auth.Credential{
		ID: credID, Email: a.Email, DisplayName: a.DisplayName, PasswordHash: a.PasswordHash,
		Status: auth.StatusProvisioning, AuthVersion: 1, ProvisioningAttemptID: a.ID, CreatedAt: now, UpdatedAt: now,
	}
	s.creds[c.ID] = c
	return *c, nil
}

func (s *Store) ListProvisioning(_ context.Context, olderThan time.Time, limit int) ([]auth.Credential, error) {
	defer s.lock()()
	if s.Fail != nil {
		return nil, s.Fail
	}
	var out []auth.Credential
	for _, c := range s.creds {
		if c.Status == auth.StatusProvisioning && c.UpdatedAt.Before(olderThan) && len(out) < limit {
			out = append(out, *c)
		}
	}
	return out, nil
}

func (s *Store) ActivateCredential(_ context.Context, credID, userID uuid.UUID, now time.Time) error {
	defer s.lock()()
	if s.Fail != nil {
		return s.Fail
	}
	c, ok := s.creds[credID]
	if !ok || c.Status != auth.StatusProvisioning {
		return auth.ErrNotFound
	}
	for _, o := range s.creds {
		if o.UserID == userID && o.ID != credID {
			return auth.ErrAccountExists
		}
	}
	c.UserID, c.Status, c.UpdatedAt = userID, auth.StatusActive, now
	return nil
}

func (s *Store) CredentialByEmail(_ context.Context, email string) (auth.Credential, error) {
	defer s.lock()()
	if s.Fail != nil {
		return auth.Credential{}, s.Fail
	}
	if c := s.credByEmail(email); c != nil {
		return *c, nil
	}
	return auth.Credential{}, auth.ErrNotFound
}

func (s *Store) CredentialByUserID(_ context.Context, userID uuid.UUID) (auth.Credential, error) {
	defer s.lock()()
	if s.Fail != nil {
		return auth.Credential{}, s.Fail
	}
	for _, c := range s.creds {
		if c.UserID == userID && userID != uuid.Nil {
			return *c, nil
		}
	}
	return auth.Credential{}, auth.ErrNotFound
}

func (s *Store) CredentialByID(_ context.Context, id uuid.UUID) (auth.Credential, error) {
	defer s.lock()()
	if s.Fail != nil {
		return auth.Credential{}, s.Fail
	}
	if c, ok := s.creds[id]; ok {
		return *c, nil
	}
	return auth.Credential{}, auth.ErrNotFound
}

func (s *Store) RecordLoginFailure(_ context.Context, id uuid.UUID, now time.Time) error {
	defer s.lock()()
	if c, ok := s.creds[id]; ok {
		c.FailedAttempts++
		if d := auth.LoginBackoff(c.FailedAttempts); d > 0 {
			c.NextAllowedAt = now.Add(d)
		}
	}
	return s.Fail
}

func (s *Store) RecordLoginSuccess(_ context.Context, id uuid.UUID, _ time.Time) error {
	defer s.lock()()
	if c, ok := s.creds[id]; ok {
		c.FailedAttempts, c.NextAllowedAt = 0, time.Time{}
	}
	return s.Fail
}

func (s *Store) SetPasswordHash(_ context.Context, id uuid.UUID, hash string, now time.Time) error {
	defer s.lock()()
	if c, ok := s.creds[id]; ok {
		c.PasswordHash, c.UpdatedAt = hash, now
	}
	return s.Fail
}

func (s *Store) UpdateAccount(_ context.Context, id uuid.UUID, u auth.AccountUpdate, now time.Time) (auth.Credential, error) {
	defer s.lock()()
	if s.Fail != nil {
		return auth.Credential{}, s.Fail
	}
	c, ok := s.creds[id]
	if !ok {
		return auth.Credential{}, auth.ErrNotFound
	}
	if u.Email != nil {
		if o := s.credByEmail(*u.Email); o != nil && o.ID != id {
			return auth.Credential{}, auth.ErrAccountExists
		}
		c.Email = *u.Email
	}
	if u.PasswordHash != nil {
		c.PasswordHash = *u.PasswordHash
	}
	if u.Status != nil {
		c.Status = *u.Status
	}
	if u.ResetFailures {
		c.FailedAttempts, c.NextAllowedAt = 0, time.Time{}
	}
	if u.BumpVersion {
		c.AuthVersion++
		for _, ls := range s.sessions {
			if ls.CredentialID == id && ls.RevokedAt == nil {
				t := now
				ls.RevokedAt = &t
			}
		}
		for _, f := range s.families {
			if f.UserID == c.UserID && f.RevokedAt == nil {
				t := now
				f.RevokedAt = &t
			}
		}
	}
	c.UpdatedAt = now
	return *c, nil
}

func (s *Store) CreateTicket(_ context.Context, t auth.LoginTicket) error {
	defer s.lock()()
	if s.Fail != nil {
		return s.Fail
	}
	s.tickets[string(t.Hash)] = &t
	return nil
}

func (s *Store) ConsumeTicket(_ context.Context, hash []byte, now time.Time) (auth.LoginTicket, error) {
	defer s.lock()()
	if s.Fail != nil {
		return auth.LoginTicket{}, s.Fail
	}
	t, ok := s.tickets[string(hash)]
	if !ok || s.ticketsUsed[string(hash)] || !t.ExpiresAt.After(now) {
		return auth.LoginTicket{}, auth.ErrNotFound
	}
	s.ticketsUsed[string(hash)] = true
	return *t, nil
}

func (s *Store) CreateLoginSession(_ context.Context, ls auth.LoginSession) error {
	defer s.lock()()
	if s.Fail != nil {
		return s.Fail
	}
	s.sessions[ls.ID] = &ls
	return nil
}

func (s *Store) SetAuthTime(_ context.Context, id uuid.UUID, t time.Time) error {
	defer s.lock()()
	if ls, ok := s.sessions[id]; ok {
		ls.AuthTime = t
	}
	return s.Fail
}

func (s *Store) CreateFamily(_ context.Context, f auth.RefreshFamily, rt auth.RefreshToken, at auth.AccessRecord) error {
	defer s.lock()()
	if s.Fail != nil {
		return s.Fail
	}
	s.families[f.ID], s.refresh[rt.ID], s.access[at.JTI] = &f, &rt, &at
	return nil
}

func (s *Store) RefreshByHash(_ context.Context, hash []byte) (auth.RefreshToken, auth.RefreshFamily, auth.LoginSession, auth.Credential, error) {
	defer s.lock()()
	if s.Fail != nil {
		return auth.RefreshToken{}, auth.RefreshFamily{}, auth.LoginSession{}, auth.Credential{}, s.Fail
	}
	for _, rt := range s.refresh {
		if bytes.Equal(rt.Hash, hash) {
			f := s.families[rt.FamilyID]
			ls := s.sessions[f.LoginSessionID]
			c := s.creds[ls.CredentialID]
			return *rt, *f, *ls, *c, nil
		}
	}
	return auth.RefreshToken{}, auth.RefreshFamily{}, auth.LoginSession{}, auth.Credential{}, auth.ErrNotFound
}

func (s *Store) Rotate(_ context.Context, old, next auth.RefreshToken, at auth.AccessRecord, idle, now time.Time) error {
	defer s.lock()()
	if s.Fail != nil {
		return s.Fail
	}
	f, ok := s.families[old.FamilyID]
	if !ok || f.RevokedAt != nil {
		return auth.ErrNotFound
	}
	cur := s.refresh[old.ID]
	if cur.UsedAt != nil {
		t := now
		f.RevokedAt = &t
		return auth.ErrRefreshReused
	}
	t := now
	cur.UsedAt = &t
	f.IdleExpiresAt = idle
	s.refresh[next.ID], s.access[at.JTI] = &next, &at
	return nil
}

func (s *Store) RevokeFamily(_ context.Context, id uuid.UUID, _ string, now time.Time) error {
	defer s.lock()()
	if f, ok := s.families[id]; ok && f.RevokedAt == nil {
		t := now
		f.RevokedAt = &t
	}
	return s.Fail
}

func (s *Store) RevokeLoginSession(_ context.Context, id uuid.UUID, _ string, now time.Time) error {
	defer s.lock()()
	if ls, ok := s.sessions[id]; ok && ls.RevokedAt == nil {
		t := now
		ls.RevokedAt = &t
	}
	return s.Fail
}

func (s *Store) RevokeMemberFamilies(_ context.Context, ws, mem uuid.UUID, _ string, now time.Time) error {
	defer s.lock()()
	for _, f := range s.families {
		if f.WorkspaceID == ws && f.MemberID == mem && f.RevokedAt == nil {
			t := now
			f.RevokedAt = &t
		}
	}
	return s.Fail
}

func (s *Store) RevokeWorkspaceFamilies(_ context.Context, ws uuid.UUID, _ string, now time.Time) error {
	defer s.lock()()
	for _, f := range s.families {
		if f.WorkspaceID == ws && f.RevokedAt == nil {
			t := now
			f.RevokedAt = &t
		}
	}
	return s.Fail
}

func (s *Store) RevokeAccessToken(_ context.Context, jti string, now time.Time) error {
	defer s.lock()()
	if a, ok := s.access[jti]; ok && a.RevokedAt == nil {
		t := now
		a.RevokedAt = &t
	}
	return s.Fail
}

func (s *Store) AccessState(_ context.Context, jti string) (auth.AccessState, error) {
	defer s.lock()()
	if s.Fail != nil {
		return auth.AccessState{}, s.Fail
	}
	a, ok := s.access[jti]
	if !ok {
		return auth.AccessState{}, auth.ErrNotFound
	}
	f := s.families[a.FamilyID]
	ls := s.sessions[f.LoginSessionID]
	return auth.AccessState{Access: *a, Family: *f, Session: *ls, Credential: *s.creds[ls.CredentialID]}, nil
}

func (s *Store) CreatePasswordReset(_ context.Context, hash []byte, credID uuid.UUID, _, exp time.Time) error {
	defer s.lock()()
	s.resets[string(hash)] = &link{credID: credID, expires: exp}
	return s.Fail
}

func (s *Store) ConsumePasswordReset(_ context.Context, hash []byte, now time.Time) (uuid.UUID, error) {
	defer s.lock()()
	l, ok := s.resets[string(hash)]
	if !ok || l.consumed || !l.expires.After(now) {
		return uuid.Nil, auth.ErrNotFound
	}
	l.consumed = true
	return l.credID, nil
}

func (s *Store) CreateEmailChange(_ context.Context, hash []byte, credID uuid.UUID, email string, _, exp time.Time) error {
	defer s.lock()()
	s.emailChg[string(hash)] = &link{credID: credID, email: email, expires: exp}
	return s.Fail
}

func (s *Store) ConsumeEmailChange(_ context.Context, hash []byte, now time.Time) (uuid.UUID, string, error) {
	defer s.lock()()
	l, ok := s.emailChg[string(hash)]
	if !ok || l.consumed || !l.expires.After(now) {
		return uuid.Nil, "", auth.ErrNotFound
	}
	l.consumed = true
	return l.credID, l.email, nil
}

func idemKey(u uuid.UUID, route, key string) string { return u.String() + "|" + route + "|" + key }

func (s *Store) GetIdempotency(_ context.Context, u uuid.UUID, route, key string) (auth.IdempotencyRecord, error) {
	defer s.lock()()
	r, ok := s.idem[idemKey(u, route, key)]
	if !ok {
		return r, auth.ErrNotFound
	}
	return r, nil
}

func (s *Store) ReserveIdempotency(_ context.Context, r auth.IdempotencyRecord) error {
	defer s.lock()()
	k := idemKey(r.UserID, r.Route, r.Key)
	if old, ok := s.idem[k]; ok {
		stale := r.CreatedAt.Sub(old.CreatedAt) > 24*time.Hour ||
			(old.StatusCode == 0 && r.CreatedAt.Sub(old.CreatedAt) > time.Minute)
		if !stale {
			return auth.ErrIdempotencyHit
		}
	}
	s.idem[k] = r
	return nil
}

func (s *Store) CompleteIdempotency(_ context.Context, u uuid.UUID, route, key string, status int, body []byte) error {
	defer s.lock()()
	k := idemKey(u, route, key)
	r, ok := s.idem[k]
	if !ok {
		return auth.ErrNotFound
	}
	r.StatusCode, r.ResponseJSON = status, append([]byte(nil), body...)
	s.idem[k] = r
	return nil
}

func (s *Store) ReleaseIdempotency(_ context.Context, u uuid.UUID, route, key string) error {
	defer s.lock()()
	k := idemKey(u, route, key)
	if r, ok := s.idem[k]; ok && r.StatusCode == 0 {
		delete(s.idem, k)
	}
	return nil
}

func (s *Store) Audit(_ context.Context, kind string, _ uuid.UUID, _ map[string]any, _ time.Time) error {
	defer s.lock()()
	s.Events = append(s.Events, kind)
	return nil
}

func (s *Store) Cleanup(context.Context, time.Time) (int64, error) { return 0, nil }

// Session returns a copy of a login session (tests).
func (s *Store) Session(id uuid.UUID) auth.LoginSession {
	defer s.lock()()
	return *s.sessions[id]
}

// AgeAuthTime moves a login session's auth_time back (tests).
func (s *Store) AgeAuthTime(id uuid.UUID, d time.Duration) {
	defer s.lock()()
	s.sessions[id].AuthTime = s.sessions[id].AuthTime.Add(-d)
}
