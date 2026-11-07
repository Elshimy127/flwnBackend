//go:build pgintegration

// Runs the store against a real Postgres. Point it at an empty database whose role may create
// schema auth (a throwaway local database, never flwn_auth in production):
//
//	AUTH_TEST_DATABASE_URL=postgres://... go test -tags pgintegration ./internal/auth/pgstore/ -v
package pgstore_test

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hesham127/flwnBackend/internal/auth"
	"github.com/Hesham127/flwnBackend/internal/auth/pgstore"
	"github.com/Hesham127/flwnBackend/internal/platform/db"
)

func open(t *testing.T) *pgstore.Store {
	url := os.Getenv("AUTH_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("AUTH_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := db.Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	// A bootstrapped database already has schema auth (and the app role may not create one).
	var exists bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'auth')`).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		if _, err := pool.Exec(ctx, `CREATE SCHEMA auth`); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Migrate(ctx, url); err != nil {
		t.Fatal(err)
	}
	if err := db.CheckVersion(ctx, pool); err != nil {
		t.Fatal(err)
	}
	return pgstore.New(pool)
}

func TestStoreLifecycle(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	email := "pg-" + uuid.NewString()[:8] + "@example.com"

	// Two attempts; verifying one creates the credential and removes the other.
	_, h1, _ := auth.NewOpaqueToken()
	_, h2, _ := auth.NewOpaqueToken()
	for _, h := range [][]byte{h1, h2} {
		if err := s.CreateAttempt(ctx, auth.RegistrationAttempt{ID: uuid.New(), Email: email, DisplayName: "P",
			PasswordHash: "$argon2id$x", TokenHash: h, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	cred, err := s.VerifyAttempt(ctx, h2, uuid.New(), now)
	if err != nil || cred.Status != auth.StatusProvisioning {
		t.Fatalf("verify: %v %+v", err, cred)
	}
	if _, err := s.VerifyAttempt(ctx, h1, uuid.New(), now); !errors.Is(err, auth.ErrNotFound) && !errors.Is(err, auth.ErrAccountExists) {
		t.Fatalf("second attempt: %v", err)
	}
	if _, err := s.VerifyAttempt(ctx, h2, uuid.New(), now); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("replayed verify: %v", err)
	}
	user := uuid.New()
	if err := s.ActivateCredential(ctx, cred.ID, user, now); err != nil {
		t.Fatal(err)
	}

	// Failure counter and backoff.
	for i := 0; i < 5; i++ {
		_ = s.RecordLoginFailure(ctx, cred.ID, now)
	}
	c, _ := s.CredentialByUserID(ctx, user)
	if c.FailedAttempts != 5 || !c.NextAllowedAt.After(now) {
		t.Fatalf("backoff not recorded: %+v", c)
	}

	// Ticket is single-use.
	_, th, _ := auth.NewOpaqueToken()
	_ = s.CreateTicket(ctx, auth.LoginTicket{Hash: th, CredentialID: cred.ID, UserID: user, AuthVersion: 1,
		AuthTime: now, CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute)})
	if _, err := s.ConsumeTicket(ctx, th, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeTicket(ctx, th, now); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("ticket reused: %v", err)
	}

	// Session, family, rotation, strict reuse.
	ls := auth.LoginSession{ID: uuid.New(), CredentialID: cred.ID, UserID: user, AuthVersion: 1, AuthTime: now,
		CreatedAt: now, AbsoluteExpiresAt: now.Add(24 * time.Hour)}
	if err := s.CreateLoginSession(ctx, ls); err != nil {
		t.Fatal(err)
	}
	fam := auth.RefreshFamily{ID: uuid.New(), LoginSessionID: ls.ID, UserID: user, WorkspaceID: uuid.New(),
		MemberID: uuid.New(), AuthVersion: 1, CreatedAt: now, IdleExpiresAt: now.Add(time.Hour)}
	_, rh, _ := auth.NewOpaqueToken()
	rt := auth.RefreshToken{ID: uuid.New(), FamilyID: fam.ID, Generation: 0, Hash: rh, CreatedAt: now}
	if err := s.CreateFamily(ctx, fam, rt, auth.AccessRecord{JTI: "j0-" + fam.ID.String(), FamilyID: fam.ID, AuthVersion: 1, IssuedAt: now, ExpiresAt: now.Add(15 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if st, err := s.AccessState(ctx, "j0-"+fam.ID.String()); err != nil || st.Credential.UserID != user {
		t.Fatalf("access state: %v %+v", err, st)
	}

	var wg sync.WaitGroup
	errs := make([]error, 6)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, nh, _ := auth.NewOpaqueToken()
			errs[i] = s.Rotate(ctx, rt, auth.RefreshToken{ID: uuid.New(), FamilyID: fam.ID, Generation: 1, Hash: nh, CreatedAt: now},
				auth.AccessRecord{JTI: uuid.NewString(), FamilyID: fam.ID, AuthVersion: 1, IssuedAt: now, ExpiresAt: now.Add(time.Minute)},
				now.Add(time.Hour), now)
		}(i)
	}
	wg.Wait()
	ok := 0
	for _, e := range errs {
		if e == nil {
			ok++
		}
	}
	if ok != 1 {
		t.Fatalf("%d concurrent rotations succeeded: %v", ok, errs)
	}
	_, f2, _, _, _ := s.RefreshByHash(ctx, rh)
	if f2.RevokedAt == nil {
		t.Fatal("reuse did not revoke the family")
	}

	if err := s.RevokeWorkspaceFamilies(ctx, fam.WorkspaceID, "test", now); err != nil {
		t.Fatal(err)
	}

	// Account-wide revocation bumps auth_version and revokes sessions.
	c, err = s.UpdateAccount(ctx, cred.ID, auth.AccountUpdate{BumpVersion: true, ResetFailures: true, Reason: "test"}, now)
	if err != nil || c.AuthVersion != 2 || c.FailedAttempts != 0 {
		t.Fatalf("update account: %v %+v", err, c)
	}
	st, _ := s.AccessState(ctx, "j0-"+fam.ID.String())
	if st.Session.RevokedAt == nil {
		t.Fatal("login session not revoked")
	}

	// Idempotency key conflict.
	rec := auth.IdempotencyRecord{Key: "k", UserID: user, Route: "POST /x", RequestHash: []byte{1}, CreatedAt: now}
	if err := s.ReserveIdempotency(ctx, rec); err != nil {
		t.Fatal(err)
	}
	if err := s.ReserveIdempotency(ctx, rec); !errors.Is(err, auth.ErrIdempotencyHit) {
		t.Fatalf("pending key reserved twice: %v", err)
	}
	if err := s.CompleteIdempotency(ctx, user, "POST /x", "k", 201, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if got, err := s.GetIdempotency(ctx, user, "POST /x", "k"); err != nil || got.StatusCode != 201 {
		t.Fatalf("completed key: %v %+v", err, got)
	}
	stale := rec
	stale.Key, stale.CreatedAt = "stale", now.Add(-2*time.Minute)
	_ = s.ReserveIdempotency(ctx, stale)
	stale.CreatedAt = now
	if err := s.ReserveIdempotency(ctx, stale); err != nil {
		t.Fatalf("stale pending key not reclaimable: %v", err)
	}
	if _, err := s.Cleanup(ctx, now.Add(48*time.Hour)); err != nil {
		t.Fatal(err)
	}
}
