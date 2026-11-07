package auth_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hesham127/flwnBackend/internal/auth"
	"github.com/Hesham127/flwnBackend/internal/auth/authtest"
)

var ctx = context.Background()

const pw = "correct horse battery"

// signup registers and verifies an account and returns its engine user id.
func signup(t *testing.T, e *authtest.Env, email string) uuid.UUID {
	t.Helper()
	if err := e.Svc.Register(ctx, email, pw, "Test User"); err != nil {
		t.Fatal(err)
	}
	if err := e.Svc.VerifyEmail(ctx, e.Mailer.Token("verify", email)); err != nil {
		t.Fatal(err)
	}
	id, ok, _ := e.Engine.FindUserByEmail(ctx, email)
	if !ok {
		t.Fatal("engine user not provisioned")
	}
	return id
}

// session logs in and opens a session in ws.
func session(t *testing.T, e *authtest.Env, email string, ws uuid.UUID) auth.TokenPair {
	t.Helper()
	res, err := e.Svc.Login(ctx, email, pw)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := e.Svc.CreateSession(ctx, res.Ticket, ws)
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

func mustAuth(t *testing.T, e *authtest.Env, tok string) auth.Principal {
	t.Helper()
	p, err := e.Svc.Authenticate(ctx, tok, true)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	return p
}

func wantErr(t *testing.T, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("got %v, want %v", err, target)
	}
}

func TestPreHijackOnlyVerifiedAttemptActivates(t *testing.T) {
	e := authtest.NewEnv(t)
	victim := "victim@example.com"
	// Attacker signs up first with their own password; the link goes to the victim's mailbox.
	if err := e.Svc.Register(ctx, victim, "attacker-password-1", "Mallory"); err != nil {
		t.Fatal(err)
	}
	attackerLink := e.Mailer.Token("verify", victim)
	// No credential exists yet: the attacker cannot log in.
	_, err := e.Svc.Login(ctx, victim, "attacker-password-1")
	wantErr(t, err, auth.ErrInvalidCredentials)
	// The real owner signs up and clicks their own link.
	if err := e.Svc.Register(ctx, victim, pw, "Victim"); err != nil {
		t.Fatal(err)
	}
	if err := e.Svc.VerifyEmail(ctx, e.Mailer.Token("verify", victim)); err != nil {
		t.Fatal(err)
	}
	// The attacker's attempt is gone and their password never works.
	wantErr(t, e.Svc.VerifyEmail(ctx, attackerLink), auth.ErrInvalidLink)
	_, err = e.Svc.Login(ctx, victim, "attacker-password-1")
	wantErr(t, err, auth.ErrInvalidCredentials)
	if _, err := e.Svc.Login(ctx, victim, pw); err != nil {
		t.Fatalf("owner login: %v", err)
	}
	// Registering again for an active account creates nothing and sends a notice.
	if err := e.Svc.Register(ctx, victim, "another-password-9", "X"); err != nil {
		t.Fatal(err)
	}
	if !e.Mailer.Has("existing", victim) {
		t.Fatal("no signup-on-existing notice")
	}
}

func TestVerifyLinkSingleUseAndExpiry(t *testing.T) {
	e := authtest.NewEnv(t)
	_ = e.Svc.Register(ctx, "a@example.com", pw, "A")
	link := e.Mailer.Token("verify", "a@example.com")
	e.Clock.Advance(25 * time.Hour)
	wantErr(t, e.Svc.VerifyEmail(ctx, link), auth.ErrInvalidLink)
}

func TestProvisioningRecovery(t *testing.T) {
	e := authtest.NewEnv(t)
	_ = e.Svc.Register(ctx, "p@example.com", pw, "P")
	e.Engine.FailCreate = true // engine fails after the credential exists
	if err := e.Svc.VerifyEmail(ctx, e.Mailer.Token("verify", "p@example.com")); err != nil {
		t.Fatal(err)
	}
	cred, _ := e.Store.CredentialByEmail(ctx, "p@example.com")
	if cred.Status != auth.StatusProvisioning {
		t.Fatalf("status %s", cred.Status)
	}
	// The reconciler finishes it.
	e.Clock.Advance(2 * time.Minute)
	if err := e.Svc.ReconcileProvisioning(ctx); err != nil {
		t.Fatal(err)
	}
	cred, _ = e.Store.CredentialByEmail(ctx, "p@example.com")
	if cred.Status != auth.StatusActive || cred.UserID == uuid.Nil {
		t.Fatalf("not activated: %+v", cred)
	}
}

func TestProvisioningLinksExistingEngineUser(t *testing.T) {
	e := authtest.NewEnv(t)
	existing, _ := e.Engine.CreateUser(ctx, "inv@example.com", "Invited")
	id := signup(t, e, "inv@example.com")
	if id != existing {
		t.Fatal("did not link the existing engine user")
	}
}

func TestLoginTicketSingleUseAndShortLived(t *testing.T) {
	e := authtest.NewEnv(t)
	u := signup(t, e, "t@example.com")
	ws := uuid.New()
	e.Engine.AddMember(ws, u, "member", auth.MemberTypeHuman)
	res, err := e.Svc.Login(ctx, "T@Example.com", pw)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Memberships) != 1 {
		t.Fatalf("memberships %v", res.Memberships)
	}
	if _, err := e.Svc.CreateSession(ctx, res.Ticket, ws); err != nil {
		t.Fatal(err)
	}
	_, err = e.Svc.CreateSession(ctx, res.Ticket, ws)
	wantErr(t, err, auth.ErrUnauthenticated)

	res2, _ := e.Svc.Login(ctx, "t@example.com", pw)
	e.Clock.Advance(6 * time.Minute)
	_, err = e.Svc.CreateSession(ctx, res2.Ticket, ws)
	wantErr(t, err, auth.ErrUnauthenticated)

	// A ticket is not a JWT and never authenticates a request.
	_, err = e.Svc.Authenticate(ctx, res2.Ticket, false)
	wantErr(t, err, auth.ErrUnauthenticated)
}

func TestSessionRequiresHumanMembership(t *testing.T) {
	e := authtest.NewEnv(t)
	u := signup(t, e, "h@example.com")
	other := uuid.New()
	aiWS := uuid.New()
	e.Engine.AddMember(aiWS, u, "admin", "AI")
	res, _ := e.Svc.Login(ctx, "h@example.com", pw)
	if len(res.Memberships) != 0 {
		t.Fatal("AI membership listed for human login")
	}
	_, err := e.Svc.CreateSession(ctx, res.Ticket, other)
	wantErr(t, err, auth.ErrNotMember)
	res, _ = e.Svc.Login(ctx, "h@example.com", pw)
	_, err = e.Svc.CreateSession(ctx, res.Ticket, aiWS)
	wantErr(t, err, auth.ErrNotMember)
}

func TestLoginFailuresBackoffNoEnumeration(t *testing.T) {
	e := authtest.NewEnv(t)
	signup(t, e, "b@example.com")
	_, err := e.Svc.Login(ctx, "nobody@example.com", pw)
	wantErr(t, err, auth.ErrInvalidCredentials)
	for i := 0; i < 5; i++ {
		_, err = e.Svc.Login(ctx, "b@example.com", "wrong-password-x")
		wantErr(t, err, auth.ErrInvalidCredentials)
	}
	_, err = e.Svc.Login(ctx, "b@example.com", pw)
	wantErr(t, err, auth.ErrTooManyAttempts)
	e.Clock.Advance(2 * time.Second)
	if _, err := e.Svc.Login(ctx, "b@example.com", pw); err != nil {
		t.Fatalf("login after backoff: %v", err)
	}
}

type world struct {
	e      *authtest.Env
	user   uuid.UUID
	ws     uuid.UUID
	member uuid.UUID
	email  string
}

func newWorld(t *testing.T, role string) world {
	e := authtest.NewEnv(t)
	u := signup(t, e, "w@example.com")
	ws := uuid.New()
	m := e.Engine.AddMember(ws, u, role, auth.MemberTypeHuman)
	return world{e: e, user: u, ws: ws, member: m, email: "w@example.com"}
}

func TestAuthenticatePrincipal(t *testing.T) {
	w := newWorld(t, "member")
	pair := session(t, w.e, w.email, w.ws)
	p := mustAuth(t, w.e, pair.AccessToken)
	if p.UserID != w.user || p.MemberID != w.member || p.WorkspaceID != w.ws || p.Role != auth.RoleMember {
		t.Fatalf("principal %+v", p)
	}
	if !p.HasScope(auth.ScopePlanningWrite) || p.HasScope(auth.ScopeIdentityWrite) {
		t.Fatalf("scopes %v", p.Scopes)
	}
}

func TestRevocationLevels(t *testing.T) {
	t.Run("individual token", func(t *testing.T) {
		w := newWorld(t, "member")
		pair := session(t, w.e, w.email, w.ws)
		p := mustAuth(t, w.e, pair.AccessToken)
		_ = w.e.Store.RevokeAccessToken(ctx, p.JTI, w.e.Clock.Now())
		_, err := w.e.Svc.Authenticate(ctx, pair.AccessToken, true)
		wantErr(t, err, auth.ErrUnauthenticated)
	})
	t.Run("refresh family (logout)", func(t *testing.T) {
		w := newWorld(t, "member")
		pair := session(t, w.e, w.email, w.ws)
		if err := w.e.Svc.Logout(ctx, pair.RefreshToken, ""); err != nil {
			t.Fatal(err)
		}
		_, err := w.e.Svc.Authenticate(ctx, pair.AccessToken, true)
		wantErr(t, err, auth.ErrUnauthenticated)
		_, err = w.e.Svc.Refresh(ctx, pair.RefreshToken)
		wantErr(t, err, auth.ErrUnauthenticated)
	})
	t.Run("login session (device)", func(t *testing.T) {
		w := newWorld(t, "member")
		ws2 := uuid.New()
		w.e.Engine.AddMember(ws2, w.user, "viewer", auth.MemberTypeHuman)
		a := session(t, w.e, w.email, w.ws)
		b, err := w.e.Svc.Switch(ctx, a.RefreshToken, ws2)
		if err != nil {
			t.Fatal(err)
		}
		other := session(t, w.e, w.email, w.ws) // second device
		if err := w.e.Svc.RevokeLoginSession(ctx, mustAuth(t, w.e, a.AccessToken)); err != nil {
			t.Fatal(err)
		}
		for _, tok := range []string{a.AccessToken, b.AccessToken} {
			_, err := w.e.Svc.Authenticate(ctx, tok, true)
			wantErr(t, err, auth.ErrUnauthenticated)
		}
		mustAuth(t, w.e, other.AccessToken)
	})
	t.Run("account-wide (logout-all)", func(t *testing.T) {
		w := newWorld(t, "member")
		a := session(t, w.e, w.email, w.ws)
		b := session(t, w.e, w.email, w.ws)
		if err := w.e.Svc.LogoutAll(ctx, mustAuth(t, w.e, a.AccessToken)); err != nil {
			t.Fatal(err)
		}
		for _, tok := range []string{a.AccessToken, b.AccessToken} {
			_, err := w.e.Svc.Authenticate(ctx, tok, true)
			wantErr(t, err, auth.ErrUnauthenticated)
		}
		_, err := w.e.Svc.Refresh(ctx, b.RefreshToken)
		wantErr(t, err, auth.ErrUnauthenticated)
	})
}

func TestLogoutWorksWithExpiredAccessToken(t *testing.T) {
	w := newWorld(t, "member")
	pair := session(t, w.e, w.email, w.ws)
	w.e.Clock.Advance(20 * time.Minute)
	if err := w.e.Svc.Logout(ctx, pair.RefreshToken, pair.AccessToken); err != nil {
		t.Fatal(err)
	}
	_, err := w.e.Svc.Refresh(ctx, pair.RefreshToken)
	wantErr(t, err, auth.ErrUnauthenticated)
}

func TestRefreshRotationAndStrictReuse(t *testing.T) {
	w := newWorld(t, "member")
	p0 := session(t, w.e, w.email, w.ws)
	p1, err := w.e.Svc.Refresh(ctx, p0.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	mustAuth(t, w.e, p1.AccessToken)
	// Replaying the old token, even a second later, revokes the family.
	w.e.Clock.Advance(time.Second)
	_, err = w.e.Svc.Refresh(ctx, p0.RefreshToken)
	wantErr(t, err, auth.ErrRefreshReused)
	_, err = w.e.Svc.Refresh(ctx, p1.RefreshToken)
	wantErr(t, err, auth.ErrUnauthenticated)
	_, err = w.e.Svc.Authenticate(ctx, p1.AccessToken, true)
	wantErr(t, err, auth.ErrUnauthenticated)
}

func TestConcurrentRefreshExactlyOneWins(t *testing.T) {
	w := newWorld(t, "member")
	p0 := session(t, w.e, w.email, w.ws)
	var wg sync.WaitGroup
	results := make([]error, 8)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, results[i] = w.e.Svc.Refresh(ctx, p0.RefreshToken)
		}(i)
	}
	wg.Wait()
	ok := 0
	for _, err := range results {
		if err == nil {
			ok++
		} else if !errors.Is(err, auth.ErrRefreshReused) && !errors.Is(err, auth.ErrUnauthenticated) {
			t.Fatalf("unexpected error %v", err)
		}
	}
	if ok != 1 {
		t.Fatalf("%d refreshes succeeded, want exactly 1", ok)
	}
}

func TestSessionAbsoluteLifetime(t *testing.T) {
	w := newWorld(t, "member")
	p := session(t, w.e, w.email, w.ws)
	for i := 0; i < 6; i++ { // keep refreshing within idle window
		w.e.Clock.Advance(6 * 24 * time.Hour)
		var err error
		p, err = w.e.Svc.Refresh(ctx, p.RefreshToken)
		if i < 4 && err != nil {
			t.Fatalf("refresh %d: %v", i, err)
		}
		if i >= 5 {
			wantErr(t, err, auth.ErrUnauthenticated) // past 30 days
		}
		if err != nil {
			return
		}
	}
}

func TestMembershipChangesApplyImmediately(t *testing.T) {
	t.Run("demotion", func(t *testing.T) {
		w := newWorld(t, "admin")
		pair := session(t, w.e, w.email, w.ws)
		if !mustAuth(t, w.e, pair.AccessToken).HasScope(auth.ScopeIdentityWrite) {
			t.Fatal("admin lacks identity:write")
		}
		w.e.Engine.SetMember(w.member, "viewer", "")
		p := mustAuth(t, w.e, pair.AccessToken)
		if p.Role != auth.RoleViewer || p.HasScope(auth.ScopePlanningWrite) || p.HasScope(auth.ScopeIdentityWrite) {
			t.Fatalf("demotion not applied: %+v", p)
		}
	})
	t.Run("promotion waits for refresh", func(t *testing.T) {
		w := newWorld(t, "viewer")
		pair := session(t, w.e, w.email, w.ws)
		w.e.Engine.SetMember(w.member, "admin", "")
		if mustAuth(t, w.e, pair.AccessToken).HasScope(auth.ScopeIdentityWrite) {
			t.Fatal("promotion widened an existing token")
		}
		p2, err := w.e.Svc.Refresh(ctx, pair.RefreshToken)
		if err != nil {
			t.Fatal(err)
		}
		if !mustAuth(t, w.e, p2.AccessToken).HasScope(auth.ScopeIdentityWrite) {
			t.Fatal("promotion not applied after refresh")
		}
	})
	t.Run("suspension", func(t *testing.T) {
		w := newWorld(t, "member")
		pair := session(t, w.e, w.email, w.ws)
		w.e.Engine.SetMember(w.member, "", "suspended")
		_, err := w.e.Svc.Authenticate(ctx, pair.AccessToken, false)
		wantErr(t, err, auth.ErrUnauthenticated)
		w.e.Engine.SetMember(w.member, "", "active")
		_, err = w.e.Svc.Refresh(ctx, pair.RefreshToken) // family was revoked
		wantErr(t, err, auth.ErrUnauthenticated)
	})
	t.Run("removal", func(t *testing.T) {
		w := newWorld(t, "member")
		pair := session(t, w.e, w.email, w.ws)
		w.e.Engine.RemoveMember(w.member)
		_, err := w.e.Svc.Authenticate(ctx, pair.AccessToken, true)
		wantErr(t, err, auth.ErrUnauthenticated)
	})
	t.Run("unknown role denied", func(t *testing.T) {
		w := newWorld(t, "member")
		pair := session(t, w.e, w.email, w.ws)
		w.e.Engine.SetMember(w.member, "superuser", "")
		_, err := w.e.Svc.Authenticate(ctx, pair.AccessToken, true)
		wantErr(t, err, auth.ErrForbidden)
	})
}

func TestWorkspaceSessionsRevoked(t *testing.T) {
	w := newWorld(t, "owner")
	a := session(t, w.e, w.email, w.ws)
	_, _ = w.e.Svc.Authenticate(ctx, a.AccessToken, false) // warm the read cache
	if err := w.e.Svc.RevokeWorkspaceSessions(ctx, w.ws, "workspace_deleted"); err != nil {
		t.Fatal(err)
	}
	_, err := w.e.Svc.Authenticate(ctx, a.AccessToken, false)
	wantErr(t, err, auth.ErrUnauthenticated)
	_, err = w.e.Svc.Refresh(ctx, a.RefreshToken)
	wantErr(t, err, auth.ErrUnauthenticated)
}

func TestReadCacheAndInvalidation(t *testing.T) {
	w := newWorld(t, "admin")
	pair := session(t, w.e, w.email, w.ws)
	mustAuth(t, w.e, pair.AccessToken)
	_, _ = w.e.Svc.Authenticate(ctx, pair.AccessToken, false)
	hits := w.e.Engine.MemberHits
	_, _ = w.e.Svc.Authenticate(ctx, pair.AccessToken, false)
	if w.e.Engine.MemberHits != hits {
		t.Fatal("read did not use the cache")
	}
	_, _ = w.e.Svc.Authenticate(ctx, pair.AccessToken, true)
	if w.e.Engine.MemberHits != hits+1 {
		t.Fatal("write used the cache")
	}
	w.e.Engine.SetMember(w.member, "viewer", "")
	w.e.Svc.InvalidateMember(w.ws, w.member)
	p, _ := w.e.Svc.Authenticate(ctx, pair.AccessToken, false)
	if p.Role != auth.RoleViewer {
		t.Fatal("invalidation ignored")
	}
}

func TestFailClosed(t *testing.T) {
	w := newWorld(t, "member")
	pair := session(t, w.e, w.email, w.ws)
	w.e.Engine.Down = true
	_, err := w.e.Svc.Authenticate(ctx, pair.AccessToken, true)
	wantErr(t, err, auth.ErrUnavailable)
	w.e.Engine.Down = false
	w.e.Store.Fail = errors.New("db down")
	_, err = w.e.Svc.Authenticate(ctx, pair.AccessToken, true)
	wantErr(t, err, auth.ErrUnavailable)
}

func TestSwitchNeedsRefreshTokenAndMembership(t *testing.T) {
	w := newWorld(t, "viewer")
	ws2 := uuid.New()
	m2 := w.e.Engine.AddMember(ws2, w.user, "owner", auth.MemberTypeHuman)
	a := session(t, w.e, w.email, w.ws)
	// An access token is not a refresh token.
	_, err := w.e.Svc.Switch(ctx, a.AccessToken, ws2)
	wantErr(t, err, auth.ErrUnauthenticated)
	b, err := w.e.Svc.Switch(ctx, a.RefreshToken, ws2)
	if err != nil {
		t.Fatal(err)
	}
	p := mustAuth(t, w.e, b.AccessToken)
	if p.WorkspaceID != ws2 || p.MemberID != m2 || p.Role != auth.RoleOwner {
		t.Fatalf("switched principal %+v", p)
	}
	mustAuth(t, w.e, a.AccessToken) // old session still open
	_, err = w.e.Svc.Switch(ctx, a.RefreshToken, uuid.New())
	wantErr(t, err, auth.ErrNotMember)
}

func TestRecentAuth(t *testing.T) {
	w := newWorld(t, "owner")
	pair := session(t, w.e, w.email, w.ws)
	p := mustAuth(t, w.e, pair.AccessToken)
	if err := w.e.Svc.RequireRecent(p); err != nil {
		t.Fatalf("fresh login not recent: %v", err)
	}
	w.e.Clock.Advance(11 * time.Minute)
	// Refresh does not move auth_time.
	p2, err := w.e.Svc.Refresh(ctx, pair.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	p = mustAuth(t, w.e, p2.AccessToken)
	wantErr(t, w.e.Svc.LogoutAll(ctx, p), auth.ErrReauthRequired)
	wantErr(t, w.e.Svc.Reauth(ctx, p, "wrong-password-x"), auth.ErrInvalidCredentials)
	if err := w.e.Svc.Reauth(ctx, p, pw); err != nil {
		t.Fatal(err)
	}
	p = mustAuth(t, w.e, p2.AccessToken)
	if err := w.e.Svc.LogoutAll(ctx, p); err != nil {
		t.Fatalf("logout-all after reauth: %v", err)
	}
}

func TestPasswordChangeAndReset(t *testing.T) {
	w := newWorld(t, "member")
	a := session(t, w.e, w.email, w.ws)
	other := session(t, w.e, w.email, w.ws)
	p := mustAuth(t, w.e, a.AccessToken)
	_, err := w.e.Svc.ChangePassword(ctx, p, "wrong-password-x", "new password 123")
	wantErr(t, err, auth.ErrInvalidCredentials)
	fresh, err := w.e.Svc.ChangePassword(ctx, p, pw, "new password 123")
	if err != nil {
		t.Fatal(err)
	}
	for _, tok := range []string{a.AccessToken, other.AccessToken} {
		_, err := w.e.Svc.Authenticate(ctx, tok, true)
		wantErr(t, err, auth.ErrUnauthenticated)
	}
	mustAuth(t, w.e, fresh.AccessToken)

	// Reset: link is single-use and ends every session.
	_ = w.e.Svc.ForgotPassword(ctx, "nobody@example.com") // same answer, no mail
	if err := w.e.Svc.ForgotPassword(ctx, w.email); err != nil {
		t.Fatal(err)
	}
	link := w.e.Mailer.Token("reset", w.email)
	if err := w.e.Svc.ResetPassword(ctx, link, "reset password 456"); err != nil {
		t.Fatal(err)
	}
	wantErr(t, w.e.Svc.ResetPassword(ctx, link, "again password 789"), auth.ErrInvalidLink)
	_, err = w.e.Svc.Authenticate(ctx, fresh.AccessToken, true)
	wantErr(t, err, auth.ErrUnauthenticated)
	if _, err := w.e.Svc.Login(ctx, w.email, "reset password 456"); err != nil {
		t.Fatal(err)
	}
}

func TestEmailChange(t *testing.T) {
	w := newWorld(t, "member")
	pair := session(t, w.e, w.email, w.ws)
	p := mustAuth(t, w.e, pair.AccessToken)
	if err := w.e.Svc.RequestEmailChange(ctx, p, "New@Example.com"); err != nil {
		t.Fatal(err)
	}
	if err := w.e.Svc.ConfirmEmailChange(ctx, w.e.Mailer.Token("email", "new@example.com")); err != nil {
		t.Fatal(err)
	}
	if w.e.Engine.Users[w.user] != "new@example.com" {
		t.Fatal("engine email not updated")
	}
	if !w.e.Mailer.Has("emailnotice", w.email) {
		t.Fatal("old address not notified")
	}
	_, err := w.e.Svc.Authenticate(ctx, pair.AccessToken, true)
	wantErr(t, err, auth.ErrUnauthenticated)
	if _, err := w.e.Svc.Login(ctx, "new@example.com", pw); err != nil {
		t.Fatal(err)
	}
}

func TestDeleteAccountLastOwner(t *testing.T) {
	w := newWorld(t, "owner")
	pair := session(t, w.e, w.email, w.ws)
	p := mustAuth(t, w.e, pair.AccessToken)
	err := w.e.Svc.DeleteAccount(ctx, p)
	var lo *auth.LastOwnerError
	if !errors.As(err, &lo) || len(lo.Workspaces) != 1 || lo.Workspaces[0].WorkspaceID != w.ws {
		t.Fatalf("got %v", err)
	}
}

func TestDeleteAccountWithoutWorkspace(t *testing.T) {
	e := authtest.NewEnv(t)
	signup(t, e, "lonely@example.com")
	res, err := e.Svc.Login(ctx, "lonely@example.com", pw)
	if err != nil || len(res.Memberships) != 0 {
		t.Fatalf("login: %v %v", err, res.Memberships)
	}
	if err := e.Svc.DeleteAccountWithTicket(ctx, res.Ticket); err != nil {
		t.Fatal(err)
	}
	wantErr(t, e.Svc.DeleteAccountWithTicket(ctx, res.Ticket), auth.ErrUnauthenticated) // single use
	_, err = e.Svc.Login(ctx, "lonely@example.com", pw)
	wantErr(t, err, auth.ErrInvalidCredentials)
}

func TestDeleteAccountWithTicketStillChecksLastOwner(t *testing.T) {
	w := newWorld(t, "owner")
	res, _ := w.e.Svc.Login(ctx, w.email, pw)
	var lo *auth.LastOwnerError
	if err := w.e.Svc.DeleteAccountWithTicket(ctx, res.Ticket); !errors.As(err, &lo) {
		t.Fatalf("got %v, want last owner", err)
	}
}

func TestCreateFirstWorkspace(t *testing.T) {
	e := authtest.NewEnv(t)
	signup(t, e, "new@example.com")
	res, _ := e.Svc.Login(ctx, "new@example.com", pw)
	ws, pair, err := e.Svc.CreateFirstWorkspace(ctx, res.Ticket, "Acme", "acme")
	if err != nil {
		t.Fatal(err)
	}
	p := mustAuth(t, e, pair.AccessToken)
	if p.WorkspaceID != ws.ID || p.Role != auth.RoleOwner {
		t.Fatalf("principal %+v", p)
	}
	_, _, err = e.Svc.CreateFirstWorkspace(ctx, res.Ticket, "Acme2", "acme2")
	wantErr(t, err, auth.ErrUnauthenticated) // ticket already used
}
