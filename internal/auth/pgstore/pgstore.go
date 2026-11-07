// Package pgstore is the Postgres implementation of auth.Store (schema in
// internal/platform/db/migrations). Every multi-step operation runs in one transaction.
package pgstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hesham127/flwnBackend/internal/auth"
)

type Store struct{ pool *pgxpool.Pool }

func New(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

var _ auth.Store = (*Store)(nil)

func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

func (s *Store) tx(ctx context.Context, fn func(pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, s.pool, fn)
}

func notFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.ErrNotFound
	}
	return err
}

func isUnique(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func nullUUID(id uuid.UUID) any {
	if id == uuid.Nil {
		return nil
	}
	return id
}

// ---------------------------------------------------------------------------------------------
// Registration

func (s *Store) CountAttemptsSince(ctx context.Context, email string, since time.Time) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM registration_attempts WHERE email_canonical = $1 AND created_at >= $2`,
		email, since).Scan(&n)
	return n, err
}

func (s *Store) CreateAttempt(ctx context.Context, a auth.RegistrationAttempt) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO registration_attempts
		  (id, email_canonical, display_name, password_hash, verify_token_hash, created_at, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		a.ID, a.Email, a.DisplayName, a.PasswordHash, a.TokenHash, a.CreatedAt, a.ExpiresAt)
	return err
}

func (s *Store) VerifyAttempt(ctx context.Context, hash []byte, credID uuid.UUID, now time.Time) (auth.Credential, error) {
	var out auth.Credential
	err := s.tx(ctx, func(tx pgx.Tx) error {
		var a auth.RegistrationAttempt
		err := tx.QueryRow(ctx, `
			UPDATE registration_attempts SET consumed_at = $2
			WHERE verify_token_hash = $1 AND consumed_at IS NULL AND expires_at > $2
			RETURNING id, email_canonical, display_name, password_hash`,
			hash, now).Scan(&a.ID, &a.Email, &a.DisplayName, &a.PasswordHash)
		if err != nil {
			return notFound(err)
		}
		// Serialize everything that creates a credential for this email.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, a.Email); err != nil {
			return err
		}
		var exists bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM credentials WHERE email_canonical = $1)`, a.Email).Scan(&exists); err != nil {
			return err
		}
		if exists {
			return auth.ErrAccountExists
		}
		out = auth.Credential{
			ID: credID, Email: a.Email, DisplayName: a.DisplayName, PasswordHash: a.PasswordHash,
			Status: auth.StatusProvisioning, AuthVersion: 1, ProvisioningAttemptID: a.ID, CreatedAt: now, UpdatedAt: now,
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO credentials (id, email_canonical, display_name, password_hash, status, auth_version,
			                         provisioning_attempt_id, created_at, updated_at)
			VALUES ($1,$2,$3,$4,'provisioning',1,$5,$6,$6)`,
			out.ID, out.Email, out.DisplayName, out.PasswordHash, a.ID, now); err != nil {
			if isUnique(err) {
				return auth.ErrAccountExists
			}
			return err
		}
		_, err = tx.Exec(ctx, `DELETE FROM registration_attempts WHERE email_canonical = $1 AND id <> $2`, a.Email, a.ID)
		return err
	})
	// The consumed attempt must stay consumed even when the account exists, so a failed verify
	// cannot be replayed; ErrAccountExists rolls back, so mark it again outside the tx.
	if errors.Is(err, auth.ErrAccountExists) {
		_, _ = s.pool.Exec(ctx, `UPDATE registration_attempts SET consumed_at = $2 WHERE verify_token_hash = $1`, hash, now)
	}
	return out, err
}

const credCols = `id, user_id, email_canonical, display_name, password_hash, status, auth_version,
	provisioning_attempt_id, failed_attempts, next_allowed_at, created_at, updated_at`

func scanCred(row pgx.Row) (auth.Credential, error) {
	var c auth.Credential
	var userID, attemptID *uuid.UUID
	var next *time.Time
	var status string
	err := row.Scan(&c.ID, &userID, &c.Email, &c.DisplayName, &c.PasswordHash, &status, &c.AuthVersion,
		&attemptID, &c.FailedAttempts, &next, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return c, notFound(err)
	}
	c.Status = auth.CredentialStatus(status)
	if userID != nil {
		c.UserID = *userID
	}
	if attemptID != nil {
		c.ProvisioningAttemptID = *attemptID
	}
	if next != nil {
		c.NextAllowedAt = *next
	}
	return c, nil
}

func (s *Store) ListProvisioning(ctx context.Context, olderThan time.Time, limit int) ([]auth.Credential, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+credCols+` FROM credentials
		WHERE status = 'provisioning' AND updated_at < $1 ORDER BY updated_at LIMIT $2`, olderThan, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []auth.Credential
	for rows.Next() {
		c, err := scanCred(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) ActivateCredential(ctx context.Context, credID, userID uuid.UUID, now time.Time) error {
	tag, err := s.pool.Exec(ctx, `UPDATE credentials SET user_id = $2, status = 'active', updated_at = $3
		WHERE id = $1 AND status = 'provisioning'`, credID, userID, now)
	if isUnique(err) {
		return auth.ErrAccountExists
	}
	if err == nil && tag.RowsAffected() == 0 {
		return auth.ErrNotFound
	}
	return err
}

// ---------------------------------------------------------------------------------------------
// Credentials

func (s *Store) CredentialByEmail(ctx context.Context, email string) (auth.Credential, error) {
	return scanCred(s.pool.QueryRow(ctx, `SELECT `+credCols+` FROM credentials WHERE email_canonical = $1`, email))
}

func (s *Store) CredentialByUserID(ctx context.Context, userID uuid.UUID) (auth.Credential, error) {
	return scanCred(s.pool.QueryRow(ctx, `SELECT `+credCols+` FROM credentials WHERE user_id = $1`, userID))
}

func (s *Store) CredentialByID(ctx context.Context, id uuid.UUID) (auth.Credential, error) {
	return scanCred(s.pool.QueryRow(ctx, `SELECT `+credCols+` FROM credentials WHERE id = $1`, id))
}

func (s *Store) RecordLoginFailure(ctx context.Context, credID uuid.UUID, now time.Time) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `UPDATE credentials SET failed_attempts = failed_attempts + 1
			WHERE id = $1 RETURNING failed_attempts`, credID).Scan(&n); err != nil {
			return notFound(err)
		}
		if d := auth.LoginBackoff(n); d > 0 {
			_, err := tx.Exec(ctx, `UPDATE credentials SET next_allowed_at = $2 WHERE id = $1`, credID, now.Add(d))
			return err
		}
		return nil
	})
}

func (s *Store) RecordLoginSuccess(ctx context.Context, credID uuid.UUID, _ time.Time) error {
	_, err := s.pool.Exec(ctx, `UPDATE credentials SET failed_attempts = 0, next_allowed_at = NULL
		WHERE id = $1 AND (failed_attempts <> 0 OR next_allowed_at IS NOT NULL)`, credID)
	return err
}

func (s *Store) SetPasswordHash(ctx context.Context, credID uuid.UUID, hash string, now time.Time) error {
	_, err := s.pool.Exec(ctx, `UPDATE credentials SET password_hash = $2, updated_at = $3 WHERE id = $1`, credID, hash, now)
	return err
}

func (s *Store) UpdateAccount(ctx context.Context, credID uuid.UUID, u auth.AccountUpdate, now time.Time) (auth.Credential, error) {
	var out auth.Credential
	err := s.tx(ctx, func(tx pgx.Tx) error {
		var status *string
		if u.Status != nil {
			v := string(*u.Status)
			status = &v
		}
		bump := 0
		if u.BumpVersion {
			bump = 1
		}
		c, err := scanCred(tx.QueryRow(ctx, `
			UPDATE credentials SET
			  password_hash   = COALESCE($2, password_hash),
			  email_canonical = COALESCE($3, email_canonical),
			  status          = COALESCE($4, status),
			  failed_attempts = CASE WHEN $5 THEN 0 ELSE failed_attempts END,
			  next_allowed_at = CASE WHEN $5 THEN NULL ELSE next_allowed_at END,
			  auth_version    = auth_version + $6,
			  updated_at      = $7
			WHERE id = $1
			RETURNING `+credCols, credID, u.PasswordHash, u.Email, status, u.ResetFailures, bump, now))
		if err != nil {
			if isUnique(err) {
				return auth.ErrAccountExists
			}
			return err
		}
		out = c
		if !u.BumpVersion {
			return nil
		}
		reason := u.Reason
		if reason == "" {
			reason = "account_revoked"
		}
		if _, err := tx.Exec(ctx, `UPDATE login_sessions SET revoked_at = $2, revoke_reason = $3
			WHERE credential_id = $1 AND revoked_at IS NULL`, credID, now, reason); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE refresh_families SET revoked_at = $2, revoke_reason = $3
			WHERE user_id = $1 AND revoked_at IS NULL`, c.UserID, now, reason)
		return err
	})
	return out, err
}

// ---------------------------------------------------------------------------------------------
// Tickets and sessions

func (s *Store) CreateTicket(ctx context.Context, t auth.LoginTicket) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO login_tickets
		(token_hash, credential_id, user_id, auth_version, auth_time, created_at, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		t.Hash, t.CredentialID, t.UserID, t.AuthVersion, t.AuthTime, t.CreatedAt, t.ExpiresAt)
	return err
}

func (s *Store) ConsumeTicket(ctx context.Context, hash []byte, now time.Time) (auth.LoginTicket, error) {
	t := auth.LoginTicket{Hash: hash}
	err := s.pool.QueryRow(ctx, `UPDATE login_tickets SET consumed_at = $2
		WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > $2
		RETURNING credential_id, user_id, auth_version, auth_time, created_at, expires_at`, hash, now).
		Scan(&t.CredentialID, &t.UserID, &t.AuthVersion, &t.AuthTime, &t.CreatedAt, &t.ExpiresAt)
	return t, notFound(err)
}

func (s *Store) CreateLoginSession(ctx context.Context, ls auth.LoginSession) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO login_sessions
		(id, credential_id, user_id, auth_version, auth_time, created_at, absolute_expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		ls.ID, ls.CredentialID, ls.UserID, ls.AuthVersion, ls.AuthTime, ls.CreatedAt, ls.AbsoluteExpiresAt)
	return err
}

func (s *Store) SetAuthTime(ctx context.Context, id uuid.UUID, t time.Time) error {
	_, err := s.pool.Exec(ctx, `UPDATE login_sessions SET auth_time = $2 WHERE id = $1 AND revoked_at IS NULL`, id, t)
	return err
}

func insertAccess(ctx context.Context, tx pgx.Tx, a auth.AccessRecord) error {
	_, err := tx.Exec(ctx, `INSERT INTO access_tokens (jti, family_id, auth_version, issued_at, expires_at)
		VALUES ($1,$2,$3,$4,$5)`, a.JTI, a.FamilyID, a.AuthVersion, a.IssuedAt, a.ExpiresAt)
	return err
}

func insertRefresh(ctx context.Context, tx pgx.Tx, r auth.RefreshToken) error {
	_, err := tx.Exec(ctx, `INSERT INTO refresh_tokens (id, family_id, generation, token_hash, created_at)
		VALUES ($1,$2,$3,$4,$5)`, r.ID, r.FamilyID, r.Generation, r.Hash, r.CreatedAt)
	return err
}

func (s *Store) CreateFamily(ctx context.Context, f auth.RefreshFamily, rt auth.RefreshToken, at auth.AccessRecord) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO refresh_families
			(id, login_session_id, user_id, workspace_id, member_id, auth_version, created_at, idle_expires_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			f.ID, f.LoginSessionID, f.UserID, f.WorkspaceID, f.MemberID, f.AuthVersion, f.CreatedAt, f.IdleExpiresAt); err != nil {
			return err
		}
		if err := insertRefresh(ctx, tx, rt); err != nil {
			return err
		}
		return insertAccess(ctx, tx, at)
	})
}

const familyCols = `f.id, f.login_session_id, f.user_id, f.workspace_id, f.member_id, f.auth_version,
	f.created_at, f.idle_expires_at, f.revoked_at`
const sessionCols = `ls.id, ls.credential_id, ls.user_id, ls.auth_version, ls.auth_time, ls.created_at,
	ls.absolute_expires_at, ls.revoked_at`
const credColsC = `c.id, c.user_id, c.email_canonical, c.display_name, c.password_hash, c.status, c.auth_version,
	c.provisioning_attempt_id, c.failed_attempts, c.next_allowed_at, c.created_at, c.updated_at`

func (s *Store) RefreshByHash(ctx context.Context, hash []byte) (auth.RefreshToken, auth.RefreshFamily, auth.LoginSession, auth.Credential, error) {
	var rt auth.RefreshToken
	var f auth.RefreshFamily
	var ls auth.LoginSession
	var c auth.Credential
	var userID, attemptID *uuid.UUID
	var next *time.Time
	var status string
	err := s.pool.QueryRow(ctx, `
		SELECT rt.id, rt.family_id, rt.generation, rt.token_hash, rt.created_at, rt.used_at,
		       `+familyCols+`, `+sessionCols+`, `+credColsC+`
		FROM refresh_tokens rt
		JOIN refresh_families f ON f.id = rt.family_id
		JOIN login_sessions ls ON ls.id = f.login_session_id
		JOIN credentials c ON c.id = ls.credential_id
		WHERE rt.token_hash = $1`, hash).Scan(
		&rt.ID, &rt.FamilyID, &rt.Generation, &rt.Hash, &rt.CreatedAt, &rt.UsedAt,
		&f.ID, &f.LoginSessionID, &f.UserID, &f.WorkspaceID, &f.MemberID, &f.AuthVersion, &f.CreatedAt, &f.IdleExpiresAt, &f.RevokedAt,
		&ls.ID, &ls.CredentialID, &ls.UserID, &ls.AuthVersion, &ls.AuthTime, &ls.CreatedAt, &ls.AbsoluteExpiresAt, &ls.RevokedAt,
		&c.ID, &userID, &c.Email, &c.DisplayName, &c.PasswordHash, &status, &c.AuthVersion, &attemptID, &c.FailedAttempts, &next, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return rt, f, ls, c, notFound(err)
	}
	c.Status = auth.CredentialStatus(status)
	if userID != nil {
		c.UserID = *userID
	}
	if next != nil {
		c.NextAllowedAt = *next
	}
	return rt, f, ls, c, nil
}

func (s *Store) Rotate(ctx context.Context, old, next auth.RefreshToken, at auth.AccessRecord, idle, now time.Time) error {
	reused := false
	err := s.tx(ctx, func(tx pgx.Tx) error {
		var revoked *time.Time
		if err := tx.QueryRow(ctx, `SELECT revoked_at FROM refresh_families WHERE id = $1 FOR UPDATE`,
			old.FamilyID).Scan(&revoked); err != nil {
			return notFound(err)
		}
		if revoked != nil {
			return auth.ErrNotFound
		}
		tag, err := tx.Exec(ctx, `UPDATE refresh_tokens SET used_at = $2 WHERE id = $1 AND used_at IS NULL`, old.ID, now)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			reused = true
			return auth.ErrRefreshReused
		}
		if _, err := tx.Exec(ctx, `UPDATE refresh_families SET idle_expires_at = $2 WHERE id = $1`, old.FamilyID, idle); err != nil {
			return err
		}
		if err := insertRefresh(ctx, tx, next); err != nil {
			return err
		}
		return insertAccess(ctx, tx, at)
	})
	if reused {
		// Strict reuse detection: the token was already used, so the whole family dies.
		if rerr := s.RevokeFamily(ctx, old.FamilyID, "refresh_reused", now); rerr != nil {
			return fmt.Errorf("%w (revoke failed: %v)", auth.ErrRefreshReused, rerr)
		}
	}
	return err
}

func (s *Store) RevokeFamily(ctx context.Context, id uuid.UUID, reason string, now time.Time) error {
	_, err := s.pool.Exec(ctx, `UPDATE refresh_families SET revoked_at = $2, revoke_reason = $3
		WHERE id = $1 AND revoked_at IS NULL`, id, now, reason)
	return err
}

func (s *Store) RevokeLoginSession(ctx context.Context, id uuid.UUID, reason string, now time.Time) error {
	_, err := s.pool.Exec(ctx, `UPDATE login_sessions SET revoked_at = $2, revoke_reason = $3
		WHERE id = $1 AND revoked_at IS NULL`, id, now, reason)
	return err
}

func (s *Store) RevokeMemberFamilies(ctx context.Context, ws, mem uuid.UUID, reason string, now time.Time) error {
	_, err := s.pool.Exec(ctx, `UPDATE refresh_families SET revoked_at = $3, revoke_reason = $4
		WHERE workspace_id = $1 AND member_id = $2 AND revoked_at IS NULL`, ws, mem, now, reason)
	return err
}

func (s *Store) RevokeWorkspaceFamilies(ctx context.Context, ws uuid.UUID, reason string, now time.Time) error {
	_, err := s.pool.Exec(ctx, `UPDATE refresh_families SET revoked_at = $2, revoke_reason = $3
		WHERE workspace_id = $1 AND revoked_at IS NULL`, ws, now, reason)
	return err
}

func (s *Store) RevokeAccessToken(ctx context.Context, jti string, now time.Time) error {
	_, err := s.pool.Exec(ctx, `UPDATE access_tokens SET revoked_at = $2 WHERE jti = $1 AND revoked_at IS NULL`, jti, now)
	return err
}

// AccessState is the one indexed query per request (PK lookups joined).
func (s *Store) AccessState(ctx context.Context, jti string) (auth.AccessState, error) {
	var st auth.AccessState
	a, f, ls, c := &st.Access, &st.Family, &st.Session, &st.Credential
	var userID, attemptID *uuid.UUID
	var next *time.Time
	var status string
	err := s.pool.QueryRow(ctx, `
		SELECT a.jti, a.family_id, a.auth_version, a.issued_at, a.expires_at, a.revoked_at,
		       `+familyCols+`, `+sessionCols+`, `+credColsC+`
		FROM access_tokens a
		JOIN refresh_families f ON f.id = a.family_id
		JOIN login_sessions ls ON ls.id = f.login_session_id
		JOIN credentials c ON c.id = ls.credential_id
		WHERE a.jti = $1`, jti).Scan(
		&a.JTI, &a.FamilyID, &a.AuthVersion, &a.IssuedAt, &a.ExpiresAt, &a.RevokedAt,
		&f.ID, &f.LoginSessionID, &f.UserID, &f.WorkspaceID, &f.MemberID, &f.AuthVersion, &f.CreatedAt, &f.IdleExpiresAt, &f.RevokedAt,
		&ls.ID, &ls.CredentialID, &ls.UserID, &ls.AuthVersion, &ls.AuthTime, &ls.CreatedAt, &ls.AbsoluteExpiresAt, &ls.RevokedAt,
		&c.ID, &userID, &c.Email, &c.DisplayName, &c.PasswordHash, &status, &c.AuthVersion, &attemptID, &c.FailedAttempts, &next, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return st, notFound(err)
	}
	c.Status = auth.CredentialStatus(status)
	if userID != nil {
		c.UserID = *userID
	}
	return st, nil
}

// ---------------------------------------------------------------------------------------------
// Links, idempotency, audit, cleanup

func (s *Store) CreatePasswordReset(ctx context.Context, hash []byte, credID uuid.UUID, now, exp time.Time) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO password_resets (token_hash, credential_id, created_at, expires_at)
		VALUES ($1,$2,$3,$4)`, hash, credID, now, exp)
	return err
}

func (s *Store) ConsumePasswordReset(ctx context.Context, hash []byte, now time.Time) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.pool.QueryRow(ctx, `UPDATE password_resets SET consumed_at = $2
		WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > $2 RETURNING credential_id`, hash, now).Scan(&id)
	return id, notFound(err)
}

func (s *Store) CreateEmailChange(ctx context.Context, hash []byte, credID uuid.UUID, email string, now, exp time.Time) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO email_changes (token_hash, credential_id, new_email, created_at, expires_at)
		VALUES ($1,$2,$3,$4,$5)`, hash, credID, email, now, exp)
	return err
}

func (s *Store) ConsumeEmailChange(ctx context.Context, hash []byte, now time.Time) (uuid.UUID, string, error) {
	var id uuid.UUID
	var email string
	err := s.pool.QueryRow(ctx, `UPDATE email_changes SET consumed_at = $2
		WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > $2
		RETURNING credential_id, new_email`, hash, now).Scan(&id, &email)
	return id, email, notFound(err)
}

func (s *Store) GetIdempotency(ctx context.Context, userID uuid.UUID, route, key string) (auth.IdempotencyRecord, error) {
	r := auth.IdempotencyRecord{Key: key, UserID: userID, Route: route}
	err := s.pool.QueryRow(ctx, `SELECT request_hash, status_code, response_json, created_at
		FROM idempotency_keys WHERE user_id = $1 AND route = $2 AND key = $3`, userID, route, key).
		Scan(&r.RequestHash, &r.StatusCode, &r.ResponseJSON, &r.CreatedAt)
	return r, notFound(err)
}

func (s *Store) ReserveIdempotency(ctx context.Context, r auth.IdempotencyRecord) error {
	body := r.ResponseJSON
	if body == nil {
		body = []byte{}
	}
	// Takes the key, or takes over a record that is expired (24h) or a stale pending reservation
	// (crashed request, > 1 min). A live record makes the upsert affect no row.
	tag, err := s.pool.Exec(ctx, `INSERT INTO idempotency_keys
		(key, user_id, route, request_hash, status_code, response_json, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (user_id, route, key) DO UPDATE SET
		  request_hash = EXCLUDED.request_hash, status_code = EXCLUDED.status_code,
		  response_json = EXCLUDED.response_json, created_at = EXCLUDED.created_at
		WHERE idempotency_keys.created_at < EXCLUDED.created_at - interval '24 hours'
		   OR (idempotency_keys.status_code = 0 AND idempotency_keys.created_at < EXCLUDED.created_at - interval '1 minute')`,
		r.Key, r.UserID, r.Route, r.RequestHash, r.StatusCode, body, r.CreatedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return auth.ErrIdempotencyHit
	}
	return nil
}

func (s *Store) CompleteIdempotency(ctx context.Context, userID uuid.UUID, route, key string, status int, body []byte) error {
	_, err := s.pool.Exec(ctx, `UPDATE idempotency_keys SET status_code = $4, response_json = $5
		WHERE user_id = $1 AND route = $2 AND key = $3 AND status_code = 0`, userID, route, key, status, body)
	return err
}

func (s *Store) ReleaseIdempotency(ctx context.Context, userID uuid.UUID, route, key string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM idempotency_keys
		WHERE user_id = $1 AND route = $2 AND key = $3 AND status_code = 0`, userID, route, key)
	return err
}

func (s *Store) Audit(ctx context.Context, kind string, userID uuid.UUID, detail map[string]any, now time.Time) error {
	if detail == nil {
		detail = map[string]any{}
	}
	b, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO audit_events (at, kind, user_id, detail) VALUES ($1,$2,$3,$4)`,
		now, kind, nullUUID(userID), b)
	return err
}

// Cleanup deletes expired rows in batches of 5000. Revoked/expired sessions are kept 7 days for
// audit; audit events 90 days.
func (s *Store) Cleanup(ctx context.Context, now time.Time) (int64, error) {
	stmts := []string{
		`DELETE FROM access_tokens WHERE jti IN (SELECT jti FROM access_tokens WHERE expires_at < $1::timestamptz - interval '1 hour' LIMIT 5000)`,
		`DELETE FROM login_tickets WHERE token_hash IN (SELECT token_hash FROM login_tickets WHERE expires_at < $1::timestamptz - interval '1 hour' LIMIT 5000)`,
		`DELETE FROM registration_attempts WHERE id IN (SELECT id FROM registration_attempts WHERE expires_at < $1::timestamptz LIMIT 5000)`,
		`DELETE FROM password_resets WHERE token_hash IN (SELECT token_hash FROM password_resets WHERE expires_at < $1::timestamptz - interval '1 day' LIMIT 5000)`,
		`DELETE FROM email_changes WHERE token_hash IN (SELECT token_hash FROM email_changes WHERE expires_at < $1::timestamptz - interval '1 day' LIMIT 5000)`,
		`DELETE FROM idempotency_keys WHERE (user_id, route, key) IN (SELECT user_id, route, key FROM idempotency_keys WHERE created_at < $1::timestamptz - interval '24 hours' LIMIT 5000)`,
		`DELETE FROM refresh_families WHERE id IN (SELECT id FROM refresh_families
		   WHERE COALESCE(revoked_at, idle_expires_at) < $1::timestamptz - interval '7 days' LIMIT 5000)`,
		`DELETE FROM login_sessions WHERE id IN (SELECT id FROM login_sessions
		   WHERE COALESCE(revoked_at, absolute_expires_at) < $1::timestamptz - interval '7 days' LIMIT 5000)`,
		`DELETE FROM audit_events WHERE id IN (SELECT id FROM audit_events WHERE at < $1::timestamptz - interval '90 days' LIMIT 5000)`,
		// Provisioning credentials are never deleted here: their email is proven, so the
		// reconciler keeps retrying and alerts after 1h.
	}
	var total int64
	for _, q := range stmts {
		tag, err := s.pool.Exec(ctx, q, now)
		if err != nil {
			return total, err
		}
		total += tag.RowsAffected()
	}
	return total, nil
}
