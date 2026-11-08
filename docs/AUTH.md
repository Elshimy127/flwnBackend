# Authentication and authorization

flwnBackend is the only service that checks passwords, decides scopes and signs tokens. The
data engine owns identity data (users, workspaces, members, roles, statuses) and never sees a
password. Code comments refer to the sections below as `docs/AUTH.md §N`.

## Ownership and trust boundaries (§1)

| Data | Owner | Where |
|---|---|---|
| Password hash, login email, account status, `auth_version` | backend | `flwn_auth.auth.credentials` |
| Login sessions, refresh families/tokens, access-token index, tickets, reset/verify links, idempotency keys, audit log | backend | `flwn_auth.auth.*` |
| Profile, workspaces, members, role, status, type | data engine | engine Postgres |
| Role → scope map | backend code | `internal/auth/scopes.go` |

```
browser / native client ──HTTPS──▶ flwnBackend ──service key + X-Acting-Member-Id──▶ data engine
                                      │                                                 (private network)
                                      └── flwn_auth (own DB, own roles; engine/AI roles: no access)
```

* The engine's service key passes every engine scope check, so **the backend is the
  authorization point**: every route goes through `secure.Router` with a declared policy.
* Request handlers get `*dataengine.Client`, which refuses any call without an authenticated
  acting member. The auth service and background jobs use `dataengine.SystemClient` (no acting
  member, identity endpoints only, every call logged as `actor=system`).
* Inbound `X-Acting-Member-Id`, `X-Data-API-Key` and `X-Member-Id` are stripped.

## Tokens

Header `kid`. Claims: `iss` (`flwn-backend`), `aud` (`["flwn-backend"]`), `sub`, `ws`, `typ`,
`mem`, `scope` (space-separated string), `iat`, `nbf`, `exp` (≤ 15 min), `jti`. Human tokens:
`sub = mem = member id`; `obo`, `act`, `agent`, `run` must be absent. `agent`/`run`/`service`
tokens are parsed and rejected until a later phase. No email, name or user id in tokens.

The verifier allows only HS256, rejects unknown `kid`, checks `iss` exactly and that `aud`
contains `flwn-backend`, requires `iat`/`nbf`/`exp` (30 s leeway, lifetime ≤ 15 min), decodes
types strictly (a scope array is rejected) and applies per-`typ` claim rules.

The login ticket is **not** a JWT: an opaque 256-bit value, SHA-256 stored, single-use,
5 minutes, accepted only by `/auth/session` and `/auth/workspaces`.

## Revocation (§1–2)

Every access token is registered (`access_tokens`) at issue, and each request does one indexed
query joining access token → family → login session → credential. A token is valid only if
none of them is revoked/expired and `access_tokens.auth_version = credentials.auth_version`.

| Level | Action | Ends | Triggered by |
|---|---|---|---|
| Account | `auth_version += 1` (+ mark sessions revoked) | everything of the user | password change/reset, logout-all, account disable/delete, email change |
| Login session | `login_sessions.revoked_at` | all workspaces of one device | `/auth/logout-device` |
| Refresh family | `refresh_families.revoked_at` | one workspace session | logout, refresh reuse, member suspended/removed/mismatch |
| Access token | `access_tokens.revoked_at` | one token | logout with a still-valid access token, admin tooling |

All levels apply on the next request. If the auth DB is unreachable, requests get 503.

## Registration (§3, §7)

No credential exists, and no engine user is created, until the email is proven. Attempts are
per attempt, not per email, so an attacker's earlier sign-up can neither block nor capture the
real owner's account.

1. `POST /auth/register` → `registration_attempts` row + verification mail. Always 202. If an
   active account exists, no attempt is created and a "someone tried to sign up" mail is sent.
   5 attempts per email per hour, plus per-IP limits.
2. `POST /auth/verify-email` consumes that attempt and, under
   `pg_advisory_xact_lock(hashtext(email))`, creates a `provisioning` credential with **that
   attempt's** password; other attempts for the email are deleted.
3. Provisioning: engine `GET /users?email=` → link, else `POST /users` (409 → look up and link)
   → credential `active`. The canonical email is the natural key, so retries are safe.
4. A crash or engine outage leaves the credential `provisioning`; the reconciler (every 60 s)
   retries and alerts after 1 h, and a login with the right password resumes it inline. Login is
   refused (`account_provisioning`) until it is `active`.

## Refresh (§4)

Strict reuse detection, no grace window: presenting an already-used refresh token revokes its
family (`refresh_reused`). A grace window cannot tell a legitimate retry from an attacker who
replays within the window. Accepted cost: concurrent refreshes or a lost response log out that
workspace session; clients must single-flight refreshes (Web Locks across tabs) and refresh at
~80 % of the access lifetime. Rotation is one transaction (`SELECT … FOR UPDATE` on the family,
`UPDATE … WHERE used_at IS NULL`). Idle expiry 7 days, absolute 30 days per login session.

## Workspaces (§5)

Login returns a ticket plus the user's active HUMAN memberships and never returns tokens.
Every token pair comes from one function, `issueSession`: ticket exchange (`/auth/session`),
first workspace (`/auth/workspaces`), switch (`/auth/switch`, needs the refresh token, not an
access token) and password change. Switching opens a new family in the same login session; the
old one stays usable (multiple tabs). The engine creates a workspace and its owner member in one
transaction (`owner_user_id`) and keeps at least one active human owner (409 `last_owner`).

## Engine contract (§6)

| Endpoint | Used for |
|---|---|
| `GET /users/{id}/memberships?status=active&type=HUMAN` (service-only) | login list, switcher, session issuance |
| `GET /workspaces/{ws}/members/{mid}` | per-request live check |
| `GET /users?email=`, `POST /users` (409 `email_taken`) | provisioning |
| `POST /workspaces` + `owner_user_id` | atomic create |
| `POST /workspaces/{ws}/ownership/transfer`, member PATCH/DELETE (409 `last_owner`) | ownership |

Backend reactions: member 404 or mismatch (workspace, id, user, type) → 401 + family revoked;
unknown role/type/status → 403; engine 401/403 (our key) or 5xx/timeout → 503 (fail closed).
Auth lookups time out after 2 s; GETs retry once, writes never.

Per-request membership check: writes and `identity:*` never use a cache; reads may use a 5 s
cache that the member/workspace services invalidate synchronously when they change a role or
status. Effective scopes = token scopes ∩ live role scopes: demotion applies at once, promotion
at the next refresh.

## Routes (§8)

Modes: `PUBLIC`, `TICKET`, `REFRESH` (cookie + CSRF + Origin, or native body), `ACCESS`
(Bearer + live checks + `:workspace_id`/body `workspace_id` must equal the token's `ws`),
`RECENT` (ACCESS + password verified within 10 minutes). Routes can only be registered through
`secure.Router`; `tests/security_test.go` fails on any route without a policy or any public
route outside the allowlist.

| Route | Mode | Authorization |
|---|---|---|
| `/healthz`, `/readyz` | PUBLIC | — |
| `POST /auth/register`, `/verify-email`, `/login`, `/password/forgot`, `/password/reset`, `/email/confirm` | PUBLIC | rate limited |
| `POST /auth/session`, `/auth/workspaces` (+ `/auth/native/…`) | TICKET | active HUMAN membership |
| `POST /auth/account/delete` | TICKET | account deletion for a user with no workspace left (tokens are workspace-bound); the ticket is a password check < 5 min old; last-owner check applies |
| `POST /auth/refresh`, `/logout`, `/switch` (+ `/auth/native/…`) | REFRESH | — |
| `POST /auth/csrf` | REFRESH | browser only: Origin + refresh cookie, no CSRF header; returns the CSRF token after a reload |
| `GET /auth/me`, `/auth/workspaces`; `POST /auth/reauth`, `/password`, `/logout-device` | ACCESS | own data only |
| `POST /auth/logout-all`, `/auth/email`; `DELETE /auth/account` | RECENT | last-owner check on delete |
| `POST /workspaces` | ACCESS | Idempotency-Key (reserved before the handler runs: a concurrent duplicate gets 409 `request_in_progress`, a repeat gets the stored response, another body gets 409 `idempotency_key_reused`, a failed request frees the key); caller becomes owner |
| `GET /workspaces` | ACCESS | own memberships only |
| `GET /workspaces/:ws` | ACCESS | `identity:read` |
| `PATCH /workspaces/:ws` | ACCESS | `identity:write`, admin+ |
| `DELETE /workspaces/:ws`, `POST …/ownership/transfer` | RECENT | owner |
| `/workspaces/:ws/members`, `/teams` | ACCESS | read `identity:read`; write `identity:write` + admin+; owner role changes need owner; member email changes refused |
| projects, work items, sprints, tasks, by-key, member projects/tasks | ACCESS | read `planning:read`; write `planning:write` |
| `GET/PATCH /users/:id` | ACCESS | self only; `email` refused (use `/auth/email`) |

`POST /users`, `GET /users` and `DELETE /users/:id` are no longer exposed.

## Browser model (§9)

* Access token: JS memory only, `Authorization: Bearer`. Never localStorage/sessionStorage.
* Refresh token: `__Secure-flwn_rt_<workspace>` cookie, `HttpOnly; Secure; SameSite=Strict;
  Path=/api/v1/auth`, one per workspace so tabs can hold different workspaces. Cookie routes
  name the workspace in `X-Workspace-Id`.
* CSRF (cookie routes only): `__Host-flwn_csrf` (readable, `Path=/`) = HMAC(`CSRF_KEY`, login
  session id), echoed in `X-CSRF-Token`, compared in constant time, **and** `Origin` must be in
  `FRONTEND_ORIGINS`. A new login rotates it; families from an older login in the same browser
  then need a fresh login.
* CORS: exact allowlist; credentials only on `/api/v1/auth/*`; `/api/v1/auth/native/*` sends no
  CORS headers and never reads or sets cookies.
* Auth responses: `Cache-Control: no-store`. HSTS when `HSTS=true`.
* Assumes the frontend and API are same-site (e.g. `app.` and `api.` under one domain).
* Page reload: JS on `app.` cannot read the API host's CSRF cookie, and the access token is
  gone. Recover with `POST /auth/csrf` (`credentials: 'include'`, `X-Workspace-Id`, no CSRF
  header): Origin must be allowlisted and the workspace's refresh cookie valid; it returns
  `{"csrf_token"}` and changes no state. Then call `/auth/refresh` as usual.
* Local http development (`COOKIE_SECURE=false`): cookies are named `flwn_rt_<workspace>` and
  `flwn_csrf`, because browsers reject `__Secure-`/`__Host-` cookies without the Secure flag.

## Recent authentication (§10)

`login_sessions.auth_time` moves only when a password is verified (login, `/auth/reauth`);
refresh and switch never move it. RECENT routes need `auth_time ≥ now − 10 min`, otherwise
401 `reauth_required`. Password change requires the current password in the request.

## Email identity (§12)

`auth.CanonicalEmail`: trim; reject control characters, > 254 chars, no `@`; split at the last
`@`; domain → IDNA ASCII, lowercase; local part → NFC, lowercase; no dot or `+tag` stripping.
The engine stores exactly this string and has a unique index on it. Email change: RECENT
request → link to the new address → engine update (409 aborts) → credential update +
`auth_version++` → notice to the old address.

## Database roles (§13)

`deploy/auth_db_bootstrap.sql` creates `flwn_auth_owner` (NOLOGIN, owns everything),
`flwn_auth_migrator` (LOGIN, member of owner; used only by `go run . migrate` with
`AUTH_MIGRATE_DATABASE_URL`) and `flwn_auth_app` (LOGIN, DML only on `auth.*`, no DDL/TRUNCATE,
NOBYPASSRLS). `PUBLIC` has nothing; engine and AI roles get nothing. `deploy/auth_db_verify.sql`
lists the checks. The server refuses to start if the schema is older than
`db.RequiredVersion`; `/readyz` checks the auth DB and the engine. Migrations are forward-only
(goose, embedded SQL, one transaction each). Production: `sslmode=verify-full`, firewall to the
backend subnet only, Azure automated backups and a restore drill (deployment task).

## Authorization (§14)

| Role | Scopes |
|---|---|
| viewer | `identity:read planning:read collab:read files:read meetings:read memory:read conflicts:read` |
| member | viewer + `planning:write collab:write files:write meetings:write memory:write conflicts:write` |
| admin, owner | member + `identity:write` (owner-only actions are role checks) |

Never in human tokens: `admin`, `memory:maintain`, `memory:delete`, `files:delete`, `atoms:*`,
`skills:*`, `aggregate:read`. Unknown roles get nothing. `internal/auth/engine_scopes.go` is a
copy of the engine vocabulary; `scripts/check_engine_scopes.sh` diffs it in CI.

The workspace is the hard boundary (token `ws` = path, plus engine row-level security). Inside a
workspace there is no per-project ACL in v1: anyone holding `planning:write` may edit any
planning object. Collab privacy stays with the engine's viewer logic.

**Agents (later phase).** `typ=agent`, `sub = mem = agent member id`, `obo` = human member id
when delegated, `aud=["data-engine"]`, `scope = RoleScopes(agent) ∩ grant ∩ RoleScopes(obo)`
minus `identity:write` and owner actions; minted only by the backend; engine-to-engine hops set
`act`.

## Passwords

Argon2id (m = 64 MiB, t = 3, p = 2; benchmark with `go test ./internal/auth -bench Argon2` and
tune to 150–300 ms), 16-byte salt, PHC string, rehash on login when parameters change. No pepper
in v1. Length 10–256, no composition rules. Login failures: atomic counter, progressive delay
(from the 5th failure, doubling, capped at 15 min), no hard lockout, per-IP limits plus a
per (IP, canonical email / user) limit on login, register, forgot-password and reauth, generic
`invalid_credentials`, dummy hash for unknown emails.

## Runbook

* **Local:** create the DB with the bootstrap script, then `AUTH_MIGRATE_DATABASE_URL=… go run . migrate`,
  then fill `.env` from `.env.example` and run `go run .`. Verification links print to stdout
  (`[dev-mail]`).
* **Rotate the JWT key:** add `k2:<secret>` to `JWT_KEYS`, set `JWT_ACTIVE_KID=k2`, deploy;
  remove `k1` after 15 minutes.
* **Rotate the engine service key:** set `DATA_API_KEY_NEXT` on the engine, switch the
  backend's `DATA_API_KEY`, then promote the new key on the engine.
* **Tests:** `go test ./...`; Postgres store: `AUTH_TEST_DATABASE_URL=… go test -tags pgintegration ./internal/auth/pgstore/`;
  full flow against a real engine: `DATA_API_KEY=… go test -tags integration ./tests/ -run Integration -v`.
