-- +goose Up
-- Backend-owned auth state (docs/AUTH.md). Only flwn_auth_app may read or change it.

CREATE TABLE auth.registration_attempts (
    id                 uuid PRIMARY KEY,
    email_canonical    text        NOT NULL CHECK (length(email_canonical) BETWEEN 3 AND 254),
    display_name       text        NOT NULL CHECK (length(display_name) BETWEEN 1 AND 200),
    password_hash      text        NOT NULL,
    verify_token_hash  bytea       NOT NULL UNIQUE,
    created_at         timestamptz NOT NULL,
    expires_at         timestamptz NOT NULL,
    consumed_at        timestamptz,
    CHECK (expires_at > created_at)
);
CREATE INDEX registration_attempts_email_idx ON auth.registration_attempts (email_canonical, created_at);
CREATE INDEX registration_attempts_expires_idx ON auth.registration_attempts (expires_at);

CREATE TABLE auth.credentials (
    id                       uuid PRIMARY KEY,
    user_id                  uuid UNIQUE,
    email_canonical          text        NOT NULL UNIQUE CHECK (length(email_canonical) BETWEEN 3 AND 254),
    display_name             text        NOT NULL,
    password_hash            text        NOT NULL,
    status                   text        NOT NULL CHECK (status IN ('provisioning', 'active', 'disabled', 'deleted')),
    auth_version             integer     NOT NULL DEFAULT 1 CHECK (auth_version >= 1),
    provisioning_attempt_id  uuid,
    failed_attempts          integer     NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0),
    next_allowed_at          timestamptz,
    created_at               timestamptz NOT NULL,
    updated_at               timestamptz NOT NULL,
    CHECK (status = 'provisioning' OR status = 'deleted' OR user_id IS NOT NULL)
);
CREATE INDEX credentials_provisioning_idx ON auth.credentials (updated_at) WHERE status = 'provisioning';

CREATE TABLE auth.login_tickets (
    token_hash        bytea PRIMARY KEY,
    credential_id     uuid        NOT NULL REFERENCES auth.credentials (id) ON DELETE CASCADE,
    user_id           uuid        NOT NULL,
    auth_version      integer     NOT NULL,
    auth_time         timestamptz NOT NULL,
    created_at        timestamptz NOT NULL,
    expires_at        timestamptz NOT NULL,
    consumed_at       timestamptz,
    CHECK (expires_at > created_at)
);
CREATE INDEX login_tickets_expires_idx ON auth.login_tickets (expires_at);

CREATE TABLE auth.login_sessions (
    id                   uuid PRIMARY KEY,
    credential_id        uuid        NOT NULL REFERENCES auth.credentials (id) ON DELETE CASCADE,
    user_id              uuid        NOT NULL,
    auth_version         integer     NOT NULL,
    auth_time            timestamptz NOT NULL,
    created_at           timestamptz NOT NULL,
    absolute_expires_at  timestamptz NOT NULL,
    revoked_at           timestamptz,
    revoke_reason        text,
    CHECK (absolute_expires_at > created_at)
);
CREATE INDEX login_sessions_user_idx ON auth.login_sessions (user_id);
CREATE INDEX login_sessions_expires_idx ON auth.login_sessions (absolute_expires_at);

CREATE TABLE auth.refresh_families (
    id                uuid PRIMARY KEY,
    login_session_id  uuid        NOT NULL REFERENCES auth.login_sessions (id) ON DELETE CASCADE,
    user_id           uuid        NOT NULL,
    workspace_id      uuid        NOT NULL,
    member_id         uuid        NOT NULL,
    auth_version      integer     NOT NULL,
    created_at        timestamptz NOT NULL,
    idle_expires_at   timestamptz NOT NULL,
    revoked_at        timestamptz,
    revoke_reason     text
);
CREATE INDEX refresh_families_session_idx ON auth.refresh_families (login_session_id);
CREATE INDEX refresh_families_user_idx ON auth.refresh_families (user_id);
CREATE INDEX refresh_families_member_idx ON auth.refresh_families (workspace_id, member_id);
CREATE INDEX refresh_families_idle_idx ON auth.refresh_families (idle_expires_at);

CREATE TABLE auth.refresh_tokens (
    id          uuid PRIMARY KEY,
    family_id   uuid        NOT NULL REFERENCES auth.refresh_families (id) ON DELETE CASCADE,
    generation  integer     NOT NULL CHECK (generation >= 0),
    token_hash  bytea       NOT NULL UNIQUE,
    created_at  timestamptz NOT NULL,
    used_at     timestamptz,
    UNIQUE (family_id, generation)
);

CREATE TABLE auth.access_tokens (
    jti           text PRIMARY KEY,
    family_id     uuid        NOT NULL REFERENCES auth.refresh_families (id) ON DELETE CASCADE,
    auth_version  integer     NOT NULL,
    issued_at     timestamptz NOT NULL,
    expires_at    timestamptz NOT NULL,
    revoked_at    timestamptz,
    CHECK (expires_at > issued_at)
);
CREATE INDEX access_tokens_family_idx ON auth.access_tokens (family_id);
CREATE INDEX access_tokens_expires_idx ON auth.access_tokens (expires_at);

CREATE TABLE auth.password_resets (
    token_hash     bytea PRIMARY KEY,
    credential_id  uuid        NOT NULL REFERENCES auth.credentials (id) ON DELETE CASCADE,
    created_at     timestamptz NOT NULL,
    expires_at     timestamptz NOT NULL,
    consumed_at    timestamptz,
    CHECK (expires_at > created_at)
);
CREATE INDEX password_resets_expires_idx ON auth.password_resets (expires_at);

CREATE TABLE auth.email_changes (
    token_hash       bytea PRIMARY KEY,
    credential_id    uuid        NOT NULL REFERENCES auth.credentials (id) ON DELETE CASCADE,
    new_email        text        NOT NULL,
    created_at       timestamptz NOT NULL,
    expires_at       timestamptz NOT NULL,
    consumed_at      timestamptz,
    CHECK (expires_at > created_at)
);
CREATE INDEX email_changes_expires_idx ON auth.email_changes (expires_at);

CREATE TABLE auth.idempotency_keys (
    key            text        NOT NULL,
    user_id        uuid        NOT NULL,
    route          text        NOT NULL,
    request_hash   bytea       NOT NULL,
    status_code    integer     NOT NULL,
    response_json  bytea       NOT NULL,
    created_at     timestamptz NOT NULL,
    PRIMARY KEY (user_id, route, key)
);
CREATE INDEX idempotency_keys_created_idx ON auth.idempotency_keys (created_at);

CREATE TABLE auth.audit_events (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    at          timestamptz NOT NULL,
    kind        text        NOT NULL,
    user_id     uuid,
    detail      jsonb       NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX audit_events_at_idx ON auth.audit_events (at);

-- +goose Down
DROP TABLE auth.audit_events;
DROP TABLE auth.idempotency_keys;
DROP TABLE auth.email_changes;
DROP TABLE auth.password_resets;
DROP TABLE auth.access_tokens;
DROP TABLE auth.refresh_tokens;
DROP TABLE auth.refresh_families;
DROP TABLE auth.login_sessions;
DROP TABLE auth.login_tickets;
DROP TABLE auth.credentials;
DROP TABLE auth.registration_attempts;
