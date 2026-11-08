-- One-time bootstrap for the backend-owned auth database (docs/AUTH.md §13).
--
-- Run as the Postgres server admin, with psql variables for the two login passwords
-- (take them from Key Vault, never commit them):
--
--   psql "$ADMIN_URL" -v migrator_password="'...'" -v app_password="'...'" \
--        -f deploy/auth_db_bootstrap.sql
--
-- After this, only `flwnbackend migrate` (as flwn_auth_migrator) changes the schema, and the
-- server connects as flwn_auth_app. No other role, including the data engine's and any AI or
-- worker role, is granted anything here.

\set ON_ERROR_STOP on

CREATE ROLE flwn_auth_owner NOLOGIN;
CREATE ROLE flwn_auth_migrator LOGIN PASSWORD :migrator_password
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION IN ROLE flwn_auth_owner;
CREATE ROLE flwn_auth_app LOGIN PASSWORD :app_password
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION;

CREATE DATABASE flwn_auth OWNER flwn_auth_owner;
REVOKE ALL ON DATABASE flwn_auth FROM PUBLIC;
GRANT CONNECT ON DATABASE flwn_auth TO flwn_auth_migrator, flwn_auth_app;

\connect flwn_auth

REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA auth AUTHORIZATION flwn_auth_owner;
REVOKE ALL ON SCHEMA auth FROM PUBLIC;
GRANT USAGE ON SCHEMA auth TO flwn_auth_app;

-- Tables the migrator creates (as flwn_auth_owner) are usable by the app with DML only:
-- no TRUNCATE, REFERENCES, TRIGGER or DDL.
ALTER DEFAULT PRIVILEGES FOR ROLE flwn_auth_owner IN SCHEMA auth
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO flwn_auth_app;
ALTER DEFAULT PRIVILEGES FOR ROLE flwn_auth_owner IN SCHEMA auth
    GRANT USAGE, SELECT ON SEQUENCES TO flwn_auth_app;

-- The migration tool keeps its version table in schema auth.
ALTER ROLE flwn_auth_migrator SET search_path = auth;
ALTER ROLE flwn_auth_migrator SET role = flwn_auth_owner;
ALTER ROLE flwn_auth_app SET search_path = auth;
