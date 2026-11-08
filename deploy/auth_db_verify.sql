-- Privilege checks for the auth database (docs/AUTH.md §13). Run each block as the named role;
-- every statement marked "must fail" has to error, otherwise the setup is wrong.

-- As the data engine's DB role (or any role other than flwn_auth_*):
--   psql "postgresql://<engine_role>@host/flwn_auth"      -- must fail: no CONNECT

-- As flwn_auth_app:
--   CREATE TABLE auth.x (id int);                         -- must fail: no DDL
--   TRUNCATE auth.credentials;                            -- must fail: no TRUNCATE
--   SELECT count(*) FROM auth.credentials;                -- must succeed

SELECT r.rolname, r.rolsuper, r.rolbypassrls, r.rolcreatedb, r.rolcreaterole
FROM pg_roles r
WHERE r.rolname LIKE 'flwn_auth_%';

SELECT grantee, privilege_type, table_name
FROM information_schema.role_table_grants
WHERE table_schema = 'auth'
ORDER BY table_name, grantee, privilege_type;

SELECT datname, datacl FROM pg_database WHERE datname = 'flwn_auth';
