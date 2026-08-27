-- loxilb-inference-gateway — PostgreSQL bootstrap.
--
-- Provisions the two schema/role pairs the gateway needs inside a database it
-- shares with loxilb-oam:
--
--   aigw       / aigwuser        data plane: API keys and tenant quotas
--   aigw_mgmt  / aigw_mgmt_user  management plane: users and session tokens
--
-- Neither role can read the other's schema, and neither can read OAM's tables
-- in public. That is the plane boundary held at the database rather than by
-- convention: a data-plane compromise cannot reach management credentials.
--
-- Run as the database owner. Two invocation paths, same file:
--
--   Existing database (the common case — OAM is deployed, its volume exists):
--     export AIGW_DB_PASSWORD=... AIGW_MGMT_DB_PASSWORD=...
--     psql -v ON_ERROR_STOP=1 -U <owner> -d <database> \
--          -f scripts/aigw-db-bootstrap.sql
--
--   Fresh deployment: mount this file into the initdb hook, which the OAM
--   compose already does for its own schema. The passwords arrive the same
--   way, through the container's environment:
--     volumes:
--       - ./aigw-db-bootstrap.sql:/docker-entrypoint-initdb.d/10-aigw-bootstrap.sql
--
-- Passwords are read from the environment, or from -v aigw_password=... /
-- -v aigw_mgmt_password=... when those are given. Never from a literal in
-- this file.
--
-- Idempotent: safe to re-run against a database that already has it, and
-- re-running with new passwords is the rotation procedure. An init script
-- that only works on a virgin volume is one nobody can safely re-run.
--
-- See docs/AI-KEY-STORE.md for the operator procedure.

\set ON_ERROR_STOP on

-- Fall back to the environment when the variables were not passed with -v.
-- \getenv leaves the variable unset when the environment does not hold it,
-- which the guard below turns into a loud failure.
\if :{?aigw_password}
\else
\getenv aigw_password AIGW_DB_PASSWORD
\endif

\if :{?aigw_mgmt_password}
\else
\getenv aigw_mgmt_password AIGW_MGMT_DB_PASSWORD
\endif

-- Abort when a password is missing or empty, rather than creating a login
-- role with an empty password. An unset psql variable interpolates into
-- :'var' as an empty literal, so without this the script would "succeed"
-- and leave two passwordless accounts on a shared database.
--
-- The refusal raises rather than calling \quit: psql exits 0 from \quit
-- whatever argument it is given, so a caller checking the exit status — the
-- docker initdb hook among them — would read the refusal as success and
-- carry on against a database with no roles in it.
\if :{?aigw_password}
\else
\echo '*** aigw-db-bootstrap: AIGW_DB_PASSWORD is not set (or pass -v aigw_password=...)'
DO $abort$ BEGIN RAISE EXCEPTION 'aigw-db-bootstrap: AIGW_DB_PASSWORD is not set'; END $abort$;
\endif

\if :{?aigw_mgmt_password}
\else
\echo '*** aigw-db-bootstrap: AIGW_MGMT_DB_PASSWORD is not set (or pass -v aigw_mgmt_password=...)'
DO $abort$ BEGIN RAISE EXCEPTION 'aigw-db-bootstrap: AIGW_MGMT_DB_PASSWORD is not set'; END $abort$;
\endif

SELECT length(:'aigw_password') = 0 OR length(:'aigw_mgmt_password') = 0 AS aigw_pw_empty \gset
\if :aigw_pw_empty
\echo '*** aigw-db-bootstrap: refusing to create a login role with an empty password'
DO $abort$ BEGIN RAISE EXCEPTION 'aigw-db-bootstrap: refusing to create a login role with an empty password'; END $abort$;
\endif

BEGIN;

-- CREATE ROLE has no IF NOT EXISTS form, so branch on the catalogue. The
-- password cannot be set from inside a DO block: psql does not interpolate
-- variables within dollar-quoted strings, so a DO block would create the role
-- with the literal text ":'aigw_password'" as its password.
SELECT NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aigwuser') AS create_aigw \gset
\if :create_aigw
CREATE ROLE aigwuser LOGIN PASSWORD :'aigw_password';
\else
ALTER ROLE aigwuser LOGIN PASSWORD :'aigw_password';
\endif

SELECT NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aigw_mgmt_user') AS create_mgmt \gset
\if :create_mgmt
CREATE ROLE aigw_mgmt_user LOGIN PASSWORD :'aigw_mgmt_password';
\else
ALTER ROLE aigw_mgmt_user LOGIN PASSWORD :'aigw_mgmt_password';
\endif

-- Data plane.
CREATE SCHEMA IF NOT EXISTS aigw AUTHORIZATION aigwuser;
GRANT USAGE, CREATE ON SCHEMA aigw TO aigwuser;
ALTER ROLE aigwuser SET search_path = aigw;

-- Management plane.
CREATE SCHEMA IF NOT EXISTS aigw_mgmt AUTHORIZATION aigw_mgmt_user;
GRANT USAGE, CREATE ON SCHEMA aigw_mgmt TO aigw_mgmt_user;
ALTER ROLE aigw_mgmt_user SET search_path = aigw_mgmt;

-- Neither gateway role may read OAM's tables, and neither may read the
-- other's. REVOKE rather than "do not GRANT": PUBLIC holds USAGE on the
-- public schema by default on PostgreSQL 14 and earlier, and CREATE too
-- before that.
REVOKE ALL ON SCHEMA public FROM aigwuser;
REVOKE ALL ON SCHEMA public FROM aigw_mgmt_user;
REVOKE ALL ON SCHEMA aigw_mgmt FROM aigwuser;
REVOKE ALL ON SCHEMA aigw FROM aigw_mgmt_user;

COMMIT;

-- Verification. Run these after a bootstrap; all three should read as noted.
--
--   SELECT nspname, pg_get_userbyid(nspowner) AS owner FROM pg_namespace
--    WHERE nspname IN ('aigw', 'aigw_mgmt');
--     -> aigw owned by aigwuser, aigw_mgmt by aigw_mgmt_user
--
--   SELECT has_schema_privilege('aigwuser', 'aigw', 'CREATE')        AS dp_own,
--          has_schema_privilege('aigwuser', 'aigw_mgmt', 'USAGE')    AS dp_reaches_mgmt,
--          has_schema_privilege('aigw_mgmt_user', 'aigw', 'USAGE')   AS mgmt_reaches_dp,
--          has_schema_privilege('aigwuser', 'public', 'CREATE')      AS dp_creates_public;
--     -> dp_own true, the other three false
--
--   As aigwuser:  SELECT * FROM public.<any OAM table>;
--     -> ERROR: permission denied for table ...
--
-- Note on the public schema. has_schema_privilege('aigwuser','public','USAGE')
-- reads true and cannot be revoked by the statements above: USAGE on public is
-- held by the PUBLIC pseudo-role, and REVOKE ... FROM aigwuser removes only
-- privileges granted to that role directly. Revoking it from PUBLIC instead
-- would strip it from every other role on the server, OAM's included, so this
-- file does not.
--
-- USAGE alone grants nothing over the tables in the schema. What actually
-- keeps OAM's rows unreadable is that no SELECT is granted on them, and what
-- keeps the gateway from planting objects there is CREATE, which PostgreSQL 15
-- removed from PUBLIC by default and which the REVOKE above removes on older
-- servers. Both were verified on PostgreSQL 18.6: SELECT on an OAM table and
-- CREATE in public are denied, and so is any access to the other plane's
-- schema.
--
-- One caveat this file cannot fix: a counterpart that connects as the
-- database's bootstrap superuser bypasses every grant above. The isolation is
-- enforced in the direction that carries the risk — a data-plane compromise
-- reaching management credentials; closing the reverse direction requires that
-- side to connect as an ordinary role.
