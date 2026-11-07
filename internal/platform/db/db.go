// Package db opens the backend-owned auth database and runs its migrations.
//
// The server connects as flwn_auth_app (DML only). Migrations run in a separate
// `flwnbackend migrate` step as flwn_auth_migrator, never at server start; the server only
// checks that the schema is at least the version it needs (docs/AUTH.md §13).
package db

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var migrations embed.FS

// RequiredVersion is the schema version this build needs. Bump it with every new migration.
const RequiredVersion int64 = 1

// Open connects to the auth database with a bounded pool and a 5s statement timeout.
func Open(ctx context.Context, url string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("auth db: parse url: %w", err)
	}
	cfg.MaxConns = 20
	cfg.MaxConnIdleTime = 5 * time.Minute
	cfg.ConnConfig.RuntimeParams["statement_timeout"] = "5000"
	cfg.ConnConfig.RuntimeParams["search_path"] = "auth"
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("auth db: connect: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("auth db: ping: %w", err)
	}
	return pool, nil
}

// CheckVersion refuses to run against a schema older than RequiredVersion.
func CheckVersion(ctx context.Context, pool *pgxpool.Pool) error {
	var version int64
	err := pool.QueryRow(ctx,
		`SELECT COALESCE(MAX(version_id), 0) FROM auth.goose_db_version WHERE is_applied`).Scan(&version)
	if err != nil {
		return fmt.Errorf("auth db: read schema version (run `flwnbackend migrate`?): %w", err)
	}
	if version < RequiredVersion {
		return fmt.Errorf("auth db: schema version %d, need %d: run `flwnbackend migrate`", version, RequiredVersion)
	}
	return nil
}

// Migrate applies every pending migration. It must run as flwn_auth_migrator.
func Migrate(ctx context.Context, url string) error {
	pool, err := Open(ctx, url)
	if err != nil {
		return err
	}
	defer pool.Close()
	sqlDB := stdlib.OpenDBFromPool(pool)
	defer sqlDB.Close()
	return migrate(ctx, sqlDB)
}

func migrate(ctx context.Context, sqlDB *sql.DB) error {
	goose.SetBaseFS(migrations)
	goose.SetTableName("auth.goose_db_version")
	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}
	if err := goose.UpContext(ctx, sqlDB, "migrations"); err != nil {
		return fmt.Errorf("auth db: migrate: %w", err)
	}
	return nil
}
