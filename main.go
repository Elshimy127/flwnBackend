package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Hesham127/flwnBackend/internal/auth"
	"github.com/Hesham127/flwnBackend/internal/auth/pgstore"
	"github.com/Hesham127/flwnBackend/internal/config"
	"github.com/Hesham127/flwnBackend/internal/jobs"
	"github.com/Hesham127/flwnBackend/internal/mail"
	"github.com/Hesham127/flwnBackend/internal/platform/dataengine"
	"github.com/Hesham127/flwnBackend/internal/platform/db"
	"github.com/Hesham127/flwnBackend/internal/server"
)

func main() {
	// `flwnbackend migrate` applies auth-DB migrations as flwn_auth_migrator and exits. The
	// server itself never migrates and never sees the migrator credentials.
	if len(os.Args) > 1 && os.Args[1] == "migrate" {
		url := os.Getenv("AUTH_MIGRATE_DATABASE_URL")
		if url == "" {
			log.Fatal("AUTH_MIGRATE_DATABASE_URL is required for migrate")
		}
		if err := db.Migrate(context.Background(), url); err != nil {
			log.Fatal(err)
		}
		log.Print("auth db migrated")
		return
	}

	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := db.Open(ctx, cfg.AuthDatabaseURL)
	if err != nil {
		log.Fatal(err)
	}
	defer pool.Close()
	if err := db.CheckVersion(ctx, pool); err != nil {
		log.Fatal(err)
	}

	engine, err := dataengine.New(cfg.DataEngineURL, cfg.DataAPIKey)
	if err != nil {
		log.Fatal(err)
	}
	system := dataengine.NewSystemClient(cfg.DataEngineURL, cfg.DataAPIKey)

	tokens, err := auth.NewTokenManager(auth.TokenConfig{
		Issuer: cfg.JWTIssuer, Audience: cfg.JWTAudience, Keys: cfg.JWTKeys,
		ActiveKID: cfg.JWTActiveKID, TTL: cfg.AccessTTL,
	})
	if err != nil {
		log.Fatal(err)
	}
	hasher, err := auth.NewHasher(auth.DefaultArgon2)
	if err != nil {
		log.Fatal(err)
	}
	store := pgstore.New(pool)
	authSvc := auth.NewService(auth.Config{RefreshIdleTTL: cfg.RefreshIdleTTL, SessionAbsoluteTTL: cfg.SessionTTL},
		store, system, tokens, hasher, mail.DevMailer{BaseURL: cfg.PublicAppURL})

	router, _ := server.NewRouter(server.Deps{
		Engine: engine, System: system, Auth: authSvc,
		Origins: cfg.FrontendOrigins, CookieSecure: cfg.CookieSecure, CSRFKey: cfg.CSRFKey,
		HSTS: cfg.HSTS, TrustedProxies: cfg.TrustedProxies,
		Ready: func(ctx context.Context) error { return errors.Join(store.Ping(ctx), system.Ping(ctx)) },
	})
	jobs.Run(ctx, authSvc)

	srv := &http.Server{
		Addr: ":" + cfg.Port, Handler: router,
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second,
		MaxHeaderBytes: 1 << 16,
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	log.Printf("listening on :%s", cfg.Port)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
