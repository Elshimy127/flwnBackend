package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

type Config struct {
	Port          string
	DataEngineURL string
	DataAPIKey    string

	AuthDatabaseURL string
	JWTKeys         map[string][]byte // JWT_KEYS="kid1:secret1,kid0:secret0"
	JWTActiveKID    string
	JWTIssuer       string
	JWTAudience     string
	AccessTTL       time.Duration
	RefreshIdleTTL  time.Duration
	SessionTTL      time.Duration

	CSRFKey         []byte
	FrontendOrigins []string
	CookieSecure    bool
	HSTS            bool
	TrustedProxies  []string
	PublicAppURL    string // base URL for links in emails
}

// Load reads the server's configuration. Secrets (DATA_API_KEY, JWT_KEYS, CSRF_KEY and the
// auth database password) come from the environment, populated from Key Vault in production.
// AUTH_MIGRATE_DATABASE_URL is deliberately not read here: only `flwnbackend migrate` uses it.
func Load() (Config, error) {
	var errs []error
	cfg := Config{
		Port:            getenv("PORT", "8080"),
		DataEngineURL:   getenv("DATA_ENGINE_URL", "http://127.0.0.1:8002"),
		DataAPIKey:      os.Getenv("DATA_API_KEY"),
		AuthDatabaseURL: os.Getenv("AUTH_DATABASE_URL"),
		JWTActiveKID:    os.Getenv("JWT_ACTIVE_KID"),
		JWTIssuer:       getenv("JWT_ISSUER", "flwn-backend"),
		JWTAudience:     getenv("JWT_AUDIENCE", "flwn-backend"),
		CSRFKey:         []byte(os.Getenv("CSRF_KEY")),
		FrontendOrigins: splitList(os.Getenv("FRONTEND_ORIGINS")),
		CookieSecure:    getenv("COOKIE_SECURE", "true") != "false",
		HSTS:            getenv("HSTS", "false") == "true",
		TrustedProxies:  splitList(os.Getenv("TRUSTED_PROXIES")),
		PublicAppURL:    getenv("PUBLIC_APP_URL", "http://localhost:3000"),
	}
	if cfg.DataAPIKey == "" {
		errs = append(errs, errors.New("DATA_API_KEY is required"))
	}
	if cfg.AuthDatabaseURL == "" {
		errs = append(errs, errors.New("AUTH_DATABASE_URL is required"))
	}
	keys, err := parseKeys(os.Getenv("JWT_KEYS"))
	if err != nil {
		errs = append(errs, err)
	}
	cfg.JWTKeys = keys
	if _, ok := keys[cfg.JWTActiveKID]; !ok {
		errs = append(errs, errors.New("JWT_ACTIVE_KID must name a key in JWT_KEYS"))
	}
	if len(cfg.CSRFKey) < 32 {
		errs = append(errs, errors.New("CSRF_KEY must be at least 32 bytes"))
	}
	for name, dst := range map[string]*time.Duration{"ACCESS_TTL": &cfg.AccessTTL, "REFRESH_IDLE_TTL": &cfg.RefreshIdleTTL, "SESSION_TTL": &cfg.SessionTTL} {
		def := map[string]string{"ACCESS_TTL": "15m", "REFRESH_IDLE_TTL": "168h", "SESSION_TTL": "720h"}[name]
		d, err := time.ParseDuration(getenv(name, def))
		if err != nil || d <= 0 {
			errs = append(errs, fmt.Errorf("%s must be a positive duration", name))
		}
		*dst = d
	}
	if cfg.AccessTTL > 15*time.Minute {
		errs = append(errs, errors.New("ACCESS_TTL may not exceed 15m"))
	}
	if err := errors.Join(errs...); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func parseKeys(raw string) (map[string][]byte, error) {
	keys := map[string][]byte{}
	for _, part := range splitList(raw) {
		kid, secret, ok := strings.Cut(part, ":")
		if !ok || kid == "" {
			return nil, errors.New(`JWT_KEYS must look like "kid1:secret1,kid0:secret0"`)
		}
		if len(secret) < 32 {
			return nil, fmt.Errorf("JWT key %q must be at least 32 bytes", kid)
		}
		keys[kid] = []byte(secret)
	}
	if len(keys) == 0 {
		return nil, errors.New("JWT_KEYS is required")
	}
	return keys, nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
