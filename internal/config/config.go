package config

import (
	"errors"
	"os"
)

type Config struct {
	Port          string
	DataEngineURL string
	DataAPIKey    string
}

func Load() (Config, error) {
	cfg := Config{
		Port:          getenv("PORT", "8080"),
		DataEngineURL: getenv("DATA_ENGINE_URL", "http://127.0.0.1:8002"),
		DataAPIKey:    os.Getenv("DATA_API_KEY"),
	}
	if cfg.DataAPIKey == "" {
		return Config{}, errors.New("DATA_API_KEY is required")
	}
	return cfg, nil
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
