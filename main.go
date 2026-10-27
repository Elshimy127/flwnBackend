package main

import (
	"log"

	"github.com/Hesham127/flwnBackend/internal/config"
	"github.com/Hesham127/flwnBackend/internal/platform/dataengine"
	"github.com/Hesham127/flwnBackend/internal/server"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}
	engine, err := dataengine.New(cfg.DataEngineURL, cfg.DataAPIKey)
	if err != nil {
		log.Fatal(err)
	}
	if err := server.NewRouter(engine).Run(":" + cfg.Port); err != nil {
		log.Fatal(err)
	}
}
