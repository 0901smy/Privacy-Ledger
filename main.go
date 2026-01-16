package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"privacy-ledger/internal/config"
	"privacy-ledger/internal/database"
	"privacy-ledger/internal/router"
)

func main() {
	// load configuration
	cfg, err := config.Load("config.yaml")
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	// ensure basic directories exist
	if err := ensureDir(filepath.Dir(cfg.Database.Path)); err != nil {
		log.Fatalf("create data dir: %v", err)
	}
	if err := ensureDir(filepath.Dir(cfg.Log.File)); err != nil {
		log.Fatalf("create log dir: %v", err)
	}
	if err := ensureDir(cfg.Backup.Dir); err != nil {
		log.Fatalf("create backup dir: %v", err)
	}

	// init database
	db, err := database.Init(cfg.Database)
	if err != nil {
		log.Fatalf("init database: %v", err)
	}

	// run migrations
	if err := database.AutoMigrate(db); err != nil {
		log.Fatalf("migrate database: %v", err)
	}

	// setup router
	r := router.SetupRouter(cfg, db)

	addr := fmt.Sprintf("%s:%d", cfg.Server.Address, cfg.Server.Port)
	log.Printf("server listening on %s", addr)
	if err := r.Run(addr); err != nil {
		log.Fatalf("run server: %v", err)
	}
}

func ensureDir(dir string) error {
	if dir == "" || dir == "." {
		return nil
	}
	return os.MkdirAll(dir, 0o755)
}
