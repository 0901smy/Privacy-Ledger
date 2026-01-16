package database

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"privacy-ledger/internal/config"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Init creates a SQLite database connection with basic tuning.
func Init(cfg config.DatabaseConfig) (*gorm.DB, error) {
	// ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(cfg.Path), 0o755); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}

	gormLogger := logger.Default
	if !cfg.LogMode {
		gormLogger = gormLogger.LogMode(logger.Silent)
	}

	db, err := gorm.Open(sqlite.Open(cfg.Path), &gorm.Config{
		Logger: gormLogger,
	})
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("get sql db: %w", err)
	}

	// connection pool
	sqlDB.SetMaxOpenConns(10)
	sqlDB.SetMaxIdleConns(5)
	sqlDB.SetConnMaxLifetime(time.Hour)

	// SQLite performance and reliability tuning
	_, _ = sqlDB.Exec("PRAGMA journal_mode = WAL;")
	_, _ = sqlDB.Exec("PRAGMA synchronous = NORMAL;")
	_, _ = sqlDB.Exec("PRAGMA foreign_keys = ON;")

	return db, nil
}
