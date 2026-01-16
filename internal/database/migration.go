package database

import (
	"fmt"

	"privacy-ledger/internal/models"

	"gorm.io/gorm"
)

// AutoMigrate runs database schema migrations for all models.
func AutoMigrate(db *gorm.DB) error {
	if err := db.AutoMigrate(
		&models.User{},
		&models.Entry{},
		&models.Category{},
		&models.Ledger{},
		&models.AuditLog{},
		&models.Backup{},
		&models.Session{},
	); err != nil {
		return fmt.Errorf("auto migrate: %w", err)
	}
	return nil
}
