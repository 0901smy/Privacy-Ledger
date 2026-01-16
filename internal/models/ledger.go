package models

import (
	"time"

	"gorm.io/gorm"
)

// Ledger represents a single income or expense record.
type Ledger struct {
	ID         uint           `gorm:"primaryKey"`
	UserID     uint           `gorm:"index;not null"`
	CategoryID uint           `gorm:"index"`
	Type       string         `gorm:"size:16;index;not null"` // income / expense
	Amount     int64          `gorm:"not null"`               // store in cents to avoid float
	Currency   string         `gorm:"size:8;default:CNY"`
	OccurredAt time.Time      `gorm:"index"` // when the transaction happened
	Note       string         `gorm:"type:text"`
	CreatedAt  time.Time
	UpdatedAt  time.Time
	DeletedAt  gorm.DeletedAt `gorm:"index"`

	User     User     `gorm:"constraint:OnDelete:CASCADE"`
	Category Category `gorm:"constraint:OnDelete:SET NULL"`
}
