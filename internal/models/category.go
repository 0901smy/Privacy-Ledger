package models

import "time"

// Category represents income/expense category.
type Category struct {
	ID        uint      `gorm:"primaryKey"`
	UserID    uint      `gorm:"index;not null"`
	Name      string    `gorm:"size:64;not null"`
	Type      string    `gorm:"size:16;index;not null"` // income / expense
	CreatedAt time.Time
	UpdatedAt time.Time
}
