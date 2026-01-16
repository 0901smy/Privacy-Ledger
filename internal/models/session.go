package models

import "time"

// Session stores user login sessions (for logout, invalidation, audit).
type Session struct {
	ID        string    `gorm:"primaryKey;size:64"` // e.g. UUID
	UserID    uint      `gorm:"index;not null"`
	ExpiresAt time.Time `gorm:"index;not null"`
	Revoked   bool      `gorm:"index;not null"`
	CreatedAt time.Time

	User User `gorm:"constraint:OnDelete:CASCADE"`
}
