package models

import "time"

// User represents application user.
type User struct {
	ID           uint      `gorm:"primaryKey"`
	Username     string    `gorm:"size:64;uniqueIndex;not null"`
	PasswordHash string    `gorm:"size:255;not null"`
	DisplayName  string    `gorm:"size:64"`
	CreatedAt    time.Time
	UpdatedAt    time.Time

	FailedLoginAttempts int        `gorm:"default:0"`    // 连续登录失败次数
	LockedUntil         *time.Time `gorm:"index"`        // 账户锁定到期时间
	LastLoginAt         *time.Time                        // 最近登录时间
	LastLoginIP         string     `gorm:"size:64"`      // 最近登录 IP

	DeletedAt           *time.Time `gorm:"index"`              // 注销时间（非 nil 表示已注销）
	DeletePermanentlyAt *time.Time                             // 永久删除时间（注销 + 7 天）
}
