package models

import "time"

// AuditLog records important operations for auditing.
type AuditLog struct {
	ID          uint       `gorm:"primaryKey"`
	UserID      *uint      `gorm:"index"`
	Path        string     `gorm:"size:255"`    // 旧数据：明文路径
	PathEnc     string     `gorm:"size:1024"`   // 新数据：加密后的路径
	Method      string     `gorm:"size:16"`
	Action      string     `gorm:"size:1024"`   // 旧数据：明文动作/路由
	ActionEnc   string     `gorm:"size:2048"`   // 新数据：加密后的动作/路由
	IP          string     `gorm:"size:64"`
	UserAgent   string     `gorm:"size:255"`
	Metadata    string     `gorm:"size:2048"`   // 旧数据：明文请求体
	MetadataEnc string     `gorm:"size:4096"`   // 新数据：加密后的请求体摘要
	CreatedAt   time.Time
}