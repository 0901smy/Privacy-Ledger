package models

import "time"

// Entry 表示一笔账目记录
// 金额用分存储，避免浮点误差，比如 12.34 元 = 1234 分
type Entry struct {
	ID         uint      `gorm:"primaryKey"`
	UserID     uint      `gorm:"index;not null"`
	Type       string    `gorm:"size:16;not null"`
	Category   string    `gorm:"size:32;not null"`
	AmountCent int64     `gorm:"not null"`         // 金额（分），用于内部计算
	AmountEnc  string    `gorm:"size:255"`         // 金额密文（AES+base64）
	Note       string    `gorm:"size:255"`         // 备注密文（AES+base64）
	OccurredAt time.Time `gorm:"index;not null"`
	CreatedAt  time.Time
	UpdatedAt  time.Time
}