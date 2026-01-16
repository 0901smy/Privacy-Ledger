package util

import (
	"fmt"
	"time"
)

// ValidateAmount 验证金额（必须为正数且不超过上限）
func ValidateAmount(amount float64) error {
	if amount <= 0 {
		return fmt.Errorf("amount must be positive, got %f", amount)
	}
	if amount >= 10000000 { // 限制最大金额为1千万
		return fmt.Errorf("amount too large, got %f", amount)
	}
	return nil
}

// ValidateDate 验证日期格式（必须为 YYYY-MM-DD）
func ValidateDate(dateStr string) error {
	if dateStr == "" {
		return fmt.Errorf("date is empty")
	}
	_, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		return fmt.Errorf("invalid date format: %w", err)
	}
	return nil
}

// ValidateCategory 验证分类（不能为空且长度合理）
func ValidateCategory(category string) error {
	if category == "" {
		return fmt.Errorf("category is empty")
	}
	if len(category) > 20 {
		return fmt.Errorf("category too long, max 20 characters")
	}
	return nil
}
