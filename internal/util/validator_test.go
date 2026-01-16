package util

import (
	"testing"
)

// ==================== TDD: 先写测试 ====================

// TestValidateAmount_Positive 测试正数金额
func TestValidateAmount_Positive(t *testing.T) {
	testCases := []float64{0.01, 1.0, 100.5, 9999999.99}
	
	for _, amount := range testCases {
		err := ValidateAmount(amount)
		if err != nil {
			t.Errorf("ValidateAmount(%f) error = %v, want nil", amount, err)
		}
	}
}

// TestValidateAmount_Zero 测试零金额（异常）
func TestValidateAmount_Zero(t *testing.T) {
	err := ValidateAmount(0)
	
	if err == nil {
		t.Error("ValidateAmount(0) error = nil, want error")
	}
}

// TestValidateAmount_Negative 测试负数金额（异常）
func TestValidateAmount_Negative(t *testing.T) {
	testCases := []float64{-0.01, -100, -9999.99}
	
	for _, amount := range testCases {
		err := ValidateAmount(amount)
		if err == nil {
			t.Errorf("ValidateAmount(%f) error = nil, want error", amount)
		}
	}
}

// TestValidateAmount_TooLarge 测试金额过大（异常）
func TestValidateAmount_TooLarge(t *testing.T) {
	err := ValidateAmount(100000000) // 1亿
	
	if err == nil {
		t.Error("ValidateAmount(100000000) error = nil, want error")
	}
}

// TestValidateDate_Valid 测试有效日期
func TestValidateDate_Valid(t *testing.T) {
	testCases := []string{
		"2024-01-01",
		"2024-12-31",
		"2025-06-15",
	}
	
	for _, date := range testCases {
		err := ValidateDate(date)
		if err != nil {
			t.Errorf("ValidateDate(%q) error = %v, want nil", date, err)
		}
	}
}

// TestValidateDate_InvalidFormat 测试无效格式（异常）
func TestValidateDate_InvalidFormat(t *testing.T) {
	testCases := []string{
		"",
		"2024/01/01",
		"01-01-2024",
		"2024-1-1",
		"not-a-date",
		"2024-13-01", // 月份错误
		"2024-01-32", // 日期错误
	}
	
	for _, date := range testCases {
		err := ValidateDate(date)
		if err == nil {
			t.Errorf("ValidateDate(%q) error = nil, want error", date)
		}
	}
}

// TestValidateCategory_Valid 测试有效分类
func TestValidateCategory_Valid(t *testing.T) {
	testCases := []string{"餐饮", "交通", "购物", "娱乐", "工资"}
	
	for _, category := range testCases {
		err := ValidateCategory(category)
		if err != nil {
			t.Errorf("ValidateCategory(%q) error = %v, want nil", category, err)
		}
	}
}

// TestValidateCategory_Empty 测试空分类（异常）
func TestValidateCategory_Empty(t *testing.T) {
	err := ValidateCategory("")
	
	if err == nil {
		t.Error("ValidateCategory(\"\") error = nil, want error")
	}
}

// TestValidateCategory_TooLong 测试过长分类（异常）
func TestValidateCategory_TooLong(t *testing.T) {
	longCategory := "这是一个非常非常非常非常非常长的分类名称超过了合理的限制范围"
	
	err := ValidateCategory(longCategory)
	
	if err == nil {
		t.Error("ValidateCategory() with long string error = nil, want error")
	}
}
