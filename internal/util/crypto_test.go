package util

import (
	"strings"
	"testing"
)

// ============ 密码哈希测试 ============

func TestHashPassword(t *testing.T) {
	password := "MyPassword123"
	
	// 测试正常哈希
	hashed, err := HashPassword(password)
	if err != nil {
		t.Fatalf("哈希失败: %v", err)
	}
	if !strings.Contains(hashed, "$") {
		t.Error("哈希格式错误，应包含 $")
	}
	
	// 测试空密码
	_, err = HashPassword("")
	if err == nil {
		t.Error("空密码应返回错误")
	}
	
	// 测试相同密码生成不同哈希
	hashed2, _ := HashPassword(password)
	if hashed == hashed2 {
		t.Error("相同密码应生成不同哈希（随机salt）")
	}
}

func TestCheckPassword(t *testing.T) {
	password := "TestPass456"
	hashed, _ := HashPassword(password)
	
	// 测试正确密码
	if !CheckPassword(password, hashed) {
		t.Error("正确密码验证失败")
	}
	
	// 测试错误密码
	if CheckPassword("WrongPass", hashed) {
		t.Error("错误密码不应通过验证")
	}
	
	// 测试空输入
	if CheckPassword("", hashed) {
		t.Error("空密码不应通过验证")
	}
	if CheckPassword(password, "") {
		t.Error("空哈希不应通过验证")
	}
	
	// 测试无效格式
	if CheckPassword(password, "invalid-format") {
		t.Error("无效格式不应通过验证")
	}
}

// ============ 随机字符串测试 ============

func TestRandomString(t *testing.T) {
	// 测试正常生成
	str, err := RandomString(32)
	if err != nil {
		t.Fatalf("生成失败: %v", err)
	}
	if len(str) != 32 {
		t.Errorf("长度错误: 期望32，实际%d", len(str))
	}
	
	// 测试唯一性
	str2, _ := RandomString(32)
	if str == str2 {
		t.Error("应生成不同的随机字符串")
	}
	
	// 测试无效长度
	_, err = RandomString(0)
	if err == nil {
		t.Error("长度0应返回错误")
	}
	_, err = RandomString(-5)
	if err == nil {
		t.Error("负数长度应返回错误")
	}
}

// ============ AES 加密测试 ============

func TestEncryptDecryptAES(t *testing.T) {
	key := "test-encryption-key"
	
	testCases := []string{
		"Hello World",
		"中文测试",
		"",
		"Special!@#$%^&*()",
		strings.Repeat("A", 1000),
	}
	
	for _, plaintext := range testCases {
		// 加密
		encrypted, err := EncryptAES(key, []byte(plaintext))
		if err != nil {
			t.Fatalf("加密失败 '%s': %v", plaintext, err)
		}
		
		// 解密
		decrypted, err := DecryptAES(key, encrypted)
		if err != nil {
			t.Fatalf("解密失败 '%s': %v", plaintext, err)
		}
		
		// 验证
		if string(decrypted) != plaintext {
			t.Errorf("数据不匹配\n期望: %s\n实际: %s", plaintext, string(decrypted))
		}
	}
}

func TestEncryptAES_DifferentKeys(t *testing.T) {
	plaintext := []byte("Secret Data")
	
	encrypted1, _ := EncryptAES("key1", plaintext)
	encrypted2, _ := EncryptAES("key2", plaintext)
	
	if string(encrypted1) == string(encrypted2) {
		t.Error("不同密钥应生成不同密文")
	}
}

func TestDecryptAES_WrongKey(t *testing.T) {
	plaintext := []byte("Data")
	encrypted, _ := EncryptAES("correct-key", plaintext)
	
	_, err := DecryptAES("wrong-key", encrypted)
	if err == nil {
		t.Error("错误密钥应解密失败")
	}
}

func TestDecryptAES_InvalidData(t *testing.T) {
	key := "test-key"
	
	// 数据太短
	_, err := DecryptAES(key, []byte{1, 2, 3})
	if err == nil {
		t.Error("过短数据应返回错误")
	}
	
	// 空数据
	_, err = DecryptAES(key, []byte{})
	if err == nil {
		t.Error("空数据应返回错误")
	}
}

// ============ 集成测试 ============

func TestRealWorldScenario(t *testing.T) {
	// 1. 用户注册
	password := "User123Pass"
	hashedPassword, _ := HashPassword(password)
	
	// 2. 用户登录验证
	if !CheckPassword(password, hashedPassword) {
		t.Fatal("登录验证失败")
	}
	
	// 3. 生成加密密钥
	encKey, _ := RandomString(32)
	
	// 4. 加密数据
	data := []byte(`{"amount":5000,"note":"工资"}`)
	encrypted, _ := EncryptAES(encKey, data)
	
	// 5. 解密数据
	decrypted, _ := DecryptAES(encKey, encrypted)
	
	if string(decrypted) != string(data) {
		t.Error("完整流程数据不匹配")
	}
}

// ============ 性能测试 ============

func BenchmarkHashPassword(b *testing.B) {
	for i := 0; i < b.N; i++ {
		HashPassword("BenchPassword")
	}
}

func BenchmarkEncryptAES(b *testing.B) {
	key := "bench-key"
	data := []byte("Benchmark data")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		EncryptAES(key, data)
	}
}

func BenchmarkDecryptAES(b *testing.B) {
	key := "bench-key"
	data := []byte("Benchmark data")
	encrypted, _ := EncryptAES(key, data)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DecryptAES(key, encrypted)
	}
}
