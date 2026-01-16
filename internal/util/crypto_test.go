package util

import (
	"strings"
	"testing"
)

// ==================== TDD Step 1: 测试 HashPassword ====================

// TestHashPassword_ValidInput 测试有效输入
func TestHashPassword_ValidInput(t *testing.T) {
	password := "SecurePass123"
	
	result, err := HashPassword(password)
	
	// 断言1: 无错误
	if err != nil {
		t.Fatalf("HashPassword() error = %v, want nil", err)
	}
	
	// 断言2: 返回值不为空
	if result == "" {
		t.Error("HashPassword() returned empty string")
	}
	
	// 断言3: 格式符合 "salt$hash"
	if !strings.Contains(result, "$") {
		t.Errorf("HashPassword() = %q, want format 'salt$hash'", result)
	}
	
	// 断言4: 正好包含一个分隔符
	count := strings.Count(result, "$")
	if count != 1 {
		t.Errorf("HashPassword() delimiter count = %d, want 1", count)
	}
}

// TestHashPassword_EmptyInput 测试空输入（边界条件）
func TestHashPassword_EmptyInput(t *testing.T) {
	result, err := HashPassword("")
	
	// 断言1: 必须返回错误
	if err == nil {
		t.Fatal("HashPassword(\"\") error = nil, want error")
	}
	
	// 断言2: 错误信息包含 "empty"
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("error message = %q, want contains 'empty'", err.Error())
	}
	
	// 断言3: 返回值应为空
	if result != "" {
		t.Errorf("HashPassword(\"\") result = %q, want empty", result)
	}
}

// TestHashPassword_RandomSalt 测试盐值随机性（单元特性）
func TestHashPassword_RandomSalt(t *testing.T) {
	password := "SamePassword"
	
	hash1, err1 := HashPassword(password)
	hash2, err2 := HashPassword(password)
	
	// 断言1: 两次调用都成功
	if err1 != nil || err2 != nil {
		t.Fatalf("HashPassword() failed: err1=%v, err2=%v", err1, err2)
	}
	
	// 断言2: 相同密码应生成不同哈希（因为盐值随机）
	if hash1 == hash2 {
		t.Error("HashPassword() with same input should generate different hashes due to random salt")
	}
	
	// 断言3: 盐值部分应不同
	salt1 := strings.Split(hash1, "$")[0]
	salt2 := strings.Split(hash2, "$")[0]
	if salt1 == salt2 {
		t.Error("Salt values should be different")
	}
}

// TestHashPassword_OutputLength 测试输出长度合理性（单元特性）
func TestHashPassword_OutputLength(t *testing.T) {
	password := "TestPass"
	
	result, err := HashPassword(password)
	
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	
	// base64编码的 16字节salt + "$" + 32字节hash 约为 22+1+43=66 字符
	if len(result) < 50 {
		t.Errorf("HashPassword() length = %d, seems too short", len(result))
	}
	if len(result) > 100 {
		t.Errorf("HashPassword() length = %d, seems too long", len(result))
	}
}

// ==================== TDD Step 2: 测试 CheckPassword ====================

// TestCheckPassword_CorrectPassword 测试正确密码匹配
func TestCheckPassword_CorrectPassword(t *testing.T) {
	password := "MyPassword123"
	stored, _ := HashPassword(password)
	
	result := CheckPassword(password, stored)
	
	// 断言: 应返回 true
	if !result {
		t.Errorf("CheckPassword() = false, want true for correct password")
	}
}

// TestCheckPassword_WrongPassword 测试错误密码
func TestCheckPassword_WrongPassword(t *testing.T) {
	correctPass := "CorrectPassword"
	wrongPass := "WrongPassword"
	stored, _ := HashPassword(correctPass)
	
	result := CheckPassword(wrongPass, stored)
	
	// 断言: 应返回 false
	if result {
		t.Errorf("CheckPassword() = true, want false for wrong password")
	}
}

// TestCheckPassword_EmptyPassword 测试空密码输入（边界条件）
func TestCheckPassword_EmptyPassword(t *testing.T) {
	stored, _ := HashPassword("SomePassword")
	
	result := CheckPassword("", stored)
	
	// 断言: 空密码应返回 false
	if result {
		t.Error("CheckPassword() with empty password = true, want false")
	}
}

// TestCheckPassword_EmptyStored 测试空存储值（边界条件）
func TestCheckPassword_EmptyStored(t *testing.T) {
	result := CheckPassword("SomePassword", "")
	
	// 断言: 空存储值应返回 false
	if result {
		t.Error("CheckPassword() with empty stored = true, want false")
	}
}

// TestCheckPassword_BothEmpty 测试双空输入（边界条件）
func TestCheckPassword_BothEmpty(t *testing.T) {
	result := CheckPassword("", "")
	
	// 断言: 都为空应返回 false
	if result {
		t.Error("CheckPassword() with both empty = true, want false")
	}
}

// TestCheckPassword_InvalidFormat_NoDelimiter 测试无分隔符格式（异常处理）
func TestCheckPassword_InvalidFormat_NoDelimiter(t *testing.T) {
	result := CheckPassword("password", "nosaltnodelimiternohash")
	
	// 断言: 无效格式应返回 false
	if result {
		t.Error("CheckPassword() with no delimiter = true, want false")
	}
}

// TestCheckPassword_InvalidFormat_TooManyParts 测试多个分隔符（异常处理）
func TestCheckPassword_InvalidFormat_TooManyParts(t *testing.T) {
	result := CheckPassword("password", "salt$hash$extra")
	
	// 断言: 格式错误应返回 false
	if result {
		t.Error("CheckPassword() with too many parts = true, want false")
	}
}

// TestCheckPassword_InvalidFormat_BadBase64Salt 测试无效Base64盐值（异常处理）
func TestCheckPassword_InvalidFormat_BadBase64Salt(t *testing.T) {
	result := CheckPassword("password", "!!!invalid!!!$validhashpart")
	
	// 断言: 无效编码应返回 false
	if result {
		t.Error("CheckPassword() with invalid base64 salt = true, want false")
	}
}

// TestCheckPassword_InvalidFormat_BadBase64Hash 测试无效Base64哈希（异常处理）
func TestCheckPassword_InvalidFormat_BadBase64Hash(t *testing.T) {
	result := CheckPassword("password", "validsaltpart$!!!invalid!!!")
	
	// 断言: 无效编码应返回 false
	if result {
		t.Error("CheckPassword() with invalid base64 hash = true, want false")
	}
}

// TestCheckPassword_CaseSensitive 测试密码大小写敏感（单元特性）
func TestCheckPassword_CaseSensitive(t *testing.T) {
	password := "Password"
	stored, _ := HashPassword(password)
	
	// 断言: 大小写不同应返回 false
	if CheckPassword("password", stored) {
		t.Error("CheckPassword() should be case-sensitive")
	}
	if CheckPassword("PASSWORD", stored) {
		t.Error("CheckPassword() should be case-sensitive")
	}
}

// ==================== TDD Step 3: 测试 RandomString ====================

// TestRandomString_ValidLength 测试有效长度
func TestRandomString_ValidLength(t *testing.T) {
	lengths := []int{1, 8, 16, 32, 64}
	
	for _, length := range lengths {
		result, err := RandomString(length)
		
		// 断言1: 无错误
		if err != nil {
			t.Errorf("RandomString(%d) error = %v, want nil", length, err)
			continue
		}
		
		// 断言2: 长度正确
		if len(result) != length {
			t.Errorf("RandomString(%d) length = %d, want %d", length, len(result), length)
		}
	}
}

// TestRandomString_ZeroLength 测试长度为0（边界条件）
func TestRandomString_ZeroLength(t *testing.T) {
	result, err := RandomString(0)
	
	// 断言1: 必须返回错误
	if err == nil {
		t.Fatal("RandomString(0) error = nil, want error")
	}
	
	// 断言2: 错误信息包含 "positive"
	if !strings.Contains(err.Error(), "positive") {
		t.Errorf("error message = %q, want contains 'positive'", err.Error())
	}
	
	// 断言3: 返回值为空
	if result != "" {
		t.Errorf("RandomString(0) result = %q, want empty", result)
	}
}

// TestRandomString_NegativeLength 测试负数长度（边界条件）
func TestRandomString_NegativeLength(t *testing.T) {
	result, err := RandomString(-10)
	
	// 断言1: 必须返回错误
	if err == nil {
		t.Fatal("RandomString(-10) error = nil, want error")
	}
	
	// 断言2: 返回值为空
	if result != "" {
		t.Errorf("RandomString(-10) result = %q, want empty", result)
	}
}

// TestRandomString_Uniqueness 测试唯一性（单元特性）
func TestRandomString_Uniqueness(t *testing.T) {
	length := 32
	
	str1, err1 := RandomString(length)
	str2, err2 := RandomString(length)
	
	// 断言1: 都成功
	if err1 != nil || err2 != nil {
		t.Fatalf("RandomString() failed: err1=%v, err2=%v", err1, err2)
	}
	
	// 断言2: 应生成不同字符串
	if str1 == str2 {
		t.Error("RandomString() should generate unique strings")
	}
}

// TestRandomString_CharacterSet 测试字符集合法性（单元特性）
func TestRandomString_CharacterSet(t *testing.T) {
	result, err := RandomString(100)
	
	if err != nil {
		t.Fatalf("RandomString() error = %v", err)
	}
	
	// 断言: URL-safe base64 字符集 [A-Za-z0-9_-]
	for _, c := range result {
		if !((c >= 'A' && c <= 'Z') || 
		     (c >= 'a' && c <= 'z') || 
		     (c >= '0' && c <= '9') || 
		     c == '_' || c == '-') {
			t.Errorf("RandomString() contains invalid character: %c", c)
		}
	}
}

// ==================== TDD Step 4: 测试 EncryptAES ====================

// TestEncryptAES_ValidInput 测试有效输入
func TestEncryptAES_ValidInput(t *testing.T) {
	key := "my-encryption-key"
	plaintext := []byte("Hello, World!")
	
	ciphertext, err := EncryptAES(key, plaintext)
	
	// 断言1: 无错误
	if err != nil {
		t.Fatalf("EncryptAES() error = %v, want nil", err)
	}
	
	// 断言2: 密文不为空
	if len(ciphertext) == 0 {
		t.Error("EncryptAES() returned empty ciphertext")
	}
	
	// 断言3: 密文长度应大于明文（包含nonce+tag）
	// GCM: nonce(12) + ciphertext(len(plaintext)) + tag(16)
	expectedMinLen := 12 + len(plaintext) + 16
	if len(ciphertext) < expectedMinLen {
		t.Errorf("EncryptAES() length = %d, want >= %d", len(ciphertext), expectedMinLen)
	}
}

// TestEncryptAES_EmptyPlaintext 测试空明文（边界条件）
func TestEncryptAES_EmptyPlaintext(t *testing.T) {
	key := "test-key"
	plaintext := []byte("")
	
	ciphertext, err := EncryptAES(key, plaintext)
	
	// 断言1: 无错误（空数据也能加密）
	if err != nil {
		t.Fatalf("EncryptAES() with empty plaintext error = %v, want nil", err)
	}
	
	// 断言2: 仍应返回 nonce+tag (12+16=28字节)
	if len(ciphertext) < 28 {
		t.Errorf("EncryptAES() with empty plaintext length = %d, want >= 28", len(ciphertext))
	}
}

// TestEncryptAES_DifferentKeys 测试不同密钥产生不同密文（单元特性）
func TestEncryptAES_DifferentKeys(t *testing.T) {
	plaintext := []byte("Same Data")
	
	cipher1, err1 := EncryptAES("key1", plaintext)
	cipher2, err2 := EncryptAES("key2", plaintext)
	
	// 断言1: 都成功
	if err1 != nil || err2 != nil {
		t.Fatalf("EncryptAES() failed: err1=%v, err2=%v", err1, err2)
	}
	
	// 断言2: 密文应不同
	if string(cipher1) == string(cipher2) {
		t.Error("EncryptAES() with different keys should produce different ciphertexts")
	}
}

// TestEncryptAES_RandomNonce 测试随机nonce（单元特性）
func TestEncryptAES_RandomNonce(t *testing.T) {
	key := "test-key"
	plaintext := []byte("Same Plaintext")
	
	cipher1, _ := EncryptAES(key, plaintext)
	cipher2, _ := EncryptAES(key, plaintext)
	
	// 断言: 即使密钥和明文相同，密文也应不同（因为nonce随机）
	if string(cipher1) == string(cipher2) {
		t.Error("EncryptAES() should use random nonce, producing different ciphertexts")
	}
	
	// 断言: nonce部分（前12字节）应不同
	nonce1 := cipher1[:12]
	nonce2 := cipher2[:12]
	if string(nonce1) == string(nonce2) {
		t.Error("Nonces should be different")
	}
}

// TestEncryptAES_OutputFormat 测试输出格式（单元特性）
func TestEncryptAES_OutputFormat(t *testing.T) {
	key := "test-key"
	plaintext := []byte("Test")
	
	ciphertext, err := EncryptAES(key, plaintext)
	
	if err != nil {
		t.Fatalf("EncryptAES() error = %v", err)
	}
	
	// 断言: 格式为 nonce(12) + encrypted + tag(16)
	// 最少应为 12 + 0 + 16 = 28 字节
	if len(ciphertext) < 28 {
		t.Errorf("EncryptAES() output too short: %d bytes", len(ciphertext))
	}
}

// ==================== TDD Step 5: 测试 DecryptAES ====================

// TestDecryptAES_ValidCiphertext 测试有效密文
func TestDecryptAES_ValidCiphertext(t *testing.T) {
	key := "test-key"
	originalPlaintext := []byte("Secret Message")
	
	// 先加密
	ciphertext, _ := EncryptAES(key, originalPlaintext)
	
	// 再解密
	decrypted, err := DecryptAES(key, ciphertext)
	
	// 断言1: 无错误
	if err != nil {
		t.Fatalf("DecryptAES() error = %v, want nil", err)
	}
	
	// 断言2: 解密结果与原文一致
	if string(decrypted) != string(originalPlaintext) {
		t.Errorf("DecryptAES() = %q, want %q", decrypted, originalPlaintext)
	}
}

// TestDecryptAES_WrongKey 测试错误密钥（异常处理）
func TestDecryptAES_WrongKey(t *testing.T) {
	correctKey := "correct-key"
	wrongKey := "wrong-key"
	plaintext := []byte("Data")
	
	ciphertext, _ := EncryptAES(correctKey, plaintext)
	
	_, err := DecryptAES(wrongKey, ciphertext)
	
	// 断言: 必须返回错误
	if err == nil {
		t.Error("DecryptAES() with wrong key error = nil, want error")
	}
}

// TestDecryptAES_EmptyCiphertext 测试空密文（边界条件）
func TestDecryptAES_EmptyCiphertext(t *testing.T) {
	key := "test-key"
	
	_, err := DecryptAES(key, []byte{})
	
	// 断言1: 必须返回错误
	if err == nil {
		t.Fatal("DecryptAES() with empty ciphertext error = nil, want error")
	}
	
	// 断言2: 错误信息包含 "short"
	if !strings.Contains(err.Error(), "short") {
		t.Errorf("error message = %q, want contains 'short'", err.Error())
	}
}

// TestDecryptAES_TooShort 测试过短密文（边界条件）
func TestDecryptAES_TooShort(t *testing.T) {
	key := "test-key"
	shortData := []byte{1, 2, 3, 4, 5}
	
	_, err := DecryptAES(key, shortData)
	
	// 断言: 必须返回错误
	if err == nil {
		t.Error("DecryptAES() with short data error = nil, want error")
	}
}

// TestDecryptAES_CorruptedData 测试损坏的密文（异常处理）
func TestDecryptAES_CorruptedData(t *testing.T) {
	key := "test-key"
	plaintext := []byte("Original")
	
	ciphertext, _ := EncryptAES(key, plaintext)
	
	// 篡改最后一个字节（破坏GCM tag）
	ciphertext[len(ciphertext)-1] ^= 0xFF
	
	_, err := DecryptAES(key, ciphertext)
	
	// 断言: 必须返回错误（GCM认证失败）
	if err == nil {
		t.Error("DecryptAES() with corrupted data error = nil, want error")
	}
}

// TestDecryptAES_CorruptedNonce 测试损坏的nonce（异常处理）
func TestDecryptAES_CorruptedNonce(t *testing.T) {
	key := "test-key"
	plaintext := []byte("Data")
	
	ciphertext, _ := EncryptAES(key, plaintext)
	
	// 篡改nonce（前12字节）
	ciphertext[0] ^= 0xFF
	
	_, err := DecryptAES(key, ciphertext)
	
	// 断言: 必须返回错误
	if err == nil {
		t.Error("DecryptAES() with corrupted nonce error = nil, want error")
	}
}

// TestDecryptAES_EmptyPlaintext 测试解密空明文（边界条件）
func TestDecryptAES_EmptyPlaintext(t *testing.T) {
	key := "test-key"
	emptyPlaintext := []byte("")
	
	ciphertext, _ := EncryptAES(key, emptyPlaintext)
	decrypted, err := DecryptAES(key, ciphertext)
	
	// 断言1: 无错误
	if err != nil {
		t.Fatalf("DecryptAES() error = %v", err)
	}
	
	// 断言2: 应解密为空
	if len(decrypted) != 0 {
		t.Errorf("DecryptAES() = %q, want empty", decrypted)
	}
}