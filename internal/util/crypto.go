package util

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// HashPassword 使用 PBKDF2+SHA256 生成密码哈希，返回 "salt$hash" 形式的字符串。
func HashPassword(password string) (string, error) {
	if password == "" {
		return "", fmt.Errorf("password is empty")
	}

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	hash := pbkdf2.Key([]byte(password), salt, 100_000, 32, sha256.New)
	saltStr := base64.RawStdEncoding.EncodeToString(salt)
	hashStr := base64.RawStdEncoding.EncodeToString(hash)

	return saltStr + "$" + hashStr, nil
}

// CheckPassword 验证明文密码与存储的哈希是否匹配。
func CheckPassword(password, stored string) bool {
	if password == "" || stored == "" {
		return false
	}
	
	// 使用 strings.Split 替代 fmt.Sscanf
	parts := strings.Split(stored, "$")
	if len(parts) != 2 {
		return false
	}
	saltStr := parts[0]
	hashStr := parts[1]

	salt, err := base64.RawStdEncoding.DecodeString(saltStr)
	if err != nil {
		return false
	}
	expectedHash, err := base64.RawStdEncoding.DecodeString(hashStr)
	if err != nil {
		return false
	}

	hash := pbkdf2.Key([]byte(password), salt, 100_000, len(expectedHash), sha256.New)

	// constant time compare
	if len(hash) != len(expectedHash) {
		return false
	}
	var diff byte
	for i := range hash {
		diff |= hash[i] ^ expectedHash[i]
	}
	return diff == 0
}

// RandomString 生成指定长度的随机字符串（URL 安全，用于密钥、token 等）。
func RandomString(n int) (string, error) {
	if n <= 0 {
		return "", fmt.Errorf("length must be positive")
	}
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf)[:n], nil
}

// ----------------- AES-256-GCM 加密/解密（用于备份） -----------------

// deriveKey 始终生成 32 字节 key，避免对配置长度过于敏感。
func deriveKey(keyStr string) []byte {
	sum := sha256.Sum256([]byte(keyStr))
	return sum[:]
}

// EncryptAES 使用 AES-256-GCM 加密数据，返回 nonce+ciphertext。
func EncryptAES(keyStr string, plaintext []byte) ([]byte, error) {
	key := deriveKey(keyStr)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm: %w", err)
	}

	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	// 前面拼上 nonce，解密时可以拆回来
	return append(nonce, ciphertext...), nil
}

// DecryptAES 使用 AES-256-GCM 解密数据（输入必须是 nonce+ciphertext）。
func DecryptAES(keyStr string, data []byte) ([]byte, error) {
	key := deriveKey(keyStr)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm: %w", err)
	}

	ns := aesgcm.NonceSize()
	if len(data) < ns {
		return nil, fmt.Errorf("cipher too short")
	}
	nonce, ciphertext := data[:ns], data[ns:]

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plaintext, nil
}
