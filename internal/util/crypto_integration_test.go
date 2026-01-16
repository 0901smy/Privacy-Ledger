package util

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"privacy-ledger/internal/config"
	"privacy-ledger/internal/database"
	"privacy-ledger/internal/models"

	"gorm.io/gorm"
)

// TestIntegration_UserPasswordFlow 集成测试：用户密码完整流程
func TestIntegration_UserPasswordFlow(t *testing.T) {
	// 1. 初始化测试数据库
	db := setupTestDB(t)
	defer cleanupTestDB(t, db)

	// 2. 创建用户（使用 crypto.HashPassword）
	password := "SecurePassword123"
	hashedPassword, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	user := models.User{
		Username:     "testuser",
		PasswordHash: hashedPassword,
		DisplayName:  "Test User",
	}

	// 3. 保存到数据库
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("Create user failed: %v", err)
	}

	// 4. 从数据库查询用户
	var dbUser models.User
	if err := db.Where("username = ?", "testuser").First(&dbUser).Error; err != nil {
		t.Fatalf("Query user failed: %v", err)
	}

	// 5. 验证密码（使用 crypto.CheckPassword）
	if !CheckPassword(password, dbUser.PasswordHash) {
		t.Error("CheckPassword failed: should return true for correct password")
	}

	// 6. 错误密码验证
	if CheckPassword("WrongPassword", dbUser.PasswordHash) {
		t.Error("CheckPassword failed: should return false for wrong password")
	}

	t.Logf("√ User password integration test passed (UserID: %d)", dbUser.ID)
}

// TestIntegration_EntryDataEncryption 集成测试：账目数据加密流程
func TestIntegration_EntryDataEncryption(t *testing.T) {
	// 1. 初始化测试数据库
	db := setupTestDB(t)
	defer cleanupTestDB(t, db)

	// 2. 创建用户
	hashedPwd, _ := HashPassword("TestPassword")
	user := models.User{
		Username:     "entryuser",
		PasswordHash: hashedPwd,
	}
	db.Create(&user)

	// 3. 准备账目数据
	sensitiveNote := "敏感备注：给女朋友买礼物 5000 元"
	sensitiveAmount := "5000.00"
	encryptionKey := "user-encryption-key-12345"

	// 4. 加密备注和金额（使用 crypto.EncryptAES）
	encryptedNote, err := EncryptAES(encryptionKey, []byte(sensitiveNote))
	if err != nil {
		t.Fatalf("EncryptAES note failed: %v", err)
	}

	encryptedAmount, err := EncryptAES(encryptionKey, []byte(sensitiveAmount))
	if err != nil {
		t.Fatalf("EncryptAES amount failed: %v", err)
	}

	// 5. 创建账目记录
	entry := models.Entry{
		UserID:     user.ID,
		Type:       "expense",
		Category:   "礼物",
		AmountCent: 500000, // 5000.00 元 = 500000 分
		AmountEnc:  string(encryptedAmount),
		Note:       string(encryptedNote),
		OccurredAt: time.Now(),
	}

	if err := db.Create(&entry).Error; err != nil {
		t.Fatalf("Create entry failed: %v", err)
	}

	// 6. 从数据库查询账目
	var dbEntry models.Entry
	if err := db.First(&dbEntry, entry.ID).Error; err != nil {
		t.Fatalf("Query entry failed: %v", err)
	}

	// 7. 解密备注（使用 crypto.DecryptAES）
	decryptedNote, err := DecryptAES(encryptionKey, []byte(dbEntry.Note))
	if err != nil {
		t.Fatalf("DecryptAES note failed: %v", err)
	}

	// 8. 解密金额
	decryptedAmount, err := DecryptAES(encryptionKey, []byte(dbEntry.AmountEnc))
	if err != nil {
		t.Fatalf("DecryptAES amount failed: %v", err)
	}

	// 9. 验证解密结果
	if string(decryptedNote) != sensitiveNote {
		t.Errorf("Decrypted note mismatch:\nwant: %s\ngot:  %s", sensitiveNote, decryptedNote)
	}

	if string(decryptedAmount) != sensitiveAmount {
		t.Errorf("Decrypted amount mismatch:\nwant: %s\ngot:  %s", sensitiveAmount, decryptedAmount)
	}

	// 10. 错误密钥解密测试
	wrongKey := "wrong-key-67890"
	_, err = DecryptAES(wrongKey, []byte(dbEntry.Note))
	if err == nil {
		t.Error("DecryptAES should fail with wrong key")
	}

	t.Logf("√ Entry encryption integration test passed (EntryID: %d)", dbEntry.ID)
}

// TestIntegration_MultiUserEncryption 集成测试：多用户数据隔离
func TestIntegration_MultiUserEncryption(t *testing.T) {
	db := setupTestDB(t)
	defer cleanupTestDB(t, db)

	// 创建两个用户
	user1 := createTestUser(t, db, "alice", "AlicePassword")
	user2 := createTestUser(t, db, "bob", "BobPassword")

	// 两个用户使用不同密钥加密数据
	aliceKey := "alice-secret-key"
	bobKey := "bob-secret-key"

	aliceData := "Alice 的私密账本"
	bobData := "Bob 的私密账本"

	// 加密并存储
	aliceEncrypted, _ := EncryptAES(aliceKey, []byte(aliceData))
	bobEncrypted, _ := EncryptAES(bobKey, []byte(bobData))

	entry1 := models.Entry{
		UserID:     user1.ID,
		Type:       "income",
		Category:   "工资",
		AmountCent: 10000,
		Note:       string(aliceEncrypted),
		OccurredAt: time.Now(),
	}
	entry2 := models.Entry{
		UserID:     user2.ID,
		Type:       "expense",
		Category:   "购物",
		AmountCent: 5000,
		Note:       string(bobEncrypted),
		OccurredAt: time.Now(),
	}

	db.Create(&entry1)
	db.Create(&entry2)

	// 验证数据隔离
	var aliceEntry models.Entry
	db.Where("user_id = ?", user1.ID).First(&aliceEntry)

	decrypted, err := DecryptAES(aliceKey, []byte(aliceEntry.Note))
	if err != nil || string(decrypted) != aliceData {
		t.Error("Alice data decryption failed")
	}

	// Bob 不能用 Alice 的密钥解密
	_, err = DecryptAES(bobKey, []byte(aliceEntry.Note))
	if err == nil {
		t.Error("Should not decrypt Alice's data with Bob's key")
	}

	t.Logf("√ Multi-user encryption isolation test passed")
}

// TestIntegration_PasswordChange 集成测试：密码修改流程
func TestIntegration_PasswordChange(t *testing.T) {
	db := setupTestDB(t)
	defer cleanupTestDB(t, db)

	// 创建用户
	oldPassword := "OldPassword123"
	user := createTestUser(t, db, "changeuser", oldPassword)

	// 修改密码
	newPassword := "NewPassword456"
	newHash, err := HashPassword(newPassword)
	if err != nil {
		t.Fatalf("Hash new password failed: %v", err)
	}

	// 更新数据库
	db.Model(&user).Update("password_hash", newHash)

	// 重新查询
	var updatedUser models.User
	db.First(&updatedUser, user.ID)

	// 验证旧密码失效
	if CheckPassword(oldPassword, updatedUser.PasswordHash) {
		t.Error("Old password should not work after change")
	}

	// 验证新密码有效
	if !CheckPassword(newPassword, updatedUser.PasswordHash) {
		t.Error("New password should work after change")
	}

	t.Logf("√ Password change integration test passed")
}

// TestIntegration_AuditLogEncryption 集成测试：审计日志加密
func TestIntegration_AuditLogEncryption(t *testing.T) {
	db := setupTestDB(t)
	defer cleanupTestDB(t, db)

	// 创建用户
	user := createTestUser(t, db, "audituser", "Password123")

	// 准备敏感日志数据
	sensitiveAction := "用户查询账目：2026-01-01 到 2026-01-31"
	sensitiveMetadata := `{"amount_range": [100, 10000], "category": "餐饮"}`
	encryptionKey := "audit-log-key"

	// 加密日志字段
	encryptedAction, _ := EncryptAES(encryptionKey, []byte(sensitiveAction))
	encryptedMetadata, _ := EncryptAES(encryptionKey, []byte(sensitiveMetadata))

	// 创建审计日志
	log := models.AuditLog{
		UserID:      &user.ID,
		Method:      "GET",
		ActionEnc:   string(encryptedAction),
		MetadataEnc: string(encryptedMetadata),
		IP:          "192.168.1.100",
		UserAgent:   "Mozilla/5.0",
	}

	if err := db.Create(&log).Error; err != nil {
		t.Fatalf("Create audit log failed: %v", err)
	}

	// 查询并解密
	var dbLog models.AuditLog
	db.First(&dbLog, log.ID)

	decryptedAction, _ := DecryptAES(encryptionKey, []byte(dbLog.ActionEnc))
	decryptedMetadata, _ := DecryptAES(encryptionKey, []byte(dbLog.MetadataEnc))

	if string(decryptedAction) != sensitiveAction {
		t.Errorf("Action decryption failed")
	}

	if string(decryptedMetadata) != sensitiveMetadata {
		t.Errorf("Metadata decryption failed")
	}

	t.Logf("√ Audit log encryption test passed (LogID: %d)", dbLog.ID)
}

// ==================== 辅助函数 ====================

// setupTestDB 初始化测试数据库
func setupTestDB(t *testing.T) *gorm.DB {
	testDBPath := filepath.Join(os.TempDir(), "test_crypto_integration.db")

	cfg := config.DatabaseConfig{
		Path:    testDBPath,
		LogMode: false,
	}

	db, err := database.Init(cfg)
	if err != nil {
		t.Fatalf("Init test database failed: %v", err)
	}

	// 自动迁移所有模型
	if err := db.AutoMigrate(
		&models.User{},
		&models.Entry{},
		&models.Category{},
		&models.Backup{},
		&models.AuditLog{},
		&models.Session{},
	); err != nil {
		t.Fatalf("AutoMigrate failed: %v", err)
	}

	return db
}

// cleanupTestDB 清理测试数据库
func cleanupTestDB(t *testing.T, db *gorm.DB) {
	// 关闭数据库连接
	sqlDB, err := db.DB()
	if err == nil {
		sqlDB.Close()
	}

	// 删除测试文件
	testDBPath := filepath.Join(os.TempDir(), "test_crypto_integration.db")
	time.Sleep(100 * time.Millisecond) // 确保连接完全释放
	os.Remove(testDBPath)
	os.Remove(testDBPath + "-shm")
	os.Remove(testDBPath + "-wal")
}

// createTestUser 创建测试用户
func createTestUser(t *testing.T, db *gorm.DB, username, password string) models.User {
	hashedPwd, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	user := models.User{
		Username:     username,
		PasswordHash: hashedPwd,
		DisplayName:  username,
	}

	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("Create user failed: %v", err)
	}

	return user
}
