package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"privacy-ledger/internal/models"
	"privacy-ledger/internal/util"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// BackupHandler 负责备份相关接口
type BackupHandler struct {
	DB          *gorm.DB
	EncryptKey  string
	BackupDir   string
}

// NewBackupHandler 构造函数
func NewBackupHandler(db *gorm.DB, encryptKey, backupDir string) *BackupHandler {
	return &BackupHandler{
		DB:         db,
		EncryptKey: encryptKey,
		BackupDir:  backupDir,
	}
}

// backupData 是写入备份文件的内容结构（当前只备份 entries，可按需要扩展）
type backupData struct {
	UserID  uint           `json:"user_id"`
	Created time.Time      `json:"created"`
	Entries []models.Entry `json:"entries"`
}

// CreateBackup 生成当前用户的加密备份文件
func (h *BackupHandler) CreateBackup(c *gin.Context) {
	v, ok := c.Get("currentUser")
	if !ok {
		util.Error(c, http.StatusUnauthorized, util.CodeAuth, "未登录")
		return
	}
	user, ok := v.(*models.User)
	if !ok || user == nil {
		util.Error(c, http.StatusUnauthorized, util.CodeAuth, "未登录")
		return
	}

	// 查询当前用户所有 entries
	var entries []models.Entry
	if err := h.DB.Where("user_id = ?", user.ID).
		Order("occurred_at ASC, id ASC").
		Find(&entries).Error; err != nil {
		util.Error(c, http.StatusInternalServerError, util.CodeServerErr, "查询数据失败")
		return
	}

	data := backupData{
		UserID:  user.ID,
		Created: time.Now(),
		Entries: entries,
	}
	raw, err := json.MarshalIndent(&data, "", "  ")
	if err != nil {
		util.Error(c, http.StatusInternalServerError, util.CodeServerErr, "序列化失败")
		return
	}

	enc, err := util.EncryptAES(h.EncryptKey, raw)
	if err != nil {
		util.Error(c, http.StatusInternalServerError, util.CodeServerErr, "加密失败")
		return
	}

	if err := os.MkdirAll(h.BackupDir, 0o755); err != nil {
		util.Error(c, http.StatusInternalServerError, util.CodeServerErr, "创建备份目录失败")
		return
	}

	// 使用 uuid + 时间作为文件名
	idStr := uuid.New().String()
	fileName := fmt.Sprintf("backup-%d-%s.bin", user.ID, idStr)
	filePath := filepath.Join(h.BackupDir, fileName)

	if err := os.WriteFile(filePath, enc, 0o600); err != nil {
		util.Error(c, http.StatusInternalServerError, util.CodeServerErr, "写入备份文件失败")
		return
	}

	info, _ := os.Stat(filePath)

	backup := models.Backup{
		UserID:   user.ID,
		FileName: fileName,
		FilePath: filePath,
		Size:     info.Size(),
	}
	if err := h.DB.Create(&backup).Error; err != nil {
		_ = os.Remove(filePath)
		util.Error(c, http.StatusInternalServerError, util.CodeServerErr, "保存备份记录失败")
		return
	}

	util.Success(c, util.Response{
		"backup": gin.H{
			"id":         backup.ID,
			"file_name":  backup.FileName,
			"size":       backup.Size,
			"created_at": backup.CreatedAt,
		},
	})
}

// ListBackups 列出当前用户已有的备份
func (h *BackupHandler) ListBackups(c *gin.Context) {
	v, ok := c.Get("currentUser")
	if !ok {
		util.Error(c, http.StatusUnauthorized, util.CodeAuth, "未登录")
		return
	}
	user, ok := v.(*models.User)
	if !ok || user == nil {
		util.Error(c, http.StatusUnauthorized, util.CodeAuth, "未登录")
		return
	}

	var list []models.Backup
	if err := h.DB.
		Where("user_id = ?", user.ID).
		Order("created_at DESC").
		Find(&list).Error; err != nil {
		util.Error(c, http.StatusInternalServerError, util.CodeServerErr, "查询备份失败")
		return
	}

	items := make([]gin.H, 0, len(list))
	for i := range list {
		b := &list[i]
		items = append(items, gin.H{
			"id":         b.ID,
			"file_name":  b.FileName,
			"size":       b.Size,
			"created_at": b.CreatedAt,
		})
	}

	util.Success(c, util.Response{
		"items": items,
	})
}

// DownloadBackup 下载指定备份文件
func (h *BackupHandler) DownloadBackup(c *gin.Context) {
	v, ok := c.Get("currentUser")
	if !ok {
		util.Error(c, http.StatusUnauthorized, util.CodeAuth, "未登录")
		return
	}
	user, ok := v.(*models.User)
	if !ok || user == nil {
		util.Error(c, http.StatusUnauthorized, util.CodeAuth, "未登录")
		return
	}

	id := c.Param("id")

	var backup models.Backup
	if err := h.DB.
		Where("id = ? AND user_id = ?", id, user.ID).
		First(&backup).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			util.Error(c, http.StatusNotFound, util.CodeNotFound, "备份不存在")
		} else {
			util.Error(c, http.StatusInternalServerError, util.CodeServerErr, "查询备份失败")
		}
		return
	}

	c.Header("Content-Type", "application/octet-stream")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", backup.FileName))
	c.File(backup.FilePath)
}

// DeleteBackup 删除备份记录及对应文件
func (h *BackupHandler) DeleteBackup(c *gin.Context) {
	v, ok := c.Get("currentUser")
	if !ok {
		util.Error(c, http.StatusUnauthorized, util.CodeAuth, "未登录")
		return
	}
	user, ok := v.(*models.User)
	if !ok || user == nil {
		util.Error(c, http.StatusUnauthorized, util.CodeAuth, "未登录")
		return
	}

	id := c.Param("id")

	var backup models.Backup
	if err := h.DB.
		Where("id = ? AND user_id = ?", id, user.ID).
		First(&backup).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			util.Error(c, http.StatusNotFound, util.CodeNotFound, "备份不存在")
		} else {
			util.Error(c, http.StatusInternalServerError, util.CodeServerErr, "查询备份失败")
		}
		return
	}

	// 先删文件，再删记录
	_ = os.Remove(backup.FilePath)
	if err := h.DB.Delete(&backup).Error; err != nil {
		util.Error(c, http.StatusInternalServerError, util.CodeServerErr, "删除备份记录失败")
		return
	}

	util.Success(c, util.Response{
		"message": "删除成功",
	})
}

// RestoreBackup 从指定备份文件恢复当前用户的账目数据
func (h *BackupHandler) RestoreBackup(c *gin.Context) {
	v, ok := c.Get("currentUser")
	if !ok {
		util.Error(c, http.StatusUnauthorized, util.CodeAuth, "未登录")
		return
	}
	user, ok := v.(*models.User)
	if !ok || user == nil {
		util.Error(c, http.StatusUnauthorized, util.CodeAuth, "未登录")
		return
	}

	id := c.Param("id")

	var backup models.Backup
	if err := h.DB.
		Where("id = ? AND user_id = ?", id, user.ID).
		First(&backup).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			util.Error(c, http.StatusNotFound, util.CodeNotFound, "备份不存在")
		} else {
			util.Error(c, http.StatusInternalServerError, util.CodeServerErr, "查询备份失败")
		}
		return
	}

	// 读文件并解密
	encData, err := os.ReadFile(backup.FilePath)
	if err != nil {
		util.Error(c, http.StatusInternalServerError, util.CodeServerErr, "读取备份文件失败")
		return
	}

	raw, err := util.DecryptAES(h.EncryptKey, encData)
	if err != nil {
		util.Error(c, http.StatusInternalServerError, util.CodeServerErr, "解密备份文件失败")
		return
	}

	var data backupData
	if err := json.Unmarshal(raw, &data); err != nil {
		util.Error(c, http.StatusInternalServerError, util.CodeServerErr, "解析备份数据失败")
		return
	}

	// 简单校验：备份中记录的 user_id 必须等于当前用户
	if data.UserID != 0 && data.UserID != user.ID {
		util.Error(c, http.StatusBadRequest, util.CodeInvalidParam, "备份文件不属于当前用户")
		return
	}

	// 用事务：先删当前用户所有 entries，再导入备份中的 entries
	err = h.DB.Transaction(func(tx *gorm.DB) error {
		// 删除当前用户的所有账目
		if err := tx.Where("user_id = ?", user.ID).Delete(&models.Entry{}).Error; err != nil {
			return err
		}

		// 恢复备份中的账目
		for i := range data.Entries {
			e := data.Entries[i]
			e.ID = 0            // 让数据库重新分配主键
			e.UserID = user.ID  // 强制归属当前用户
			if err := tx.Create(&e).Error; err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		util.Error(c, http.StatusInternalServerError, util.CodeServerErr, "恢复失败")
		return
	}

	util.Success(c, util.Response{
		"message":       "恢复成功",
		"entries_count": len(data.Entries),
	})
}
