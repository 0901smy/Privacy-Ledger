package middleware

import (
	"bytes"
	"encoding/base64"
	"io"
	//"time"

	"privacy-ledger/internal/models"
	"privacy-ledger/internal/util"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func encryptField(encryptKey, plain string) (string, error) {
	if plain == "" || encryptKey == "" {
		return plain, nil
	}
	b, err := util.EncryptAES(encryptKey, []byte(plain))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func AuditMiddleware(db *gorm.DB, encryptKey string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 获取用户 ID
		var userID uint
		if v, ok := c.Get("currentUser"); ok {
			if user, ok := v.(*models.User); ok && user != nil {
				userID = user.ID
			}
		}

		// 读取请求体
		var bodyBytes []byte
		if c.Request.Body != nil {
			bodyBytes, _ = io.ReadAll(c.Request.Body)
			c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}

		// 执行请求
		c.Next()

		// 只记录登录用户的操作
		if userID == 0 {
			return
		}

		// 构造 action
		path := c.Request.URL.Path
		action := c.Request.Method + " " + path
		
		if len(bodyBytes) > 0 && len(bodyBytes) < 2000 {
			action += " " + string(bodyBytes)
		}

		// 加密 path 和 action
		encPath, _ := encryptField(encryptKey, path)
		encAction, _ := encryptField(encryptKey, action)

		log := models.AuditLog{
			UserID:    &userID,
			Path:      "",           // 不存明文
			PathEnc:   encPath,
			Method:    c.Request.Method,
			Action:    "",           // 不存明文
			ActionEnc: encAction,
			IP:        c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
		}

		_ = db.Create(&log).Error
	}
}
