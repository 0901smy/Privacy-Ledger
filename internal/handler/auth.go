package handler

import (
	"net/http"
	"regexp"
	"strings"
	"time"

	"privacy-ledger/internal/models"
	"privacy-ledger/internal/util"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// AuthHandler 负责登录/注册相关接口
type AuthHandler struct {
	DB        *gorm.DB
	JWTSecret string
	TokenTTL  time.Duration
}

// NewAuthHandler 构造函数
func NewAuthHandler(db *gorm.DB, jwtSecret string, ttlHours int) *AuthHandler {
	if ttlHours <= 0 {
		ttlHours = 24
	}
	return &AuthHandler{
		DB:        db,
		JWTSecret: jwtSecret,
		TokenTTL:  time.Duration(ttlHours) * time.Hour,
	}
}

// ---------- 注册 ----------

type registerReq struct {
	Username        string `json:"username" binding:"required"`           // 3-20 位，字母数字下划线
	Password        string `json:"password" binding:"required"`           // 8-32 且强度检查
	ConfirmPassword string `json:"confirm_password" binding:"required"`   // 必须和 Password 一致
	DisplayName     string `json:"display_name" binding:"max=64"`
}


func (h *AuthHandler) Register(c *gin.Context) {
	var req registerReq
	if err := c.ShouldBindJSON(&req); err != nil {
		util.Error(c, http.StatusBadRequest, util.CodeInvalidParam, "参数错误")
		return
	}

	req.Username = strings.TrimSpace(req.Username)

	// 用户名规则：3-20 位，仅字母、数字、下划线
	usernameRe := regexp.MustCompile(`^[A-Za-z0-9_]{3,20}$`)
	if !usernameRe.MatchString(req.Username) {
		util.Error(c, http.StatusBadRequest, util.CodeInvalidParam, "用户名必须为3-20位字母、数字或下划线")
		return
	}

	// 密码强度检查
	if !isStrongPassword(req.Password) {
		util.Error(c, http.StatusBadRequest, util.CodeInvalidParam, "密码需8-32位，且包含大写、小写字母和数字")
		return
	}

	// 两次输入一致
	if req.Password != req.ConfirmPassword {
		util.Error(c, http.StatusBadRequest, util.CodeInvalidParam, "两次输入的密码不一致")
		return
	}

	// 不区分大小写唯一：使用 LOWER(username) 检查
	var count int64
	if err := h.DB.Model(&models.User{}).
		Where("LOWER(username) = LOWER(?)", req.Username).
		Count(&count).Error; err != nil {
		util.Error(c, http.StatusInternalServerError, util.CodeServerErr, "查询用户失败")
		return
	}
	if count > 0 {
		util.Error(c, http.StatusBadRequest, util.CodeInvalidParam, "用户名已存在")
		return
	}

	// 使用 bcrypt cost=12 做密码哈希
	const bcryptCost = 12
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcryptCost)
	if err != nil {
		util.Error(c, http.StatusInternalServerError, util.CodeServerErr, "密码加密失败")
		return
	}

	user := models.User{
		Username:     req.Username,
		PasswordHash: string(hash),
		DisplayName:  req.DisplayName,
	}
	if err := h.DB.Create(&user).Error; err != nil {
		util.Error(c, http.StatusInternalServerError, util.CodeServerErr, "创建用户失败")
		return
	}

	util.Success(c, util.Response{
		"message": "注册成功",
		"user": gin.H{
			"id":           user.ID,
			"username":     user.Username,
			"display_name": user.DisplayName,
		},
	})
}

// 检查密码强度：8-32 位，包含大小写字母和数字
func isStrongPassword(pwd string) bool {
	if len(pwd) < 8 || len(pwd) > 32 {
		return false
	}
	var hasUpper, hasLower, hasDigit bool
	for _, ch := range pwd {
		switch {
		case ch >= 'A' && ch <= 'Z':
			hasUpper = true
		case ch >= 'a' && ch <= 'z':
			hasLower = true
		case ch >= '0' && ch <= '9':
			hasDigit = true
		}
	}
	return hasUpper && hasLower && hasDigit
}

// ---------- 登录 ----------

type loginReq struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req loginReq
	if err := c.ShouldBindJSON(&req); err != nil {
		util.Error(c, http.StatusBadRequest, util.CodeInvalidParam, "参数错误")
		return
	}

	req.Username = strings.TrimSpace(req.Username)

	var user models.User
	// 用户名不区分大小写匹配
	if err := h.DB.Where("LOWER(username) = LOWER(?)", req.Username).
		First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			util.Error(c, http.StatusUnauthorized, util.CodeAuth, "用户名或密码错误")
		} else {
			util.Error(c, http.StatusInternalServerError, util.CodeServerErr, "查询用户失败")
		}
		return
	}

	now := time.Now()

	// 检查是否被锁定
	if user.LockedUntil != nil && now.Before(*user.LockedUntil) {
		util.Error(c, http.StatusUnauthorized, util.CodeAuth, "账户已锁定，请稍后再试")
		return
	}

	// 校验密码
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		// 密码错误：递增失败次数，达到5次则锁定10分钟
		user.FailedLoginAttempts++
		if user.FailedLoginAttempts >= 5 {
            lockUntil := now.Add(10 * time.Minute)
			user.LockedUntil = &lockUntil
			user.FailedLoginAttempts = 0 // 锁定后计数清零也可以
		}
		_ = h.DB.Save(&user).Error
		util.Error(c, http.StatusUnauthorized, util.CodeAuth, "用户名或密码错误")
		return
	}

	// 登录成功：重置失败次数和锁定时间，记录登录 IP 和时间
	user.FailedLoginAttempts = 0
	user.LockedUntil = nil
	ip := c.ClientIP()
	user.LastLoginIP = ip
	user.LastLoginAt = &now

	// 如果账号在注销缓冲期内登录，则撤销注销
	if user.DeletedAt != nil {
		// 检查是否在 7 天缓冲期内
		if user.DeletePermanentlyAt != nil && now.Before(*user.DeletePermanentlyAt) {
			// 撤销注销
			user.DeletedAt = nil
			user.DeletePermanentlyAt = nil
		} else {
			// 已超过缓冲期，不允许登录（这种情况需要定时任务清理，这里先阻止）
			util.Error(c, http.StatusUnauthorized, util.CodeAuth, "账号已注销，无法登录")
			return
		}
	}

	_ = h.DB.Save(&user).Error


	// 生成 JWT，按需求：24 小时有效期
	ttl := 24 * time.Hour
	token, err := util.GenerateToken(h.JWTSecret, user.ID, ttl)
	if err != nil {
		util.Error(c, http.StatusInternalServerError, util.CodeServerErr, "生成 token 失败")
		return
	}

	util.Success(c, util.Response{
		"token": token,
		"user": gin.H{
			"id":           user.ID,
			"username":     user.Username,
			"display_name": user.DisplayName,
		},
	})
}
