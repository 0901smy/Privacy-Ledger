package handler

import (
	"net/http"
	"strings"
	"time"

	"privacy-ledger/internal/models"
	"privacy-ledger/internal/util"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// UpdateProfileReq 更新基本资料请求
type UpdateProfileReq struct {
	DisplayName string `json:"display_name" binding:"max=64"`
}

// ChangePasswordReq 修改密码请求
type ChangePasswordReq struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=6,max=64"`
}

// UpdateProfile 更新当前用户的昵称等资料
func UpdateProfile(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
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

		var req UpdateProfileReq
		if err := c.ShouldBindJSON(&req); err != nil {
			util.Error(c, http.StatusBadRequest, util.CodeInvalidParam, "参数错误")
			return
		}

		req.DisplayName = strings.TrimSpace(req.DisplayName)

		if err := db.Model(user).Update("display_name", req.DisplayName).Error; err != nil {
			util.Error(c, http.StatusInternalServerError, util.CodeServerErr, "更新失败")
			return
		}

		user.DisplayName = req.DisplayName

		util.Success(c, util.Response{
			"user": gin.H{
				"id":           user.ID,
				"username":     user.Username,
				"display_name": user.DisplayName,
			},
		})
	}
}

// ChangePassword 修改当前用户密码
func ChangePassword(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
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

		var req ChangePasswordReq
		if err := c.ShouldBindJSON(&req); err != nil {
			util.Error(c, http.StatusBadRequest, util.CodeInvalidParam, "参数错误")
			return
		}

		// 校验旧密码（当前用的是 bcrypt）
		if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.OldPassword)); err != nil {
			util.Error(c, http.StatusBadRequest, util.CodeInvalidParam, "原密码错误")
			return
		}

		// 加密新密码
		hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
		if err != nil {
			util.Error(c, http.StatusInternalServerError, util.CodeServerErr, "密码加密失败")
			return
		}

		if err := db.Model(user).Update("password_hash", string(hash)).Error; err != nil {
			util.Error(c, http.StatusInternalServerError, util.CodeServerErr, "更新密码失败")
			return
		}

		util.Success(c, util.Response{
			"message": "密码修改成功，请使用新密码重新登录",
		})
	}
}

// DeleteAccount 注销当前账号（设置 7 天缓冲期）
func DeleteAccount(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
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

		// 检查是否已经注销过
		if user.DeletedAt != nil {
			util.Error(c, http.StatusBadRequest, util.CodeInvalidParam, "账号已处于注销状态")
			return
		}

		now := time.Now()
		deleteAt := now
		permanentlyAt := now.Add(7 * 24 * time.Hour) // 7 天后

		user.DeletedAt = &deleteAt
		user.DeletePermanentlyAt = &permanentlyAt

		if err := db.Save(user).Error; err != nil {
			util.Error(c, http.StatusInternalServerError, util.CodeServerErr, "注销失败，请重试")
			return
		}

		util.Success(c, util.Response{
			"message":              "账号已提交注销",
			"deleted_at":           deleteAt,
			"delete_permanently_at": permanentlyAt,
			"tip":                   "7 天内重新登录可恢复账号",
		})
	}
}
