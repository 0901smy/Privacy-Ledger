package handler

import (
	"net/http"

	"privacy-ledger/internal/models"
	"privacy-ledger/internal/util"

	"github.com/gin-gonic/gin"
)

// GetMe 返回当前登录用户信息（需要经过 AuthMiddleware）
func GetMe(c *gin.Context) {
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

	util.Success(c, util.Response{
		"user": gin.H{
			"id":           user.ID,
			"username":     user.Username,
			"display_name": user.DisplayName,
			"created_at":   user.CreatedAt,
		},
	})
}
