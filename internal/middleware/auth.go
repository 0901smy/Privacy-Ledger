package middleware

import (
	"net/http"
	"strings"
	"time"

	"privacy-ledger/internal/models"
	"privacy-ledger/internal/util"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// AuthMiddleware 校验 JWT，并在 context 里放入当前用户。
// 这里直接传入 jwtSecret 字符串，而不是 config.AuthConfig。
func AuthMiddleware(jwtSecret string, db *gorm.DB) gin.HandlerFunc {
    return func(c *gin.Context) {
        var tokenStr string

        // 1) Header: Authorization: Bearer xxx
        authHeader := c.GetHeader("Authorization")
        if authHeader != "" {
            parts := strings.SplitN(authHeader, " ", 2)
            if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
                tokenStr = parts[1]
            }
        }

        // 2) URL 查询参数 ?token=xxx（用于下载等无法自定义 Header 的场景）
        if tokenStr == "" {
            tokenStr = c.Query("token")
        }

        // 3) Cookie pl_token（如果以后你想用 cookie 存 token）
        if tokenStr == "" {
            if cookie, err := c.Cookie("pl_token"); err == nil {
                tokenStr = cookie
            }
        }

        if tokenStr == "" {
            util.Error(c, http.StatusUnauthorized, util.CodeAuth, "未登录")
            c.Abort()
            return
        }

        claims, err := util.ParseToken(jwtSecret, tokenStr)
        if err != nil || claims.ExpiresAt == nil || claims.ExpiresAt.Before(time.Now()) {
            util.Error(c, http.StatusUnauthorized, util.CodeAuth, "登录已失效，请重新登录")
            c.Abort()
            return
        }

        var user models.User
        if err := db.First(&user, claims.UserID).Error; err != nil {
            if err == gorm.ErrRecordNotFound {
				util.Error(c, http.StatusUnauthorized, util.CodeAuth, "用户不存在")
			} else {
				util.Error(c, http.StatusInternalServerError, util.CodeServerErr, "查询用户失败")
			}
			c.Abort()
			return
        }

        c.Set("currentUser", &user)
        c.Next()
    }
}
