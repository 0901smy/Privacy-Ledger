package util

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// 通用返回结构里的 data 使用 map
type Response map[string]interface{}

// 业务错误码，可以先简单这样定义
const (
	CodeOK           = 0
	CodeInvalidParam = 40001
	CodeAuth         = 40101
	CodeNotFound     = 40401
	CodeServerErr    = 50001
)

// Success 统一成功返回
func Success(c *gin.Context, data Response) {
	c.JSON(http.StatusOK, gin.H{
		"code": CodeOK,
		"data": data,
	})
}

// Error 统一错误返回
func Error(c *gin.Context, httpStatus int, code int, msg string) {
	c.JSON(httpStatus, gin.H{
		"code":    code,
		"message": msg,
	})
}
