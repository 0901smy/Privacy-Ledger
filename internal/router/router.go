package router

import (
	"net/http"

	"privacy-ledger/internal/config"
	"privacy-ledger/internal/handler"
	"privacy-ledger/internal/middleware"
	

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// SetupRouter configures Gin engine, templates and static resources.
func SetupRouter(cfg *config.Config, db *gorm.DB) *gin.Engine {
	if cfg.Server.Mode != "" {
		gin.SetMode(cfg.Server.Mode)
	}
	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())

	// static files and templates
	r.Static("/static", "./web/static")
	r.LoadHTMLGlob("web/templates/*")

	// Home -> login page
	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "login.html", gin.H{
			"title": "隐私记账系统 - 登录",
		})
	})

	// 登录后访问的主页
	r.GET("/dashboard", func(c *gin.Context) {
		c.HTML(http.StatusOK, "dashboard.html", gin.H{
			"title": "隐私记账系统 - 主页",
		})
	})

	// 账户设置页面
	r.GET("/account", func(c *gin.Context) {
    	c.HTML(http.StatusOK, "account.html", gin.H{
        	"title": "隐私记账系统 - 账户设置",
    	})
	})

	// 操作日志页面
	r.GET("/logs", func(c *gin.Context) {
    	c.HTML(http.StatusOK, "logs.html", gin.H{
        	"title": "隐私记账系统 - 操作日志",
    	})
	})

	r.GET("/history", func(c *gin.Context) {
    	c.HTML(http.StatusOK, "history.html", gin.H{
        	"title": "隐私记账系统 - 历史操作",
    	})
	})

	// 数据统计页面
	r.GET("/statistics", func(c *gin.Context) {
    	c.HTML(http.StatusOK, "statistics.html", gin.H{
        	"title": "隐私记账系统 - 数据统计",
    	})
	})

	// ====== API ======
	api := r.Group("/api")

	// 从配置中读取 JWT 密钥和过期时间
	jwtSecret := cfg.JWT.Secret
	// 登录/注册接口（不需要鉴权）
	authHandler := handler.NewAuthHandler(db, jwtSecret, cfg.JWT.ExpireHours)
	api.POST("/auth/register", authHandler.Register)
	api.POST("/auth/login", authHandler.Login)

	// 需要登录才能访问的接口
	protected := api.Group("")
	protected.Use(
	    middleware.AuthMiddleware(jwtSecret, db),
    	middleware.AuditMiddleware(db, cfg.Security.EncryptionKey),
	)

	protected.GET("/me", handler.GetMe)
	
	entryHandler := handler.NewEntryHandler(db, cfg.Security.EncryptionKey)
	protected.POST("/entries", entryHandler.CreateEntry)
	protected.GET("/entries", entryHandler.ListEntries)
	protected.PUT("/entries/:id", entryHandler.UpdateEntry)
	protected.DELETE("/entries/:id", entryHandler.DeleteEntry)
	protected.GET("/stats/monthly", entryHandler.GetMonthlyStats)

	backupHandler := handler.NewBackupHandler(db, cfg.Security.EncryptionKey, cfg.Backup.Dir)
	protected.POST("/backups", backupHandler.CreateBackup)
	protected.GET("/backups", backupHandler.ListBackups)
	protected.GET("/backups/:id/download", backupHandler.DownloadBackup)
	protected.POST("/backups/:id/restore", backupHandler.RestoreBackup)
	protected.DELETE("/backups/:id", backupHandler.DeleteBackup)

	protected.POST("/profile", handler.UpdateProfile(db))
	protected.POST("/profile/password", handler.ChangePassword(db))
	protected.POST("/profile/delete", handler.DeleteAccount(db))

	logHandler := handler.NewLogHandler(db, cfg.Security.EncryptionKey)
	protected.GET("/logs", logHandler.ListLogs)
	protected.GET("/history", logHandler.ListEntryHistory)

	importExportHandler := handler.NewImportExportHandler(db, cfg.Security.EncryptionKey)
	protected.GET("/export/csv", importExportHandler.ExportCSV)
	protected.GET("/export/xlsx", importExportHandler.ExportXLSX)

	return r
}
