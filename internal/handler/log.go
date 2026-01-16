package handler

import (
	"net/http"
	"strconv"
	"strings"
	"time"
	"encoding/base64"
	"encoding/json"

	"privacy-ledger/internal/models"
	"privacy-ledger/internal/util"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// LogHandler 负责日志查询接口
type LogHandler struct {
	DB *gorm.DB
	EncryptKey string
}

func NewLogHandler(db *gorm.DB, encryptKey string) *LogHandler {
	return &LogHandler{
		DB:         db,
		EncryptKey: encryptKey,
	}
}

func (h *LogHandler) decryptField(cipherStr string) string {
	if cipherStr == "" || h.EncryptKey == "" {
		return cipherStr
	}
	b, err := base64.StdEncoding.DecodeString(cipherStr)
	if err != nil {
		return cipherStr
	}
	plain, err := util.DecryptAES(h.EncryptKey, b)
	if err != nil {
		return cipherStr
	}
	return string(plain)
}


type logResp struct {
	ID        uint      `json:"id"`
	Action    string    `json:"action"`
	Path      string    `json:"path"`
	Method    string    `json:"method"`
	IP        string    `json:"ip"`
	UserAgent string    `json:"user_agent"`
	CreatedAt time.Time `json:"created_at"`
}

// ListLogs 列出当前用户的操作日志（分页 + 时间 + 关键字）
func (h *LogHandler) ListLogs(c *gin.Context) {
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

	// 分页参数
	pageStr := c.DefaultQuery("page", "1")
	sizeStr := c.DefaultQuery("page_size", "20")
	page, _ := strconv.Atoi(pageStr)
	if page <= 0 {
		page = 1
	}
	size, _ := strconv.Atoi(sizeStr)
	if size <= 0 || size > 100 {
		size = 20
	}
	offset := (page - 1) * size

	// 时间筛选：start / end（格式 YYYY-MM-DD）
	startStr := c.Query("start")
	endStr := c.Query("end")

	var (
		startTime time.Time
		endTime   time.Time
		hasStart  bool
		hasEnd    bool
		err       error
	)

	if startStr != "" {
		startTime, err = time.Parse("2006-01-02", startStr)
		if err != nil {
			util.Error(c, http.StatusBadRequest, util.CodeInvalidParam, "开始日期格式错误")
			return
		}
		hasStart = true
	}
	if endStr != "" {
		endTime, err = time.Parse("2006-01-02", endStr)
		if err != nil {
			util.Error(c, http.StatusBadRequest, util.CodeInvalidParam, "结束日期格式错误")
			return
		}
		endTime = endTime.Add(24 * time.Hour)
		hasEnd = true
	}

	// 关键字搜索：q（匹配 path / action）
	q := strings.TrimSpace(c.Query("q"))

	base := h.DB.Model(&models.AuditLog{}).Where("user_id = ?", user.ID)
	if hasStart {
		base = base.Where("created_at >= ?", startTime)
	}
	if hasEnd {
		base = base.Where("created_at < ?", endTime)
	}
	if q != "" {
		like := "%" + q + "%"
		base = base.Where("path LIKE ? OR action LIKE ?", like, like)
	}

	// 统计总数
	var total int64
	if err := base.Session(&gorm.Session{}).Count(&total).Error; err != nil {
		util.Error(c, http.StatusInternalServerError, util.CodeServerErr, "查询失败")
		return
	}

	// 查询分页列表
	var logs []models.AuditLog
	if err := base.
		Order("created_at DESC, id DESC").
		Limit(size).
		Offset(offset).
		Find(&logs).Error; err != nil {
		util.Error(c, http.StatusInternalServerError, util.CodeServerErr, "查询失败")
		return
	}

	items := make([]logResp, 0, len(logs))
	for i := range logs {
		l := &logs[i]

		path := l.Path
    	if path == "" && l.PathEnc != "" {
        	path = h.decryptField(l.PathEnc)
   		}

    	action := l.Action
    	if action == "" && l.ActionEnc != "" {
        	action = h.decryptField(l.ActionEnc)
    	}

		items = append(items, logResp{
			ID:        l.ID,
			Action:    l.Action,
			Path:      l.Path,
			Method:    l.Method,
			IP:        l.IP,
			UserAgent: l.UserAgent,
			CreatedAt: l.CreatedAt,
		})
	}

	util.Success(c, util.Response{
		"items": items,
		"total": total,
		"page":  page,
		"size":  size,
	})
}

// ListEntryHistory 查询账目相关的历史操作（仅增删改）
func (h *LogHandler) ListEntryHistory(c *gin.Context) {
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

	pageStr := c.DefaultQuery("page", "1")
	sizeStr := c.DefaultQuery("page_size", "50")
	page, _ := strconv.Atoi(pageStr)
	if page <= 0 {
		page = 1
	}
	size, _ := strconv.Atoi(sizeStr)
	if size <= 0 || size > 100 {
		size = 50
	}
	offset := (page - 1) * size

	var allLogs []models.AuditLog
	if err := h.DB.Where("user_id = ?", user.ID).
		Order("created_at DESC").
		Find(&allLogs).Error; err != nil {
		util.Error(c, http.StatusInternalServerError, util.CodeServerErr, "查询失败")
		return
	}

	// 筛选账目操作
	var logs []models.AuditLog
	for _, l := range allLogs {
		path := l.Path
		if path == "" && l.PathEnc != "" {
			path = h.decryptField(l.PathEnc)
		}

		isEntryOp := false
		if l.Method == "POST" && path == "/api/entries" {
			isEntryOp = true
		} else if (l.Method == "PUT" || l.Method == "DELETE") &&
			strings.HasPrefix(path, "/api/entries/") {
			isEntryOp = true
		}

		if isEntryOp {
			logs = append(logs, l)
		}
	}

	total := int64(len(logs))

	// 分页
	start := offset
	end := offset + size
	if start > len(logs) {
		logs = []models.AuditLog{}
	} else {
		if end > len(logs) {
			end = len(logs)
		}
		logs = logs[start:end]
	}

	// 定义响应结构
	type entryHistoryResp struct {
		ID         uint      `json:"id"`
		Operation  string    `json:"operation"`
		Type       string    `json:"type"`
		Category   string    `json:"category"`
		Amount     string    `json:"amount"`
		Note       string    `json:"note"`
		OccurredAt string    `json:"occurred_at"`
		IP         string    `json:"ip"`
		CreatedAt  time.Time `json:"created_at"`
	}

	items := make([]entryHistoryResp, 0, len(logs))

	for i := range logs {
		l := &logs[i]

		// 解密 path（用于判断操作类型）
		path := l.Path
		if path == "" && l.PathEnc != "" {
			path = h.decryptField(l.PathEnc)
		}

		// 解密 action（用于提取账目详情）
		action := l.Action
		if action == "" && l.ActionEnc != "" {
			action = h.decryptField(l.ActionEnc)
		}

		// 确定操作类型
		var operation string
		if l.Method == "POST" && path == "/api/entries" {
			operation = "添加账目"
		} else if l.Method == "PUT" && strings.HasPrefix(path, "/api/entries/") {
			operation = "修改账目"
		} else if l.Method == "DELETE" && strings.HasPrefix(path, "/api/entries/") {
			operation = "删除账目"
		}

		// 创建响应项
		item := entryHistoryResp{
			ID:        l.ID,
			Operation: operation,
			IP:        l.IP,
			CreatedAt: l.CreatedAt,
		}

		// 解析 action 中的 JSON 数据
		if action != "" {
			jsonStart := strings.Index(action, "{")
			jsonEnd := strings.LastIndex(action, "}")

			if jsonStart >= 0 && jsonEnd > jsonStart {
				jsonStr := action[jsonStart : jsonEnd+1]
				var reqData map[string]interface{}
				
				if json.Unmarshal([]byte(jsonStr), &reqData) == nil {
					// 填充账目详情
					if v, ok := reqData["type"].(string); ok {
						if v == "income" {
							item.Type = "收入"
						} else if v == "expense" {
							item.Type = "支出"
						}
					}
					if v, ok := reqData["category"].(string); ok {
						item.Category = v
					}
					if v, ok := reqData["amount"].(string); ok {
						item.Amount = v + " 元"
					}
					if v, ok := reqData["note"].(string); ok {
						item.Note = v
					}
					if v, ok := reqData["occurred_at"].(string); ok {
						item.OccurredAt = v
					}
				}
			}
		}

		items = append(items, item)
	}

	util.Success(c, util.Response{
		"items": items,
		"total": total,
		"page":  page,
		"size":  size,
	})
}
