package handler

import (
	"net/http"
	"strconv"
	"strings"
	"time"
	"encoding/base64"

	"privacy-ledger/internal/models"
	"privacy-ledger/internal/util"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// EntryHandler 负责账目相关接口
type EntryHandler struct {
	DB *gorm.DB
	EncryptKey string
}

// encryptField 把明文加密为 base64 字符串
func (h *EntryHandler) encryptField(plain string) (string, error) {
	if plain == "" || h.EncryptKey == "" {
		return plain, nil
	}
	b, err := util.EncryptAES(h.EncryptKey, []byte(plain))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// decryptField 尝试解密 base64+AES，失败则返回原值
func (h *EntryHandler) decryptField(cipherStr string) string {
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


func NewEntryHandler(db *gorm.DB, encryptKey string) *EntryHandler {
	return &EntryHandler{
		DB:         db,
		EncryptKey: encryptKey,
	}
}

// ---------- 请求/响应结构 ----------

type createEntryReq struct {
	Type       string `json:"type" binding:"required,oneof=income expense"`
	Category   string `json:"category" binding:"max=32"`
	AmountYuan string `json:"amount" binding:"required"`
	Note       string `json:"note" binding:"max=255"`
	OccurredAt string `json:"occurred_at"`
}

type entryResp struct {
	ID         uint      `json:"id"`
	Type       string    `json:"type"`
	Category   string    `json:"category"`
	AmountCent int64     `json:"amount_cent"` // 分
	AmountYuan string    `json:"amount"`      // 元（字符串，方便前端直接显示）
	Note       string    `json:"note"`
	OccurredAt time.Time `json:"occurred_at"`
	CreatedAt  time.Time `json:"created_at"`
}

type updateEntryReq struct {
	Type       string `json:"type" binding:"required,oneof=income expense"`
	Category   string `json:"category" binding:"max=32"`
	AmountYuan string `json:"amount" binding:"required"`
	Note       string `json:"note" binding:"max=255"`
	OccurredAt string `json:"occurred_at"`
}



// ---------- 工具函数 ----------

// convertYuanToCent 将字符串金额（元）转换为分，简单处理两位小数
func convertYuanToCent(s string) (int64, error) {
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, err
	}
	return int64(f*100 + 0.5), nil
}

// formatCentToYuan 把分转成元的字符串，两位小数
func formatCentToYuan(amountCent int64) string {
	return strconv.FormatFloat(float64(amountCent)/100.0, 'f', 2, 64)
}

func (h *EntryHandler) toEntryResp(e *models.Entry) entryResp {
	// 优先用密文解密的金额；如果解密失败（返回密文本身）就退回到 AmountCent
	amountYuan := h.decryptField(e.AmountEnc)
	if amountYuan == "" || amountYuan == e.AmountEnc {
		amountYuan = formatCentToYuan(e.AmountCent)
	}
	note := h.decryptField(e.Note)

	return entryResp{
		ID:         e.ID,
		Type:       e.Type,
		Category:   e.Category,
		AmountCent: e.AmountCent,
		AmountYuan: amountYuan,
		Note:       note,
		OccurredAt: e.OccurredAt,
		CreatedAt:  e.CreatedAt,
	}
}




// ---------- 记一笔 ----------

func (h *EntryHandler) CreateEntry(c *gin.Context) {
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

	var req createEntryReq
	if err := c.ShouldBindJSON(&req); err != nil {
		util.Error(c, http.StatusBadRequest, util.CodeInvalidParam, "参数错误")
		return
	}

	req.Category = strings.TrimSpace(req.Category)
	// 类别未选择
	if req.Category == "" {
		util.Error(c, http.StatusBadRequest, util.CodeInvalidParam, "请选择类别")
		return
	}

	// 金额校验：>0，格式正确
	amountCent, err := convertYuanToCent(req.AmountYuan)
	if err != nil || amountCent <= 0 {
		util.Error(c, http.StatusBadRequest, util.CodeInvalidParam, "请输入有效金额")
		return
	}

	// 交易日期：默认为今天，可以从 occurred_at 解析；不能晚于今天
	occurredAt := time.Now()
	if req.OccurredAt != "" {
		layouts := []string{
			time.RFC3339,          // 2025-12-03T00:00:00+08:00
			"2006-01-02T15:04:05", // 2025-12-03T00:00:00
			"2006-01-02",          // 2025-12-03
		}
		for _, layout := range layouts {
			if t, err := time.Parse(layout, req.OccurredAt); err == nil {
				occurredAt = t
				break
			}
		}
	}
	// 日期晚于今天 -> 报错
	occDate := occurredAt.Format("2006-01-02")
	todayDate := time.Now().Format("2006-01-02")
	if occDate > todayDate {
		util.Error(c, http.StatusBadRequest, util.CodeInvalidParam, "交易日期不能晚于今天")
		return
	}

	// 金额和备注 AES 加密
	amountEnc, err := h.encryptField(req.AmountYuan)
	if err != nil {
		util.Error(c, http.StatusInternalServerError, util.CodeServerErr, "数据加密失败")
		return
	}
	noteEnc, err := h.encryptField(req.Note)
	if err != nil {
		util.Error(c, http.StatusInternalServerError, util.CodeServerErr, "数据加密失败")
		return
	}

	entry := models.Entry{
		UserID:     user.ID,
		Type:       req.Type,
		Category:   req.Category,
		AmountCent: amountCent,
		AmountEnc:  amountEnc,
		Note:       noteEnc,
		OccurredAt: occurredAt,
	}

	if err := h.DB.Create(&entry).Error; err != nil {
		util.Error(c, http.StatusInternalServerError, util.CodeServerErr, "保存失败，请重试")
		return
	}

	util.Success(c, util.Response{
		"entry": h.toEntryResp(&entry),
	})
}

// UpdateEntry 修改一条已有的账目记录（只能修改自己的）
func (h *EntryHandler) UpdateEntry(c *gin.Context) {
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

	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil || id <= 0 {
		util.Error(c, http.StatusBadRequest, util.CodeInvalidParam, "ID 不合法")
		return
	}

	var req updateEntryReq
	if err := c.ShouldBindJSON(&req); err != nil {
		util.Error(c, http.StatusBadRequest, util.CodeInvalidParam, "参数错误")
		return
	}

	req.Category = strings.TrimSpace(req.Category)
	if req.Category == "" {
		util.Error(c, http.StatusBadRequest, util.CodeInvalidParam, "请选择类别")
		return
	}

	amountCent, err := convertYuanToCent(req.AmountYuan)
	if err != nil || amountCent <= 0 {
		util.Error(c, http.StatusBadRequest, util.CodeInvalidParam, "请输入有效金额")
		return
	}

	occurredAt := time.Now()
	if req.OccurredAt != "" {
		layouts := []string{
			time.RFC3339,
			"2006-01-02T15:04:05",
			"2006-01-02",
		}
		for _, layout := range layouts {
			if t, err := time.Parse(layout, req.OccurredAt); err == nil {
				occurredAt = t
				break
			}
		}
	}
	occDate := occurredAt.Format("2006-01-02")
	todayDate := time.Now().Format("2006-01-02")
	if occDate > todayDate {
		util.Error(c, http.StatusBadRequest, util.CodeInvalidParam, "交易日期不能晚于今天")
		return
	}

	// 只允许修改自己的记录
	var entry models.Entry
	if err := h.DB.Where("id = ? AND user_id = ?", id, user.ID).First(&entry).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			util.Error(c, http.StatusNotFound, util.CodeNotFound, "记录不存在")
		} else {
			util.Error(c, http.StatusInternalServerError, util.CodeServerErr, "查询失败")
		}
		return
	}

	amountEnc, err := h.encryptField(req.AmountYuan)
	if err != nil {
		util.Error(c, http.StatusInternalServerError, util.CodeServerErr, "数据加密失败")
		return
	}
	noteEnc, err := h.encryptField(req.Note)
	if err != nil {
		util.Error(c, http.StatusInternalServerError, util.CodeServerErr, "数据加密失败")
		return
	}

	entry.Type = req.Type
	entry.Category = req.Category
	entry.AmountCent = amountCent
	entry.AmountEnc = amountEnc
	entry.Note = noteEnc
	entry.OccurredAt = occurredAt

	if err := h.DB.Save(&entry).Error; err != nil {
		util.Error(c, http.StatusInternalServerError, util.CodeServerErr, "保存失败，请重试")
		return
	}

	util.Success(c, util.Response{
		"entry": h.toEntryResp(&entry),
	})
}

// ListEntries 查询账目列表，支持时间范围、类型、类别、多条件筛选和排序
func (h *EntryHandler) ListEntries(c *gin.Context) {
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

	// 时间筛选：start / end，格式 YYYY-MM-DD
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
			util.Error(c, http.StatusBadRequest, util.CodeInvalidParam, "开始日期格式错误，应为 YYYY-MM-DD")
			return
		}
		hasStart = true
	}
	if endStr != "" {
		endTime, err = time.Parse("2006-01-02", endStr)
		if err != nil {
			util.Error(c, http.StatusBadRequest, util.CodeInvalidParam, "结束日期格式错误，应为 YYYY-MM-DD")
			return
		}
		// 结束日期按“当天结束”处理：< end+1 天
		endTime = endTime.Add(24 * time.Hour)
		hasEnd = true
	}

	// 如果前端没有传时间范围，默认最近 30 天
	if !hasStart && !hasEnd {
		now := time.Now()
		// 今天 00:00
		today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
		startTime = today.AddDate(0, 0, -29) // 最近 30 天（含今天）
		endTime = today.AddDate(0, 0, 1)     // 明天 00:00
		hasStart, hasEnd = true, true
	}

	// 类型筛选：income / expense
	txType := c.Query("type")
	if txType != "income" && txType != "expense" {
		txType = ""
	}

	// 类别多选：?categories=餐饮,交通,工资
	catStr := c.Query("categories")
	var catList []string
	if catStr != "" {
		for _, p := range strings.Split(catStr, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				catList = append(catList, p)
			}
		}
	}

	// 排序方式：date_desc(默认)、date_asc、amount_desc、amount_asc
	sortKey := c.DefaultQuery("sort", "date_desc")
	orderBy := "occurred_at DESC, id DESC"
	switch sortKey {
	case "date_asc":
		orderBy = "occurred_at ASC, id ASC"
	case "amount_desc":
		orderBy = "amount_cent DESC, id DESC"
	case "amount_asc":
		orderBy = "amount_cent ASC, id ASC"
	}

	// 基础查询（统一应用所有筛选，供列表和统计复用）
	base := h.DB.Model(&models.Entry{}).Where("user_id = ?", user.ID)
	if hasStart {
		base = base.Where("occurred_at >= ?", startTime)
	}
	if hasEnd {
		base = base.Where("occurred_at < ?", endTime)
	}
	if txType != "" {
		base = base.Where("type = ?", txType)
	}
	if len(catList) > 0 {
		base = base.Where("category IN ?", catList)
	}

	// 总数
	var total int64
	if err := base.Session(&gorm.Session{}).Count(&total).Error; err != nil {
		util.Error(c, http.StatusInternalServerError, util.CodeServerErr, "查询失败")
		return
	}

	// 分页列表
	var entries []models.Entry
	if err := base.Session(&gorm.Session{}).
		Order(orderBy).
		Limit(size).
		Offset(offset).
		Find(&entries).Error; err != nil {
		util.Error(c, http.StatusInternalServerError, util.CodeServerErr, "查询失败")
		return
	}

	items := make([]entryResp, 0, len(entries))
	for i := range entries {
		items = append(items, h.toEntryResp(&entries[i]))
	}

	// 统计汇总（在相同筛选条件下）
	var allEntries []models.Entry
	if err := base.Session(&gorm.Session{}).Find(&allEntries).Error; err != nil {
		util.Error(c, http.StatusInternalServerError, util.CodeServerErr, "统计失败")
		return
	}

	var totalIncomeCent int64
	var totalExpenseCent int64

	type categorySummary struct {
		Category    string `json:"category"`
		IncomeCent  int64  `json:"income_cent"`
		IncomeYuan  string `json:"income"`
		ExpenseCent int64  `json:"expense_cent"`
		ExpenseYuan string `json:"expense"`
	}

	catMap := make(map[string]*categorySummary)
	for i := range allEntries {
		e := &allEntries[i]

		if e.Type == "income" {
			totalIncomeCent += e.AmountCent
		} else {
			totalExpenseCent += e.AmountCent
		}

		cs, ok := catMap[e.Category]
		if !ok {
			cs = &categorySummary{Category: e.Category}
			catMap[e.Category] = cs
		}
		if e.Type == "income" {
			cs.IncomeCent += e.AmountCent
		} else {
			cs.ExpenseCent += e.AmountCent
		}
	}

	catListSummary := make([]categorySummary, 0, len(catMap))
	for _, cs := range catMap {
		cs.IncomeYuan = formatCentToYuan(cs.IncomeCent)
		cs.ExpenseYuan = formatCentToYuan(cs.ExpenseCent)
		catListSummary = append(catListSummary, *cs)
	}

	summary := gin.H{
		"total_income_cent":  totalIncomeCent,
		"total_income":       formatCentToYuan(totalIncomeCent),
		"total_expense_cent": totalExpenseCent,
		"total_expense":      formatCentToYuan(totalExpenseCent),
		"balance_cent":       totalIncomeCent - totalExpenseCent,
		"balance":            formatCentToYuan(totalIncomeCent - totalExpenseCent),
		"by_category":        catListSummary,
	}

	util.Success(c, util.Response{
		"items":   items,
		"total":   total,
		"page":    page,
		"size":    size,
		"summary": summary,
	})
}



// ---------- 删除一条记录 ----------

func (h *EntryHandler) DeleteEntry(c *gin.Context) {
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

	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil || id <= 0 {
		util.Error(c, http.StatusBadRequest, util.CodeInvalidParam, "ID 不合法")
		return
	}

	// 只允许删除自己的记录
	if err := h.DB.
		Where("id = ? AND user_id = ?", id, user.ID).
		Delete(&models.Entry{}).Error; err != nil {
		util.Error(c, http.StatusInternalServerError, util.CodeServerErr, "删除失败")
		return
	}

	util.Success(c, util.Response{
		"message": "删除成功",
	})
}

// GetMonthlyStats 返回指定月份的统计数据（每日收支 + 类别汇总）
func (h *EntryHandler) GetMonthlyStats(c *gin.Context) {
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

	// 月份参数：?month=2025-12
	monthStr := c.Query("month")
	if monthStr == "" {
		now := time.Now()
		monthStr = now.Format("2006-01")
	}

	// 解析月份
	t, err := time.Parse("2006-01", monthStr)
	if err != nil {
		util.Error(c, http.StatusBadRequest, util.CodeInvalidParam, "月份格式错误，应为 YYYY-MM")
		return
	}

	// 月初和下月初
	startOfMonth := time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, t.Location())
	endOfMonth := startOfMonth.AddDate(0, 1, 0)

	// 查询该月所有账目
	var entries []models.Entry
	if err := h.DB.Where("user_id = ? AND occurred_at >= ? AND occurred_at < ?",
		user.ID, startOfMonth, endOfMonth).
		Order("occurred_at ASC").
		Find(&entries).Error; err != nil {
		util.Error(c, http.StatusInternalServerError, util.CodeServerErr, "查询失败")
		return
	}

	// 按日期分组统计
	type dailyStat struct {
		Date        string `json:"date"`          // YYYY-MM-DD
		IncomeCent  int64  `json:"income_cent"`
		ExpenseCent int64  `json:"expense_cent"`
		BalanceCent int64  `json:"balance_cent"`
		IncomeYuan  string `json:"income"`
		ExpenseYuan string `json:"expense"`
		BalanceYuan string `json:"balance"`
	}

	dailyMap := make(map[string]*dailyStat)
	for i := range entries {
		e := &entries[i]
		dateKey := e.OccurredAt.Format("2006-01-02")

		ds, ok := dailyMap[dateKey]
		if !ok {
			ds = &dailyStat{Date: dateKey}
			dailyMap[dateKey] = ds
		}

		if e.Type == "income" {
			ds.IncomeCent += e.AmountCent
		} else {
			ds.ExpenseCent += e.AmountCent
		}
	}

	// 转换为数组并计算结余
	var dailyList []dailyStat
	for _, ds := range dailyMap {
		ds.BalanceCent = ds.IncomeCent - ds.ExpenseCent
		ds.IncomeYuan = formatCentToYuan(ds.IncomeCent)
		ds.ExpenseYuan = formatCentToYuan(ds.ExpenseCent)
		ds.BalanceYuan = formatCentToYuan(ds.BalanceCent)
		dailyList = append(dailyList, *ds)
	}

	// 按类别统计
	type categoryStat struct {
		Category    string `json:"category"`
		IncomeCent  int64  `json:"income_cent"`
		ExpenseCent int64  `json:"expense_cent"`
		BalanceCent int64  `json:"balance_cent"`
		IncomeYuan  string `json:"income"`
		ExpenseYuan string `json:"expense"`
		BalanceYuan string `json:"balance"`
	}

	catMap := make(map[string]*categoryStat)
	var totalIncomeCent, totalExpenseCent int64

	for i := range entries {
		e := &entries[i]
		cs, ok := catMap[e.Category]
		if !ok {
			cs = &categoryStat{Category: e.Category}
			catMap[e.Category] = cs
		}

		if e.Type == "income" {
			cs.IncomeCent += e.AmountCent
			totalIncomeCent += e.AmountCent
		} else {
			cs.ExpenseCent += e.AmountCent
			totalExpenseCent += e.AmountCent
		}
	}

	var catList []categoryStat
	for _, cs := range catMap {
		cs.BalanceCent = cs.IncomeCent - cs.ExpenseCent
		cs.IncomeYuan = formatCentToYuan(cs.IncomeCent)
		cs.ExpenseYuan = formatCentToYuan(cs.ExpenseCent)
		cs.BalanceYuan = formatCentToYuan(cs.BalanceCent)
		catList = append(catList, *cs)
	}

	util.Success(c, util.Response{
		"month":          monthStr,
		"daily":          dailyList,
		"by_category":    catList,
		"total_income":   formatCentToYuan(totalIncomeCent),
		"total_expense":  formatCentToYuan(totalExpenseCent),
		"total_balance":  formatCentToYuan(totalIncomeCent - totalExpenseCent),
	})
}
