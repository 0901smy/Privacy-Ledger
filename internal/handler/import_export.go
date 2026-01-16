package handler

import (
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"privacy-ledger/internal/models"
	"privacy-ledger/internal/util"

	"github.com/xuri/excelize/v2"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type ImportExportHandler struct {
	DB         *gorm.DB
	EncryptKey string
}

func NewImportExportHandler(db *gorm.DB, encryptKey string) *ImportExportHandler {
	return &ImportExportHandler{
		DB:         db,
		EncryptKey: encryptKey,
	}
}

// 解密字段
func (h *ImportExportHandler) decryptField(cipherStr string) string {
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

// ExportCSV 导出账目为 CSV
func (h *ImportExportHandler) ExportCSV(c *gin.Context) {
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

	var entries []models.Entry
	if err := h.DB.Where("user_id = ?", user.ID).
		Order("occurred_at DESC").
		Find(&entries).Error; err != nil {
		util.Error(c, http.StatusInternalServerError, util.CodeServerErr, "查询失败")
		return
	}

	// 设置响应头
	c.Header("Content-Type", "text/csv; charset=utf-8")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"entries_%s.csv\"",
		time.Now().Format("20060102")))

	writer := csv.NewWriter(c.Writer)
	defer writer.Flush()

	// UTF-8 BOM（让 Excel 正确识别中文）
	c.Writer.Write([]byte{0xEF, 0xBB, 0xBF})

	// 写入表头
	writer.Write([]string{"类型", "类别", "金额(元)", "备注", "日期"})

	// 写入数据
	for _, e := range entries {
		typeText := "支出"
		if e.Type == "income" {
			typeText = "收入"
		}

		amount := h.decryptField(e.AmountEnc)
		if amount == "" || amount == e.AmountEnc {
			amount = strconv.FormatFloat(float64(e.AmountCent)/100.0, 'f', 2, 64)
		}

		note := h.decryptField(e.Note)
		dateStr := e.OccurredAt.Format("2006-01-02")

		writer.Write([]string{
			typeText,
			e.Category,
			amount,
			note,
			dateStr,
		})
	}
}

// ExportXLSX 导出账目为 XLSX
func (h *ImportExportHandler) ExportXLSX(c *gin.Context) {
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

	var entries []models.Entry
	if err := h.DB.Where("user_id = ?", user.ID).
		Order("occurred_at DESC").
		Find(&entries).Error; err != nil {
		util.Error(c, http.StatusInternalServerError, util.CodeServerErr, "查询失败")
		return
	}

	f := excelize.NewFile()
	sheetName := "账目明细"
	index, err := f.NewSheet(sheetName)
	if err != nil {
		util.Error(c, http.StatusInternalServerError, util.CodeServerErr, "创建工作表失败")
		return
	}
	f.SetActiveSheet(index)

	// 设置表头
	headers := []string{"类型", "类别", "金额(元)", "备注", "日期"}
	for i, h := range headers {
		cell := fmt.Sprintf("%c1", 'A'+i)
		f.SetCellValue(sheetName, cell, h)
	}

	// 写入数据
	for idx, e := range entries {
		row := idx + 2

		typeText := "支出"
		if e.Type == "income" {
			typeText = "收入"
		}

		amount := h.decryptField(e.AmountEnc)
		if amount == "" || amount == e.AmountEnc {
			amount = strconv.FormatFloat(float64(e.AmountCent)/100.0, 'f', 2, 64)
		}

		note := h.decryptField(e.Note)
		dateStr := e.OccurredAt.Format("2006-01-02")

		f.SetCellValue(sheetName, fmt.Sprintf("A%d", row), typeText)
		f.SetCellValue(sheetName, fmt.Sprintf("B%d", row), e.Category)
		f.SetCellValue(sheetName, fmt.Sprintf("C%d", row), amount)
		f.SetCellValue(sheetName, fmt.Sprintf("D%d", row), note)
		f.SetCellValue(sheetName, fmt.Sprintf("E%d", row), dateStr)
	}

	// 设置列宽
	f.SetColWidth(sheetName, "A", "A", 10)
	f.SetColWidth(sheetName, "B", "B", 15)
	f.SetColWidth(sheetName, "C", "C", 12)
	f.SetColWidth(sheetName, "D", "D", 30)
	f.SetColWidth(sheetName, "E", "E", 12)

	c.Header("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"entries_%s.xlsx\"",
		time.Now().Format("20060102")))

	if err := f.Write(c.Writer); err != nil {
		util.Error(c, http.StatusInternalServerError, util.CodeServerErr, "导出失败")
	}
}
