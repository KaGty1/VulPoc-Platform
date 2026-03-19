package handler

import (
	"mime"
	"net/http"
	"path/filepath"
	"strconv"

	"github.com/gin-gonic/gin"

	"vulpoc-backend/model"
	"vulpoc-backend/service"
)

type EntryHandler struct {
	service *service.KnowledgeService
}

func NewEntryHandler(svc *service.KnowledgeService) *EntryHandler {
	return &EntryHandler{service: svc}
}

func (h *EntryHandler) SearchEntries(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", c.DefaultQuery("pageSize", "12")))

	result := h.service.SearchEntries(model.SearchQuery{
		Keyword:  c.Query("keyword"),
		CVE:      c.Query("cve"),
		Tag:      c.Query("tag"),
		Source:   c.Query("source"),
		FileType: c.Query("file_type"),
		Page:     page,
		PageSize: pageSize,
	})
	c.JSON(http.StatusOK, gin.H{"code": 200, "data": result})
}

func (h *EntryHandler) GetEntry(c *gin.Context) {
	entry, err := h.service.GetEntry(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"code": 404, "msg": "entry not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"code": 200, "data": entry})
}

func (h *EntryHandler) ListSources(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"code": 200, "data": h.service.GetSources()})
}

func (h *EntryHandler) ListTags(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"code": 200, "data": h.service.GetTags()})
}

func (h *EntryHandler) GetStats(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"code": 200, "data": h.service.GetStats()})
}

func (h *EntryHandler) GetAsset(c *gin.Context) {
	path := c.Query("path")
	if path == "" {
		c.JSON(http.StatusBadRequest, gin.H{"code": 400, "msg": "missing asset path"})
		return
	}
	file, err := h.service.GetAsset(c.Param("id"), path)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"code": 404, "msg": "asset not found"})
		return
	}

	contentType := mime.TypeByExtension(filepath.Ext(file.Name))
	if contentType != "" {
		c.Header("Content-Type", contentType)
	}
	if filepath.Ext(file.Name) == ".pdf" {
		c.Header("Content-Disposition", "inline")
	}
	c.File(file.AbsolutePath)
}
