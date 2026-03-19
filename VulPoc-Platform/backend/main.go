package main

import (
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"

	"vulpoc-backend/config"
	"vulpoc-backend/handler"
	"vulpoc-backend/indexer"
	"vulpoc-backend/ingest"
	"vulpoc-backend/parser"
	"vulpoc-backend/repository"
	"vulpoc-backend/router"
	"vulpoc-backend/service"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	registry := parser.NewRegistry()
	loadResult, err := ingest.LoadSources(cfg, registry)
	if err != nil {
		log.Fatalf("failed to ingest sources: %v", err)
	}

	repo := repository.NewMemoryRepository(loadResult.Entries, loadResult.Sources, loadResult.Stats, registry.Names())
	idx := indexer.New(loadResult.Entries)
	svc := service.NewKnowledgeService(repo, idx)
	entryHandler := handler.NewEntryHandler(svc)

	engine := gin.Default()
	engine.Use(cors())
	router.InitRouter(engine, entryHandler)
	registerFrontend(engine, cfg.FrontendDist)

	log.Printf("loaded %d entries from %d source(s)", len(loadResult.Entries), len(loadResult.Sources))
	for _, source := range loadResult.Sources {
		log.Printf("source=%s entries=%d files=%d skipped=%d failed=%d path=%s",
			source.Name, source.Entries, source.FilesScanned, source.FilesSkipped, source.ParseFailed, source.Path)
	}
	log.Printf("server listening on :%s", cfg.ServerPort)

	if err := engine.Run(":" + cfg.ServerPort); err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
}

func cors() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Accept")
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

func registerFrontend(engine *gin.Engine, distDir string) {
	indexPath := filepath.Join(distDir, "index.html")
	if _, err := os.Stat(indexPath); err == nil {
		engine.Static("/assets", filepath.Join(distDir, "assets"))
		engine.StaticFile("/favicon.svg", filepath.Join(distDir, "favicon.svg"))
		engine.StaticFile("/icons.svg", filepath.Join(distDir, "icons.svg"))

		engine.GET("/", func(c *gin.Context) {
			c.File(indexPath)
		})

		engine.NoRoute(func(c *gin.Context) {
			if strings.HasPrefix(c.Request.URL.Path, "/api/") {
				c.JSON(http.StatusNotFound, gin.H{
					"code": 404,
					"msg":  "route not found",
				})
				return
			}
			c.File(indexPath)
		})
		return
	} else if !errors.Is(err, os.ErrNotExist) {
		log.Printf("frontend dist check failed: %v", err)
	}

	engine.GET("/", func(c *gin.Context) {
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(`<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>VulPoc Platform API</title>
</head>
<body style="font-family: sans-serif; padding: 32px; line-height: 1.6;">
  <h1>VulPoc Platform 知识库后端已启动</h1>
  <p>当前地址是 API 服务端口。</p>
  <p>可访问接口：<code>/api/v1/entries</code>、<code>/api/v1/sources</code>、<code>/api/v1/tags</code>、<code>/api/v1/stats</code></p>
  <p>如果要打开前端页面，请先在 <code>../frontend</code> 执行 <code>npm run build</code> 或 <code>npm run dev</code>。</p>
</body>
</html>`))
	})
}
