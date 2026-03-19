package router

import (
	"github.com/gin-gonic/gin"

	"vulpoc-backend/handler"
)

func InitRouter(engine *gin.Engine, entryHandler *handler.EntryHandler) {
	api := engine.Group("/api/v1")
	{
		api.GET("/entries", entryHandler.SearchEntries)
		api.GET("/entries/:id", entryHandler.GetEntry)
		api.GET("/entries/:id/assets", entryHandler.GetAsset)
		api.GET("/sources", entryHandler.ListSources)
		api.GET("/tags", entryHandler.ListTags)
		api.GET("/stats", entryHandler.GetStats)

		// Backward-compatible aliases for the older frontend routes.
		api.GET("/vulns", entryHandler.SearchEntries)
		api.GET("/vulns/:id", entryHandler.GetEntry)
		api.GET("/vulns/:id/files", entryHandler.GetAsset)
	}
}
