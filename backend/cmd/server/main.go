// cmd/server/main.go
package main

import (
	"log"

	"ai-soc-analyst-v2/backend/internal/analyzer"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	router := gin.Default()

	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:5173"},
		AllowMethods:     []string{"GET", "POST", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type"},
		AllowCredentials: true,
	}))

	router.POST("/analyze", analyzeHandler)

	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	log.Println("Server starting on :8080")
	if err := router.Run(":8080"); err != nil {
		log.Fatal("Failed to start server: ", err)
	}
}

func analyzeHandler(c *gin.Context) {
	fileHeader, err := c.FormFile("file")
	if err != nil {
		c.JSON(400, gin.H{"error": "no file uploaded, or upload was malformed"})
		return
	}

	if fileHeader.Size == 0 {
		c.JSON(400, gin.H{"error": "uploaded file is empty"})
		return
	}

	result, err := analyzer.PreviewFile(fileHeader)
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to read uploaded file: " + err.Error()})
		return
	}

	c.JSON(200, result)
}