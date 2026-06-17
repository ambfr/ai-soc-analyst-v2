// cmd/server/main.go
package main

import (
	"io"
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

	// Open the uploaded file and read its full content into memory as a
	// string. multipart.File satisfies io.Reader, so io.ReadAll works
	// directly on it. For very large log files you'd eventually want to
	// stream this instead, but for now reading fully into memory is simpler
	// and fine for typical log sizes.
	file, err := fileHeader.Open()
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to open uploaded file: " + err.Error()})
		return
	}
	defer file.Close()

	contentBytes, err := io.ReadAll(file)
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to read uploaded file: " + err.Error()})
		return
	}

	results := analyzer.ParseLog(string(contentBytes))

	c.JSON(200, analyzer.AnalyzeResult{
		Filename:  fileHeader.Filename,
		SizeBytes: fileHeader.Size,
		TotalIPs:  len(results),
		Results:   results,
	})
}