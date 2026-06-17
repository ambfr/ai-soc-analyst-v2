// cmd/server/main.go
package main

import (
	"bufio"
	"io"
	"log"
	"os"
	"strings"

	"ai-soc-analyst-v2/backend/internal/analyzer"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

// loadEnvFile reads a simple KEY=VALUE .env file and sets each line as an
// environment variable via os.Setenv. This is a deliberately minimal
// implementation — no quoting, no comments, no multiline values — just
// enough for API keys. If the file doesn't exist, it silently does nothing
// rather than erroring, since env vars might be set another way instead
// (e.g. on a deployed server like Render, which has its own env var UI).
func loadEnvFile(path string) {
	file, err := os.Open(path)
	if err != nil {
		return // .env not found — that's fine, not an error
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue // skip blank lines and comments
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		os.Setenv(key, value)
	}
}

func main() {
	loadEnvFile(".env")

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