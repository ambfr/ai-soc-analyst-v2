// cmd/server/main.go
package main

import (
	"bufio"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"ai-soc-analyst-v2/backend/internal/analyzer"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

func loadEnvFile(path string) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
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

// upgrader configures the WebSocket upgrade. CheckOrigin is set permissive
// here (allow all) since this is a local dev / portfolio project, not a
// production service handling untrusted origins.
var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin:     func(r *http.Request) bool { return true },
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
	router.GET("/analyze/stream", streamHandler)

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
// streamHandler upgrades the connection to a WebSocket, expects the client
// to send the raw log file content as the first text message, then streams
// IPResult updates back as they're computed.
func streamHandler(c *gin.Context) {
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Println("websocket upgrade failed:", err)
		return
	}
	defer conn.Close()

	// Wait for the client to send the log content as the first message.
	_, message, err := conn.ReadMessage()
	if err != nil {
		log.Println("websocket read failed:", err)
		return
	}

	content := string(message)

	// 300ms per line gives a visible "streaming in" effect without making
	// a large log file take forever. Tune this if your demo log is huge.
	analyzer.ParseLogStreaming(content, 300*time.Millisecond, func(result analyzer.IPResult) {
		if err := conn.WriteJSON(result); err != nil {
			log.Println("websocket write failed:", err)
		}
	})

	// Send a final "done" sentinel so the frontend knows the stream finished.
	conn.WriteJSON(gin.H{"done": true})
}