// internal/analyzer/stream.go
//
// A streaming variant of ParseLog. Instead of returning one final slice,
// it processes the log line-by-line and invokes a callback each time an
// IP's data changes (first seen, or flag/count update), with a short delay
// between lines to simulate a live feed for demo purposes.
package analyzer

import (
	"strings"
	"time"
)

// ParseLogStreaming mirrors ParseLog's logic but emits incremental updates
// via the onUpdate callback as it processes each line, rather than waiting
// until the whole file is read. delayPerLine controls how long to pause
// between lines — purely for visual effect, so a demo doesn't finish instantly.
func ParseLogStreaming(content string, delayPerLine time.Duration, onUpdate func(IPResult)) {
	lines := strings.Split(content, "\n")

	occurrences := make(map[string]int)
	failedLoginCounts := make(map[string]int)

	for _, line := range lines {
		ips := ipRegex.FindAllString(line, -1)
		lowerLine := strings.ToLower(line)

		for _, ip := range ips {
			occurrences[ip]++

			if strings.Contains(lowerLine, "failed") && strings.Contains(lowerLine, "login") {
				failedLoginCounts[ip]++
			} else if strings.Contains(lowerLine, "failed password") {
				failedLoginCounts[ip]++
			}

			var flags []string
			if failedLoginCounts[ip] >= 3 {
				flags = append(flags, "repeated_failed_login")
			}
			if occurrences[ip] >= 10 {
				flags = append(flags, "high_frequency")
			}

			techniques := MapFlagsToTechniques(flags)
			ipType := classifyIP(ip)

			var intel ThreatIntel
			if ipType == "external" {
				intel = CheckIP(ip)
			} else {
				intel = ThreatIntel{Checked: false}
			}

			llmResult := ExplainIP(ip, ipType, flags, techniques, intel)
			severity := CalculateSeverity(flags, techniques, intel)

			onUpdate(IPResult{
				IP:         ip,
				Type:       ipType,
				Count:      occurrences[ip],
				Flags:      flags,
				Techniques: techniques,
				Intel:      intel,
				LLM:        llmResult,
				Severity:   severity,
			})
		}

		if delayPerLine > 0 {
			time.Sleep(delayPerLine)
		}
	}
}