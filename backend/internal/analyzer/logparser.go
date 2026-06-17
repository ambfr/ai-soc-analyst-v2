// internal/analyzer/logparser.go
package analyzer

import (
	"net"
	"regexp"
	"strings"
)

var ipRegex = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

type IPResult struct {
	IP         string           `json:"ip"`
	Type       string           `json:"type"`
	Count      int              `json:"count"`
	Flags      []string         `json:"flags"`
	Techniques []MitreTechnique `json:"mitre_techniques"`
	Intel      ThreatIntel      `json:"threat_intel"`
	LLM        LLMExplanation   `json:"llm_explanation"`
	Severity   Severity         `json:"severity"`
}

type AnalyzeResult struct {
	Filename  string     `json:"filename"`
	SizeBytes int64      `json:"size_bytes"`
	TotalIPs  int        `json:"total_ips"`
	Results   []IPResult `json:"results"`
}

var privateRanges = []*net.IPNet{
	mustParseCIDR("10.0.0.0/8"),
	mustParseCIDR("172.16.0.0/12"),
	mustParseCIDR("192.168.0.0/16"),
	mustParseCIDR("127.0.0.0/8"),
}

func mustParseCIDR(cidr string) *net.IPNet {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		panic("invalid hardcoded CIDR: " + cidr)
	}
	return network
}

func classifyIP(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "external"
	}
	for _, r := range privateRanges {
		if r.Contains(ip) {
			return "internal"
		}
	}
	return "external"
}

func ParseLog(content string) []IPResult {
	lines := strings.Split(content, "\n")

	occurrences := make(map[string]int)
	failedLoginCounts := make(map[string]int)
	var order []string
	seen := make(map[string]bool)

	for _, line := range lines {
		ips := ipRegex.FindAllString(line, -1)
		lowerLine := strings.ToLower(line)

		for _, ip := range ips {
			occurrences[ip]++
			if !seen[ip] {
				seen[ip] = true
				order = append(order, ip)
			}

			if strings.Contains(lowerLine, "failed") && strings.Contains(lowerLine, "login") {
				failedLoginCounts[ip]++
			} else if strings.Contains(lowerLine, "failed password") {
				failedLoginCounts[ip]++
			}
		}
	}

	results := make([]IPResult, 0, len(order))
	for _, ip := range order {
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

		// NEW in Phase 6: compute severity using everything gathered above.
		severity := CalculateSeverity(flags, techniques, intel)

		results = append(results, IPResult{
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

	return results
}