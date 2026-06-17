// internal/analyzer/logparser.go
//
// This file replaces the "just preview the file" logic from Phase 1 with
// real parsing: find every IP in the log, classify it as internal or
// external, count how often it appears, and flag simple suspicious patterns.
package analyzer

import (
	"net"
	"regexp"
	"strings"
)

// ipRegex matches IPv4 addresses like "192.168.1.5". This is the same pattern
// idea as the regex used in the v1 Python project, just compiled once at
// package load time (Go convention: compile regexes as package-level vars,
// not inside functions, since compiling is relatively expensive and the
// pattern never changes).
var ipRegex = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

// IPResult holds everything we know about one IP address found in the log.
// This will grow in later phases — MITRE technique in Phase 3, abuse score
// in Phase 4, severity in Phase 6 — but for now it just has the basics.
type IPResult struct {
	IP    string   `json:"ip"`
	Type  string   `json:"type"`  // "internal" or "external"
	Count int      `json:"count"` // how many times this IP appeared
	Flags []string `json:"flags"` // detected suspicious patterns, e.g. "repeated_failed_login"
}

// AnalyzeResult is the top-level response shape for /analyze, replacing
// Phase 1's PreviewResult.
type AnalyzeResult struct {
	Filename  string     `json:"filename"`
	SizeBytes int64      `json:"size_bytes"`
	TotalIPs  int        `json:"total_ips"`
	Results   []IPResult `json:"results"`
}

// privateRanges are the standard RFC1918 private IP blocks, plus loopback.
// We parse these once at startup rather than on every request.
var privateRanges = []*net.IPNet{
	mustParseCIDR("10.0.0.0/8"),
	mustParseCIDR("172.16.0.0/12"),
	mustParseCIDR("192.168.0.0/16"),
	mustParseCIDR("127.0.0.0/8"),
}

func mustParseCIDR(cidr string) *net.IPNet {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		// This can only fail if we typo'd one of the CIDR strings above,
		// which would be a bug in our own code, not a runtime/user error —
		// so panic is appropriate here rather than returning an error up
		// the call chain. Panics in Go are reserved for "this should be
		// impossible" situations, not normal error handling.
		panic("invalid hardcoded CIDR: " + cidr)
	}
	return network
}

// classifyIP returns "internal" if the IP falls within a private range,
// otherwise "external".
func classifyIP(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "external" // shouldn't happen given our regex, but be safe
	}
	for _, r := range privateRanges {
		if r.Contains(ip) {
			return "internal"
		}
	}
	return "external"
}

// ParseLog is the main entry point for Phase 2. It takes the raw log file
// content as a string, finds every IP, classifies and counts them, and
// detects simple suspicious patterns per IP.
//
// Splitting this out from the HTTP handling (which stays in main.go) keeps
// this function easily testable later — you could write a Go test that
// calls ParseLog directly with a sample string, no HTTP server needed.
func ParseLog(content string) []IPResult {
	lines := strings.Split(content, "\n")

	// occurrences maps each IP to how many lines mention it.
	occurrences := make(map[string]int)
	// failedLoginCounts tracks lines that look like failed login attempts,
	// per IP, so we can flag repeated ones.
	failedLoginCounts := make(map[string]int)
	// order preserves first-seen order of IPs, since Go maps have no
	// guaranteed iteration order and we want consistent output.
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

			// Very simple heuristic for now — Phase 3+ can make this richer.
			// We just check for common keywords indicating a failed login.
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

		// Flag repeated failed logins from the same IP — a classic brute
		// force signal. Threshold of 3 is arbitrary; tune later once you
		// see real sample logs.
		if failedLoginCounts[ip] >= 3 {
			flags = append(flags, "repeated_failed_login")
		}

		// Flag IPs that appear unusually often overall — could indicate
		// scanning or flooding. Also an arbitrary starter threshold.
		if occurrences[ip] >= 10 {
			flags = append(flags, "high_frequency")
		}

		results = append(results, IPResult{
			IP:    ip,
			Type:  classifyIP(ip),
			Count: occurrences[ip],
			Flags: flags,
		})
	}

	return results
}