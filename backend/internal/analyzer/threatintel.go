// internal/analyzer/threatintel.go
//
// Calls AbuseIPDB for each external IP and caches results in memory to
// avoid burning through the free tier's 1000 checks/day on repeat lookups.
package analyzer

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"
)

// ThreatIntel holds the fields we care about from AbuseIPDB's response.
// AbuseIPDB returns a lot more (hostnames, usage type, reports list...) but
// these are the fields useful for a dashboard at a glance.
type ThreatIntel struct {
	AbuseScore   int    `json:"abuse_score"`
	CountryCode  string `json:"country_code"`
	ISP          string `json:"isp"`
	TotalReports int    `json:"total_reports"`
	Checked      bool   `json:"checked"` // false if we skipped the lookup (e.g. internal IP, or no API key)
}

// abuseIPDBResponse mirrors the JSON AbuseIPDB actually returns. We only
// need the "data" object, but the struct shape must match the API's nesting
// for encoding/json to populate it correctly.
type abuseIPDBResponse struct {
	Data struct {
		AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
		CountryCode          string `json:"countryCode"`
		ISP                  string `json:"isp"`
		TotalReports         int    `json:"totalReports"`
	} `json:"data"`
}

// cacheEntry pairs a cached result with when it was stored, so we can
// expire old entries instead of caching forever.
type cacheEntry struct {
	result    ThreatIntel
	fetchedAt time.Time
}

const cacheTTL = 1 * time.Hour

// cache and cacheMu together form a simple thread-safe in-memory cache.
// sync.Mutex is Go's basic lock — we need it because Gin can handle multiple
// requests concurrently, and without locking, two goroutines reading/writing
// the same map at the same time would corrupt it or crash the program.
// This has no Python equivalent need in simple scripts, since you're not
// usually handling concurrent requests by hand there.
var (
	cache   = make(map[string]cacheEntry)
	cacheMu sync.Mutex
)

// httpClient is reused across requests rather than creating a new one each
// time — this is idiomatic Go; http.Client is safe for concurrent use and
// reuses connections.
var httpClient = &http.Client{Timeout: 8 * time.Second}

// CheckIP looks up a single external IP against AbuseIPDB, using the cache
// when possible. If no API key is configured, it returns a result with
// Checked: false rather than erroring — this lets the rest of the pipeline
// keep working even before you've set up a key.
func CheckIP(ip string) ThreatIntel {
	cacheMu.Lock()
	if entry, ok := cache[ip]; ok && time.Since(entry.fetchedAt) < cacheTTL {
		cacheMu.Unlock()
		return entry.result
	}
	cacheMu.Unlock()

	apiKey := os.Getenv("ABUSEIPDB_API_KEY")
	if apiKey == "" {
		// No key configured — skip gracefully instead of failing the whole
		// request. The frontend can show "not checked" for this field.
		return ThreatIntel{Checked: false}
	}

	result, err := fetchFromAbuseIPDB(ip, apiKey)
	if err != nil {
		// Network errors, rate limits, etc. — log it, but don't crash the
		// whole /analyze request just because one enrichment call failed.
		fmt.Printf("AbuseIPDB lookup failed for %s: %v\n", ip, err)
		return ThreatIntel{Checked: false}
	}

	cacheMu.Lock()
	cache[ip] = cacheEntry{result: result, fetchedAt: time.Now()}
	cacheMu.Unlock()

	return result
}

func fetchFromAbuseIPDB(ip string, apiKey string) (ThreatIntel, error) {
	req, err := http.NewRequest("GET", "https://api.abuseipdb.com/api/v2/check", nil)
	if err != nil {
		return ThreatIntel{}, err
	}

	// Query parameters go through req.URL.Query(), not string concatenation
	// — this handles URL-encoding for us automatically.
	q := req.URL.Query()
	q.Add("ipAddress", ip)
	q.Add("maxAgeInDays", "90")
	req.URL.RawQuery = q.Encode()

	req.Header.Set("Key", apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return ThreatIntel{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ThreatIntel{}, err
	}

	if resp.StatusCode != 200 {
		return ThreatIntel{}, fmt.Errorf("AbuseIPDB returned status %d: %s", resp.StatusCode, string(body))
	}

	var parsed abuseIPDBResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return ThreatIntel{}, err
	}

	return ThreatIntel{
		AbuseScore:   parsed.Data.AbuseConfidenceScore,
		CountryCode:  parsed.Data.CountryCode,
		ISP:          parsed.Data.ISP,
		TotalReports: parsed.Data.TotalReports,
		Checked:      true,
	}, nil
}