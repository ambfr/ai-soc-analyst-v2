// internal/analyzer/llmanalyzer.go
//
// Generates a short human-readable explanation and recommended action for
// a flagged IP, using Groq's hosted Llama 3.3 70B model. Groq's API is
// OpenAI-compatible, so this is a standard chat completions POST request.
package analyzer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const groqEndpoint = "https://api.groq.com/openai/v1/chat/completions"
const groqModel = "llama-3.3-70b-versatile"

// LLMExplanation is what we attach to each flagged IP.
type LLMExplanation struct {
	Explanation       string `json:"explanation"`
	RecommendedAction string `json:"recommended_action"`
	Generated         bool   `json:"generated"` // false if skipped (no flags, or no API key)
}

// --- Request/response shapes matching Groq's OpenAI-compatible API ---

type groqMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type groqRequest struct {
	Model    string        `json:"model"`
	Messages []groqMessage `json:"messages"`
	// Lower temperature = more consistent, less "creative" output — we want
	// reliable security explanations, not flowery prose.
	Temperature float64 `json:"temperature"`
	MaxTokens   int     `json:"max_tokens"`
}

type groqResponse struct {
	Choices []struct {
		Message groqMessage `json:"message"`
	} `json:"choices"`
}

var llmHTTPClient = &http.Client{Timeout: 15 * time.Second}

// ExplainIP generates an explanation for one flagged IP. It only makes sense
// to call this for IPs that actually triggered flags — calling it for clean
// IPs would just waste API calls generating "nothing suspicious here" text.
func ExplainIP(ip string, ipType string, flags []string, techniques []MitreTechnique, intel ThreatIntel) LLMExplanation {
	if len(flags) == 0 {
		return LLMExplanation{Generated: false}
	}

	apiKey := os.Getenv("GROQ_API_KEY")
	if apiKey == "" {
		return LLMExplanation{Generated: false}
	}

	prompt := buildPrompt(ip, ipType, flags, techniques, intel)

	reqBody := groqRequest{
		Model: groqModel,
		Messages: []groqMessage{
			{
				Role:    "system",
				Content: "You are a SOC (Security Operations Center) analyst assistant. Given structured detection data about one IP address, write a concise explanation of why it was flagged and a specific recommended action. Keep both under 2 sentences each. Be direct and technical, not flowery.",
			},
			{Role: "user", Content: prompt},
		},
		Temperature: 0.3,
		MaxTokens:   200,
	}

	explanation, err := callGroq(reqBody, apiKey)
	if err != nil {
		fmt.Printf("Groq call failed for %s: %v\n", ip, err)
		return LLMExplanation{Generated: false}
	}

	return explanation
}

func buildPrompt(ip string, ipType string, flags []string, techniques []MitreTechnique, intel ThreatIntel) string {
	var b strings.Builder
	fmt.Fprintf(&b, "IP address: %s (%s)\n", ip, ipType)
	fmt.Fprintf(&b, "Detected flags: %s\n", strings.Join(flags, ", "))

	if len(techniques) > 0 {
		var names []string
		for _, t := range techniques {
			names = append(names, fmt.Sprintf("%s (%s, tactic: %s)", t.Name, t.ID, t.Tactic))
		}
		fmt.Fprintf(&b, "Mapped MITRE ATT&CK techniques: %s\n", strings.Join(names, "; "))
	}

	if intel.Checked {
		fmt.Fprintf(&b, "AbuseIPDB data: confidence score %d/100, %d total reports, country: %s, ISP: %s\n",
			intel.AbuseScore, intel.TotalReports, intel.CountryCode, intel.ISP)
	}

	b.WriteString("\nRespond with exactly two lines in this format:\nExplanation: <your explanation>\nAction: <your recommended action>")

	return b.String()
}

func callGroq(reqBody groqRequest, apiKey string) (LLMExplanation, error) {
	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return LLMExplanation{}, err
	}

	req, err := http.NewRequest("POST", groqEndpoint, bytes.NewBuffer(jsonBody))
	if err != nil {
		return LLMExplanation{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := llmHTTPClient.Do(req)
	if err != nil {
		return LLMExplanation{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return LLMExplanation{}, err
	}

	if resp.StatusCode != 200 {
		return LLMExplanation{}, fmt.Errorf("groq returned status %d: %s", resp.StatusCode, string(body))
	}

	var parsed groqResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return LLMExplanation{}, err
	}

	if len(parsed.Choices) == 0 {
		return LLMExplanation{}, fmt.Errorf("groq returned no choices")
	}

	return parseExplanationText(parsed.Choices[0].Message.Content), nil
}

// parseExplanationText pulls "Explanation: ..." and "Action: ..." lines out
// of the model's raw text response. LLM output formatting isn't 100%
// guaranteed even with clear instructions, so this is intentionally
// forgiving — if it can't find the expected format, it falls back to
// dumping the whole response into the Explanation field rather than losing
// the content entirely.
func parseExplanationText(text string) LLMExplanation {
	lines := strings.Split(text, "\n")
	var explanation, action string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "explanation:") {
			explanation = strings.TrimSpace(line[len("explanation:"):])
		} else if strings.HasPrefix(lower, "action:") {
			action = strings.TrimSpace(line[len("action:"):])
		}
	}

	if explanation == "" && action == "" {
		// Fallback: couldn't parse the expected format, just use the raw text.
		explanation = strings.TrimSpace(text)
	}

	return LLMExplanation{
		Explanation:       explanation,
		RecommendedAction: action,
		Generated:         true,
	}
}