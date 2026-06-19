# Watchtower

AI-powered SOC (Security Operations Center) log analyzer. Upload a network log file and Watchtower will detect suspicious IP activity, classify it, map it to real MITRE ATT&CK techniques, check it against a live threat intelligence database, and generate a plain-English explanation and recommended action using an LLM — all shown in a dashboard built for this project.

**Live demo:** https://watchtowerr.vercel.app
*(backend is on a free tier and may take 30–60 seconds to wake up on the first request)*

![Severity: high](https://img.shields.io/badge/severity-high-orange) ![Go](https://img.shields.io/badge/backend-Go-00ADD8) ![SvelteKit](https://img.shields.io/badge/frontend-SvelteKit-FF3E00)

---

## What it does

You upload a `.log` file containing network activity (failed logins, connection attempts, etc.). Watchtower:

1. **Parses the log** and pulls out every IP address mentioned
2. **Classifies** each IP as internal (private network) or external
3. **Flags suspicious patterns** — currently repeated failed logins and unusually high request frequency
4. **Maps flags to MITRE ATT&CK techniques** (e.g. repeated failed logins → T1110, Brute Force) using a local lookup table
5. **Checks external IPs against AbuseIPDB**, a real-world threat intelligence database, for abuse history and reputation
6. **Generates a plain-English explanation and recommended action** for each flagged IP using Llama 3.3 70B (via Groq)
7. **Scores severity** (none / low / medium / high / critical) by combining all of the above
8. Displays everything in a dashboard with summary stats, charts, and expandable detail rows

There's also a **Live mode** — instead of waiting for the whole file to process, it streams results over a WebSocket and shows each detection as it happens, simulating a real-time monitoring feed.

## Why I rebuilt it

I originally built a version of this project (linked below) using Python, Streamlit, and a local GPT-2 model. It worked, but I wanted to push it further: a real frontend instead of Streamlit, real threat intelligence instead of just text generation, and a different tech stack than the other projects in my portfolio, so I rebuilt it from scratch using Go and SvelteKit instead of Python and React.

This was also my first project in Go. If you're learning Go too, the codebase has fairly heavy inline comments explaining Go-specific patterns (error handling, structs, goroutines) as a kind of built-in learning trail.

**Previous version:** [ai-soc-analyst (v1, Python/Streamlit/GPT-2)](https://github.com/ambfr/ai-soc-analyst)

## Tech stack

| Layer | Choice | Why |
|---|---|---|
| Backend | Go + [Gin](https://github.com/gin-gonic/gin) | Fast, statically typed, different from the FastAPI/Python used in my other projects |
| LLM | [Groq](https://groq.com) running Llama 3.3 70B | Fast inference, generous free tier, far better explanations than a local GPT-2 |
| Threat intel | [AbuseIPDB](https://www.abuseipdb.com) | Real-world IP reputation data, free tier |
| Framework mapping | [MITRE ATT&CK](https://attack.mitre.org) | Industry-standard taxonomy for describing attacker behavior |
| Frontend | [SvelteKit](https://kit.svelte.dev) + Tailwind CSS | Different frontend paradigm from React, used elsewhere in my portfolio |
| Charts | [Chart.js](https://www.chartjs.org) | Severity distribution and traffic split visualizations |
| Real-time | [Gorilla WebSocket](https://github.com/gorilla/websocket) | Powers the optional "live mode" streaming feed |
| Backend hosting | [Render](https://render.com) | Free tier, native Go support |
| Frontend hosting | [Vercel](https://vercel.com) | First-class SvelteKit support |

## Architecture

```
You upload a .log file
        │
        ▼
Go (Gin) backend — POST /analyze or WebSocket /analyze/stream
        │
        ├── log parser        → finds IPs, classifies internal/external, counts occurrences
        ├── MITRE mapper      → flags → real ATT&CK technique IDs (local lookup, no API)
        ├── threat intel      → external IPs checked against AbuseIPDB (cached)
        ├── LLM explainer     → Groq/Llama generates explanation + recommended action
        └── severity scorer   → combines all of the above into one severity label
        │
        ▼
JSON response, one object per IP:
{
  "ip": "203.0.113.5",
  "type": "external",
  "count": 4,
  "flags": ["repeated_failed_login"],
  "mitre_techniques": [
    { "id": "T1110", "name": "Brute Force", "tactic": "Credential Access" }
  ],
  "threat_intel": { "abuse_score": 0, "country_code": "", "isp": "" },
  "llm_explanation": {
    "explanation": "...",
    "recommended_action": "..."
  },
  "severity": "high"
}
        │
        ▼
SvelteKit dashboard — summary stats, charts, expandable per-IP detail rows
```

## Running it locally

You'll need [Go](https://go.dev/dl/) 1.22+, [Node.js](https://nodejs.org) 18+, and free API keys from [Groq](https://console.groq.com/keys) and [AbuseIPDB](https://www.abuseipdb.com/register).

### 1. Clone the repo
```bash
git clone https://github.com/ambfr/ai-soc-analyst-v2.git
cd ai-soc-analyst-v2
```

### 2. Backend setup
```bash
cd backend
go mod tidy
```

Create a file called `.env` inside `backend/` with your API keys:
```
ABUSEIPDB_API_KEY=your_key_here
GROQ_API_KEY=your_key_here
```

Run the server:
```bash
go run cmd/server/main.go
```
You should see `Listening and serving HTTP on :8080`. Leave this terminal running.

### 3. Frontend setup
Open a **new terminal window** (keep the backend running in the first one):
```bash
cd frontend
npm install
npm run dev
```
Open the URL it gives you (usually `http://localhost:5173`).

### 4. Try it
A sample log file is included at `backend/sample.log` (or create your own — see format below). Upload it and click **Analyze**, or toggle **Live mode** first to see results stream in one at a time.

## Log file format

Watchtower looks for IPv4 addresses anywhere in each line, plus the words "failed" and "login" (case-insensitive) to detect failed login attempts. A line like this:

```
2026-06-17 10:01:02 Failed login attempt from 203.0.113.5
```

will be picked up correctly. Any plaintext `.log` or `.txt` file with IP addresses in it works — the parser doesn't require a specific log format.

## Project structure

```
ai-soc-analyst-v2/
├── backend/
│   ├── cmd/server/main.go          # entry point, HTTP routes, WebSocket handler
│   └── internal/analyzer/
│       ├── logparser.go            # IP extraction, classification, flagging
│       ├── stream.go               # streaming variant used by live mode
│       ├── mitre.go                # MITRE ATT&CK lookup table
│       ├── threatintel.go          # AbuseIPDB client + cache
│       ├── llmanalyzer.go          # Groq/Llama client
│       └── severity.go             # severity scoring logic
└── frontend/
    └── src/routes/+page.svelte     # the entire dashboard UI
```

## Known limitations

- Detection logic is intentionally simple (two flag types: repeated failed logins, high frequency) — built to demonstrate the pipeline, not to be a production-grade detection engine
- AbuseIPDB's free tier allows 1,000 checks/day; results are cached in memory for an hour to stay well under that
- The free Render tier spins down after inactivity, so the first request after idle time takes 30–60 seconds
- "Live mode" simulates streaming from an uploaded file rather than tailing a real live log source

## What I'd add next

- Real-time ingestion from an actual log source (e.g. tailing a file or syslog feed) instead of simulating it from an upload
- Alert correlation — grouping related events into a single incident instead of one alert per IP
- A feedback loop where marking an alert as a false positive improves future scoring

## Credits

Threat data from [AbuseIPDB](https://www.abuseipdb.com). Technique definitions from [MITRE ATT&CK®](https://attack.mitre.org). LLM inference via [Groq](https://groq.com).
