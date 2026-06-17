// internal/analyzer/severity.go
//
// Combines threat intel, MITRE mapping, and flag count into a single
// severity label the frontend can sort/filter/color-code by. This is a
// simple weighted heuristic, not a "real" SOC scoring model — the goal is
// a sensible single field for the dashboard, not perfect accuracy.
package analyzer

// Severity levels, as constants. Go doesn't have enums like Python's Enum
// class, but the idiomatic equivalent is a typed string with a set of
// predefined constant values — this gives you named, reusable values
// without magic strings scattered everywhere.
type Severity string

const (
	SeverityNone     Severity = "none"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// CalculateSeverity decides a severity label for one IP based on whatever
// signals are available. Priority order:
//  1. AbuseIPDB score, if we actually checked the IP — this is real-world
//     reputation data, so it's weighted most heavily.
//  2. MITRE tactic, as a secondary signal — some tactics (Credential Access,
//     Lateral Movement) are inherently more serious than others (Discovery).
//  3. Flag count alone, as a fallback when there's no intel data at all
//     (e.g. internal IP, or AbuseIPDB key not configured).
func CalculateSeverity(flags []string, techniques []MitreTechnique, intel ThreatIntel) Severity {
	if len(flags) == 0 {
		return SeverityNone
	}

	// If we have real abuse data, let it dominate the decision — it reflects
	// actual observed behavior across the internet, not just our own
	// log-based heuristics.
	if intel.Checked {
		switch {
		case intel.AbuseScore >= 90:
			return SeverityCritical
		case intel.AbuseScore >= 60:
			return SeverityHigh
		case intel.AbuseScore >= 25:
			return SeverityMedium
		case intel.AbuseScore > 0:
			return SeverityLow
		}
		// AbuseScore == 0 with intel.Checked == true means AbuseIPDB has no
		// abuse history for this IP. Don't return "none" here, though —
		// our own log-based flags still indicated something worth a look,
		// so fall through to the tactic/flag-count logic below instead of
		// trusting AbuseIPDB's silence as "definitely safe."
	}

	// Tactic-based fallback: some MITRE tactics are weighted higher than
	// others, reflecting roughly how serious that category of activity is.
	highSeverityTactics := map[string]bool{
		"Credential Access": true,
		"Lateral Movement":  true,
		"Exfiltration":      true,
		"Impact":            true,
	}
	for _, t := range techniques {
		if highSeverityTactics[t.Tactic] {
			return SeverityHigh
		}
	}

	// Final fallback: just use how many distinct flags triggered.
	switch {
	case len(flags) >= 2:
		return SeverityMedium
	default:
		return SeverityLow
	}
}