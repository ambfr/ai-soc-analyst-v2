// internal/analyzer/mitre.go
//
// This file maps the simple "flags" produced by logparser.go (Phase 2) to
// real MITRE ATT&CK techniques. It's intentionally self-contained — no
// external API calls, just a local lookup table — so it can't fail at
// runtime due to network issues, and it's free.
package analyzer

// MitreTechnique describes one ATT&CK technique we care about. Real ATT&CK
// data has far more fields (sub-techniques, data sources, mitigations...),
// but for this dashboard we only need enough to show something meaningful
// next to each alert.
type MitreTechnique struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Tactic string `json:"tactic"`
	URL    string `json:"url"`
}

// flagToTechnique is the actual lookup table. The keys here must exactly
// match the flag strings produced in logparser.go's ParseLog function.
//
// Source: MITRE ATT&CK Enterprise matrix (attack.mitre.org). These IDs and
// names are stable — MITRE versions content but technique IDs don't change
// once published, so this table won't go stale the way an API response might.
var flagToTechnique = map[string]MitreTechnique{
	"repeated_failed_login": {
		ID:     "T1110",
		Name:   "Brute Force",
		Tactic: "Credential Access",
		URL:    "https://attack.mitre.org/techniques/T1110/",
	},
	"high_frequency": {
		ID:     "T1046",
		Name:   "Network Service Discovery",
		Tactic: "Discovery",
		URL:    "https://attack.mitre.org/techniques/T1046/",
	},
}

// MapFlagsToTechniques takes the flags detected for one IP and returns the
// corresponding MITRE techniques. A flag with no known mapping is silently
// skipped rather than erroring — new flags can be added to logparser.go
// over time without breaking this function; they just won't show a
// technique until someone adds an entry here too.
//
// Returns a slice, not a single value, because in principle one IP could
// trigger multiple flags that map to multiple techniques.
func MapFlagsToTechniques(flags []string) []MitreTechnique {
	techniques := make([]MitreTechnique, 0, len(flags))
	for _, flag := range flags {
		if tech, ok := flagToTechnique[flag]; ok {
			// The "value, ok := map[key]" pattern is how Go checks whether
			// a key exists, since a missing key just returns the zero value
			// (an empty MitreTechnique{}) rather than an error or nil.
			// `ok` tells us whether it was actually found.
			techniques = append(techniques, tech)
		}
	}
	return techniques
}