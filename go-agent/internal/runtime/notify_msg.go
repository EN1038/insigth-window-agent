package runtime

import "fmt"

// formatTISyncUserMessage builds a plain-language sync summary for UI / mailbox.
func formatTISyncUserMessage(rulesN, ssdeepN int) string {
	switch {
	case rulesN <= 0 && ssdeepN <= 0:
		return "Threat intelligence is up to date. No new detection rules or fuzzy signatures were needed."
	case rulesN > 0 && ssdeepN > 0:
		return fmt.Sprintf(
			"Threat intelligence updated. Downloaded %d YARA rule file(s) and %d ssdeep signature pack(s).",
			rulesN, ssdeepN)
	case rulesN > 0:
		return fmt.Sprintf(
			"Threat intelligence updated. Downloaded %d YARA rule file(s). Fuzzy signatures were already current.",
			rulesN)
	default:
		return fmt.Sprintf(
			"Threat intelligence updated. Downloaded %d ssdeep signature pack(s). YARA rules were already current.",
			ssdeepN)
	}
}
