package scan

import "fmt"

func formatScanUserMessage(status string, scanned, skipped, threats int) string {
	switch status {
	case "stopped":
		if threats > 0 {
			return fmt.Sprintf("Scan stopped early. Checked %d file(s), skipped %d, found %d threat(s).", scanned, skipped, threats)
		}
		return fmt.Sprintf("Scan stopped early. Checked %d file(s), skipped %d.", scanned, skipped)
	case "completed":
		if threats > 0 {
			return fmt.Sprintf("Scan finished. Checked %d file(s), skipped %d, found %d threat(s).", scanned, skipped, threats)
		}
		return fmt.Sprintf("Scan finished. Checked %d file(s), skipped %d. No threats found.", scanned, skipped)
	default:
		if threats > 0 {
			return fmt.Sprintf("Scan %s. Checked %d file(s), found %d threat(s).", status, scanned, threats)
		}
		return fmt.Sprintf("Scan %s. Checked %d file(s).", status, scanned)
	}
}
