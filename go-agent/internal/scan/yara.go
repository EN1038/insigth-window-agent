package scan

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/sosecure/insite-agent/internal/config"
	"github.com/sosecure/insite-agent/internal/securefs"
)

type Match struct {
	Rule     string
	FilePath string
}

type Scanner struct {
	YaraExe string
}

func NewScanner(yaraExe string) *Scanner {
	return &Scanner{YaraExe: yaraExe}
}

func (s *Scanner) ScanBatch(ruleEntries, filePaths []string) ([]Match, error) {
	if len(filePaths) == 0 {
		return nil, nil
	}
	if _, err := os.Stat(s.YaraExe); err != nil {
		return nil, fmt.Errorf("yara engine not found: %s", s.YaraExe)
	}

	listPath := filepath.Join(os.TempDir(), fmt.Sprintf("insite_scan_%d.txt", time.Now().UnixNano()))
	if err := writeScanListUTF16(listPath, filePaths); err != nil {
		return nil, err
	}
	defer securefs.WipeAndRemove(listPath)

	args := buildRuleArgs(ruleEntries)
	args = append(args, "--scan-list", listPath)

	cmd := exec.Command(s.YaraExe, args...)
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return parseYaraOutput(string(out)), nil
		}
		if len(out) > 0 {
			return nil, fmt.Errorf("yara error: %s", strings.TrimSpace(string(out)))
		}
		return nil, err
	}
	return parseYaraOutput(string(out)), nil
}

func writeScanListUTF16(path string, files []string) error {
	var u16 []uint16
	for _, f := range files {
		u16 = append(u16, utf16.Encode([]rune(f))...)
		u16 = append(u16, '\r', '\n')
	}
	b := []byte{0xFF, 0xFE}
	for _, c := range u16 {
		b = append(b, byte(c), byte(c>>8))
	}
	return os.WriteFile(path, b, 0o600)
}

func buildRuleArgs(entries []string) []string {
	// Prefer a single primary ruleset. Passing multiple files with
	// Custom:/Master: namespaces makes this yara64 build emit errors and
	// drop real matches (observed: 0 hits with 2 entries, many hits with rules.yar alone).
	if preferred := preferRuleEntrypoint(entries); preferred != "" {
		return []string{preferred}
	}
	if len(entries) == 0 {
		return nil
	}
	return []string{entries[0]}
}

func preferRuleEntrypoint(entries []string) string {
	if len(entries) == 0 {
		return ""
	}
	priority := []string{"_insite_all.yar", "rules_unified.yar", "index.yar", "rules.yar"}
	byBase := map[string]string{}
	for _, e := range entries {
		byBase[strings.ToLower(filepath.Base(e))] = e
	}
	for _, name := range priority {
		if p, ok := byBase[name]; ok {
			if st, err := os.Stat(p); err == nil && st.Size() > 0 {
				return p
			}
		}
	}
	// Fallback: largest .yar entry (skip tiny stubs).
	best := ""
	var bestSize int64
	for _, e := range entries {
		st, err := os.Stat(e)
		if err != nil || st.Size() <= 64 {
			continue
		}
		if st.Size() > bestSize {
			bestSize = st.Size()
			best = e
		}
	}
	if best != "" {
		return best
	}
	return entries[0]
}

func parseYaraOutput(output string) []Match {
	var matches []Match
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "warning:") || strings.HasPrefix(lower, "error:") || strings.HasPrefix(lower, "error ") {
			continue
		}
		// Compile diagnostics look like: C:\path\file.yar(12): error: ...
		if strings.Contains(lower, "): error") || strings.Contains(lower, "): warning") {
			continue
		}
		idx := strings.Index(line, " ")
		if idx <= 0 {
			continue
		}
		rule := line[:idx]
		path := strings.Trim(strings.TrimSpace(line[idx+1:]), `"`)
		if rule == "" || path == "" {
			continue
		}
		// Defensive: never treat compiler chatter as a match path.
		if strings.HasPrefix(strings.ToLower(path), "error:") || strings.HasPrefix(strings.ToLower(path), "warning:") {
			continue
		}
		matches = append(matches, Match{Rule: rule, FilePath: path})
	}
	return matches
}

func ResolveYaraPath(baseDir, configured string) string {
	installDir := config.InstallDir()
	var candidates []string
	if configured != "" {
		candidates = append(candidates, configured)
	}
	parentDir := filepath.Dir(baseDir)
	grandParentDir := filepath.Dir(parentDir)

	candidates = append(candidates,
		filepath.Join(baseDir, "Engine", "Yara", "yara64.exe"),
		filepath.Join(baseDir, "yara64.exe"),
		filepath.Join(parentDir, "Engine", "Yara", "yara64.exe"),
		filepath.Join(grandParentDir, "Engine", "Yara", "yara64.exe"),
		filepath.Join(installDir, "Engine", "Yara", "yara64.exe"),
		filepath.Join(installDir, "yara64.exe"),
		`C:\Program Files\SOSECURE\SOSECURE Threat inSight\Engine\Yara\yara64.exe`,
	)
	for _, p := range candidates {
		p = strings.TrimSpace(p)
		if p != "" {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	return filepath.Join(baseDir, "Engine", "Yara", "yara64.exe")
}
