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
	defer os.Remove(listPath)

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
	if len(entries) == 1 {
		return []string{entries[0]}
	}
	var args []string
	for i, e := range entries {
		ns := fmt.Sprintf("R%d", i)
		if i == 0 {
			ns = "Custom"
		} else if i == 1 {
			ns = "Master"
		}
		args = append(args, fmt.Sprintf(`%s:"%s"`, ns, e))
	}
	return args
}

func parseYaraOutput(output string) []Match {
	var matches []Match
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "warning:") {
			continue
		}
		idx := strings.Index(line, " ")
		if idx <= 0 {
			continue
		}
		rule := line[:idx]
		path := strings.Trim(strings.TrimSpace(line[idx+1:]), `"`)
		matches = append(matches, Match{Rule: rule, FilePath: path})
	}
	return matches
}

func ResolveYaraPath(baseDir, configured string) string {
	installDir := config.InstallDir()
	candidates := []string{configured}
	if configured == "" {
		candidates = nil
	}
	candidates = append(candidates,
		filepath.Join(installDir, "yara64.exe"),
		filepath.Join(installDir, "Engine", "Yara", "yara64.exe"),
		filepath.Join(baseDir, "yara64.exe"),
		filepath.Join(baseDir, "Engine", "Yara", "yara64.exe"),
	)
	for _, p := range candidates {
		if p != "" {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	if configured != "" {
		return configured
	}
	return filepath.Join(installDir, "Engine", "Yara", "yara64.exe")
}
