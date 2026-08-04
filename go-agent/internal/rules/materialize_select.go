package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	// rule Name { ... } OR rule Name : tag1 tag2 { ... }
	reYaraRuleName = regexp.MustCompile(`(?m)^\s*(?:private\s+)?rule\s+([A-Za-z_][A-Za-z0-9_]*)\b`)
	reYaraImport   = regexp.MustCompile(`(?m)^\s*import\s+"([^"]+)"`)
	// yara64 error forms observed on Windows:
	//   C:\path\file.yar(11): error: duplicated identifier "x"
	//   C:\path\./file.yar(11): error: ...
	//   error: rule "x" in C:\path\file.yar(19): invalid field name "y"
	reErrPathPrefixed = regexp.MustCompile(`(?i)^(.+\.ya?ra?)\(\d+\):\s*error:`)
	reErrPathInMsg    = regexp.MustCompile(`(?i)error:.*\bin\s+(.+\.ya?ra?)\(\d+\):`)
)

// unsupportedYaraModules are not available in the bundled yara64 build.
var unsupportedYaraModules = map[string]bool{
	"androguard": true,
	"cuckoo":     true,
}

type ruleCandidate struct {
	rel      string
	hash     string
	ruleIDs  []string
	imports  []string
	prefer   int
	skip     bool
	skipWhy  string
}

func buildScanIncludeList(destRoot string, written []string) []string {
	cands := make([]ruleCandidate, 0, len(written))
	for _, rel := range written {
		rel = normalizeRel(rel)
		if rel == "" || strings.EqualFold(filepath.Base(rel), "_insite_all.yar") {
			continue
		}
		low := strings.ToLower(rel)
		ext := strings.ToLower(filepath.Ext(rel))
		if ext != ".yar" && ext != ".yara" {
			continue
		}
		c := ruleCandidate{rel: rel, prefer: pathPreferScore(rel)}
		if shouldSkipRulePath(low) {
			c.skip = true
			c.skipWhy = "path"
			cands = append(cands, c)
			continue
		}
		plain, err := os.ReadFile(filepath.Join(destRoot, filepath.FromSlash(rel)))
		if err != nil {
			c.skip = true
			c.skipWhy = "read"
			cands = append(cands, c)
			continue
		}
		sum := sha256.Sum256(plain)
		c.hash = hex.EncodeToString(sum[:])
		c.ruleIDs = extractYaraRuleNames(string(plain))
		c.imports = extractYaraImports(string(plain))
		if why := unsupportedImportReason(c.imports); why != "" {
			c.skip = true
			c.skipWhy = why
		}
		// Pure include wrappers re-pull trees and cause nested duplicate identifiers.
		if !c.skip && len(c.ruleIDs) == 0 {
			c.skip = true
			c.skipWhy = "no-rules"
		}
		cands = append(cands, c)
	}

	// Prefer richer files first (more rule IDs), then better paths.
	sort.SliceStable(cands, func(i, j int) bool {
		if len(cands[i].ruleIDs) != len(cands[j].ruleIDs) {
			return len(cands[i].ruleIDs) > len(cands[j].ruleIDs)
		}
		if cands[i].prefer != cands[j].prefer {
			return cands[i].prefer < cands[j].prefer
		}
		return cands[i].rel < cands[j].rel
	})

	seenHash := map[string]string{}
	seenRule := map[string]string{}
	seenBase := map[string]string{}
	selected := make([]string, 0, len(cands))

	for _, c := range cands {
		if c.skip {
			continue
		}
		base := strings.ToLower(filepath.Base(c.rel))
		if prev, ok := seenBase[base]; ok {
			_ = prev
			continue
		}
		if prev, ok := seenHash[c.hash]; ok {
			_ = prev
			continue
		}
		conflict := false
		for _, id := range c.ruleIDs {
			key := strings.ToLower(id)
			if prev, ok := seenRule[key]; ok {
				_ = prev
				conflict = true
				break
			}
		}
		if conflict {
			continue
		}
		seenBase[base] = c.rel
		seenHash[c.hash] = c.rel
		for _, id := range c.ruleIDs {
			seenRule[strings.ToLower(id)] = c.rel
		}
		selected = append(selected, c.rel)
	}

	sort.Strings(selected)
	return selected
}

func shouldSkipRulePath(lowRel string) bool {
	base := filepath.Base(lowRel)
	if strings.HasPrefix(base, "._") || strings.Contains(lowRel, "__macosx/") {
		return true
	}
	if strings.Contains(lowRel, "/android/") || strings.HasPrefix(lowRel, "android/") {
		return true
	}
	// Mega index / wrapper files re-include trees and create nested duplicates.
	if base == "index.yar" || base == "index.yara" || base == "all.yar" {
		return true
	}
	if strings.HasSuffix(base, "_index.yar") || strings.HasSuffix(base, "_index.yara") {
		return true
	}
	return false
}

func pathPreferScore(rel string) int {
	rel = strings.ReplaceAll(rel, "\\", "/")
	low := strings.ToLower(rel)
	score := strings.Count(low, "/") * 10
	if strings.Contains(low, "rules-master/") {
		score += 80
	}
	if strings.Contains(low, "deprecated/") {
		score += 40
	}
	if strings.Contains(low, "mobile_malware/") {
		score += 30
	}
	return score
}

func extractYaraRuleNames(src string) []string {
	matches := reYaraRuleName.FindAllStringSubmatch(src, -1)
	out := make([]string, 0, len(matches))
	seen := map[string]bool{}
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		name := m[1]
		key := strings.ToLower(name)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, name)
	}
	return out
}

func extractYaraImports(src string) []string {
	matches := reYaraImport.FindAllStringSubmatch(src, -1)
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		if len(m) >= 2 {
			out = append(out, strings.ToLower(strings.TrimSpace(m[1])))
		}
	}
	return out
}

func unsupportedImportReason(imports []string) string {
	for _, imp := range imports {
		if unsupportedYaraModules[imp] {
			return "import:" + imp
		}
	}
	return ""
}

func writeInsiteAll(destRoot string, includes []string) (string, error) {
	var b strings.Builder
	for _, rel := range includes {
		b.WriteString("include \"")
		b.WriteString(strings.ReplaceAll(rel, `\`, `/`))
		b.WriteString("\"\n")
	}
	allPath := filepath.Join(destRoot, "_insite_all.yar")
	if err := os.WriteFile(allPath, []byte(b.String()), 0o600); err != nil {
		return "", err
	}
	return allPath, nil
}

// pruneFailingIncludes repeatedly drops files that make yara64 fail to compile.
func pruneFailingIncludes(destRoot, yaraExe string, includes []string) []string {
	if strings.TrimSpace(yaraExe) == "" {
		return includes
	}
	if _, err := os.Stat(yaraExe); err != nil {
		return includes
	}
	if len(includes) == 0 {
		return includes
	}

	dummy := filepath.Join(destRoot, "_insite_prune_dummy.bin")
	_ = os.WriteFile(dummy, []byte{0}, 0o600)
	defer os.Remove(dummy)

	selected := append([]string(nil), includes...)
	for round := 0; round < 40; round++ {
		allPath, err := writeInsiteAll(destRoot, selected)
		if err != nil || len(selected) == 0 {
			break
		}
		// Pass only the entrypoint filename; includes are resolved relative to it.
		cmd := exec.Command(yaraExe, filepath.Base(allPath), filepath.Base(dummy))
		cmd.Dir = destRoot
		out, err := cmd.CombinedOutput()
		text := string(out)
		if isYaraCompileClean(err, text) {
			break
		}
		bad := extractFailingRuleFiles(text, destRoot)
		if len(bad) == 0 {
			if len(selected) > 1 && strings.Contains(strings.ToLower(text), "error:") {
				selected = selected[1:]
				continue
			}
			break
		}
		drop := expandBadToTopLevelIncludes(destRoot, selected, bad)
		before := len(selected)
		selected = filterOutRels(selected, drop)
		if len(selected) == before {
			break
		}
	}
	return selected
}

func isYaraCompileClean(err error, text string) bool {
	low := strings.ToLower(text)
	if strings.Contains(low, "error:") {
		return false
	}
	return err == nil
}

func extractFailingRuleFiles(yaraOutput, destRoot string) map[string]bool {
	bad := map[string]bool{}
	destClean := filepath.Clean(destRoot)
	for _, line := range strings.Split(yaraOutput, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(strings.ToLower(line), "error:") {
			continue
		}
		var raw string
		if m := reErrPathPrefixed.FindStringSubmatch(line); len(m) == 2 {
			raw = m[1]
		} else if m := reErrPathInMsg.FindStringSubmatch(line); len(m) == 2 {
			raw = m[1]
		}
		if raw == "" {
			continue
		}
		raw = strings.Trim(raw, `"'`)
		rel := normalizeToDestRel(raw, destClean)
		if rel != "" {
			bad[strings.ToLower(rel)] = true
		}
	}
	return bad
}

func normalizeToDestRel(pathOrRel, destClean string) string {
	p := strings.TrimSpace(pathOrRel)
	p = strings.ReplaceAll(p, "\\", "/")
	for strings.Contains(p, "/./") {
		p = strings.ReplaceAll(p, "/./", "/")
	}
	p = strings.TrimPrefix(p, "./")
	destSlash := strings.ReplaceAll(filepath.Clean(destClean), "\\", "/")
	lowP := strings.ToLower(p)
	lowDest := strings.ToLower(destSlash)
	if i := strings.Index(lowP, lowDest); i >= 0 {
		rel := p[i+len(destSlash):]
		rel = strings.TrimPrefix(rel, "/")
		return normalizeRel(rel)
	}
	abs := filepath.Clean(filepath.FromSlash(p))
	if rel, err := filepath.Rel(filepath.Clean(destClean), abs); err == nil && rel != "" && !strings.HasPrefix(rel, "..") {
		return normalizeRel(rel)
	}
	return normalizeRel(p)
}

func filterOutRels(includes []string, bad map[string]bool) []string {
	out := make([]string, 0, len(includes))
	for _, rel := range includes {
		if bad[strings.ToLower(normalizeRel(rel))] {
			continue
		}
		out = append(out, rel)
	}
	return out
}

// expandBadToTopLevelIncludes maps nested compile-error paths back to the
// top-level include entries that pull them in (direct path, same basename,
// folder wrapper like capabilities.yar -> capabilities/*, or textual include).
func expandBadToTopLevelIncludes(destRoot string, includes []string, bad map[string]bool) map[string]bool {
	drop := make(map[string]bool, len(bad)+len(includes))
	for b := range bad {
		drop[strings.ToLower(normalizeRel(b))] = true
	}
	for b := range bad {
		b = strings.ToLower(normalizeRel(b))
		base := strings.ToLower(filepath.Base(b))
		dir := strings.ToLower(filepath.ToSlash(filepath.Dir(b)))
		for _, rel := range includes {
			low := strings.ToLower(normalizeRel(rel))
			if drop[low] {
				continue
			}
			relBase := strings.ToLower(filepath.Base(rel))
			relDir := strings.ToLower(filepath.ToSlash(filepath.Dir(rel)))
			relStem := strings.TrimSuffix(relBase, filepath.Ext(relBase))

			if low == b || relBase == base {
				drop[low] = true
				continue
			}
			// capabilities.yar wraps capabilities/capabilities.yar
			if dir != "." && dir != "" && relDir == "." && relStem == dir {
				drop[low] = true
				continue
			}
			if dir != "." && dir != "" && (relDir == dir || strings.HasPrefix(low, dir+"/")) {
				drop[low] = true
				continue
			}

			data, err := os.ReadFile(filepath.Join(destRoot, filepath.FromSlash(rel)))
			if err != nil {
				continue
			}
			lowData := strings.ToLower(string(data))
			if strings.Contains(lowData, b) || strings.Contains(lowData, strings.ToLower(filepath.Base(b))) {
				drop[low] = true
			}
		}
	}
	return drop
}

func resolveBundledYara(baseDataDir string) string {
	candidates := []string{
		filepath.Join(baseDataDir, "yara64.exe"),
		filepath.Join(baseDataDir, "Engine", "Yara", "yara64.exe"),
		filepath.Join(filepath.Dir(baseDataDir), "Engine", "Yara", "yara64.exe"),
		`C:\ProgramData\SOSECURE Threat inSight\yara64.exe`,
		`C:\ProgramData\SOSECURE Threat inSight\Engine\Yara\yara64.exe`,
	}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

// MaterializeStats is filled during Materialize for diagnostics.
type MaterializeStats struct {
	StoredFiles   int
	SelectedFiles int
	PrunedFiles   int
	Duration      time.Duration
}

func (s MaterializeStats) String() string {
	return fmt.Sprintf("stored=%d selected=%d pruned=%d in %s", s.StoredFiles, s.SelectedFiles, s.PrunedFiles, s.Duration.Round(time.Millisecond))
}
