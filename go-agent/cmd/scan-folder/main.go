// One-shot custom folder scan using the same YARA + ssdeep engines as the agent.
// Does not quarantine, does not call Center APIs, does not use snapshot skip cache.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sosecure/insite-agent/internal/config"
	"github.com/sosecure/insite-agent/internal/rules"
	"github.com/sosecure/insite-agent/internal/scan"
	"github.com/sosecure/insite-agent/internal/settings"
	"github.com/sosecure/insite-agent/internal/ssdeepscan"
)

type hit struct {
	Path   string
	Engine string
	Rule   string
	Score  int
}

func main() {
	target := flag.String("path", "", "folder or file to scan")
	threshold := flag.Int("threshold", 85, "ssdeep similarity threshold")
	mode := flag.String("mode", "both", "both (yara-first, agent default) | yara | ssdeep | dual (independent engines)")
	flag.Parse()
	if strings.TrimSpace(*target) == "" && flag.NArg() > 0 {
		*target = flag.Arg(0)
	}
	if strings.TrimSpace(*target) == "" {
		fmt.Fprintln(os.Stderr, "usage: scan-folder -path <dir> [-mode both|yara|ssdeep|dual]")
		os.Exit(2)
	}
	abs, err := filepath.Abs(*target)
	if err != nil {
		fatal(err)
	}
	st, err := os.Stat(abs)
	if err != nil {
		fatal(err)
	}

	baseDir := config.DataBaseDir()
	fmt.Println("==================================================")
	fmt.Println(" SOSECURE scan-folder (YARA + ssdeep)")
	fmt.Println(" Data:", baseDir)
	fmt.Println(" Target:", abs)
	fmt.Println(" Mode:", *mode)
	fmt.Println("==================================================")

	ruleStore := rules.New(baseDir)
	sStore := ssdeepscan.NewStore(baseDir)
	if rIdx, err := ruleStore.LoadIndex(); err != nil {
		fmt.Printf("[rules] index error: %v\n", err)
	} else if rIdx == nil {
		fmt.Println("[rules] index empty/nil")
	} else {
		fmt.Printf("[rules] index: %d files  ver=%s  updated=%s\n", len(rIdx.Files), rIdx.Version, rIdx.UpdatedAt)
	}
	if sIdx, err := sStore.LoadIndex(); err != nil {
		fmt.Printf("[ssdeep] index error: %v\n", err)
	} else if sIdx == nil {
		fmt.Println("[ssdeep] index empty/nil")
	} else {
		fmt.Printf("[ssdeep] index: %d hashes  shards=%d  ver=%d  updated=%s\n",
			sIdx.Total, len(sIdx.Blocks), sIdx.Version, sIdx.UpdatedAt)
	}

	tempDir, err := os.MkdirTemp("", "insite_rules_*")
	if err != nil {
		fatal(err)
	}
	defer rules.WipeMaterializedDir(tempDir)

	var entries []string
	needYara := *mode == "both" || *mode == "yara" || *mode == "dual"
	needSsdeep := *mode == "both" || *mode == "ssdeep" || *mode == "dual"
	if needYara {
		stats, ent, err := ruleStore.MaterializeWithStats(tempDir)
		if err != nil {
			fatal(fmt.Errorf("rules: %w", err))
		}
		entries = ent
		fmt.Printf("[rules] materialized %d entrypoint(s) (%s)\n", len(entries), stats.String())
	}

	var yaraPath string
	var scanner *scan.Scanner
	if needYara {
		yaraPath = scan.ResolveYaraPath(baseDir, "")
		if _, err := os.Stat(yaraPath); err != nil {
			alt := filepath.Join(baseDir, "Engine", "Yara", "yara64.exe")
			if _, e2 := os.Stat(alt); e2 == nil {
				yaraPath = alt
			} else if _, e3 := os.Stat(filepath.Join(baseDir, "yara64.exe")); e3 == nil {
				yaraPath = filepath.Join(baseDir, "yara64.exe")
			} else {
				fatal(fmt.Errorf("yara64.exe not found (tried %s)", yaraPath))
			}
		}
		fmt.Printf("[yara] engine: %s (fast-scan on)\n", yaraPath)
		scanner = scan.NewScanner(yaraPath)
	}

	var matcher *ssdeepscan.Matcher
	if needSsdeep {
		matcher = ssdeepscan.NewMatcher(baseDir, *threshold)
		if err := matcher.EnsureReady(); err != nil {
			fatal(fmt.Errorf("ssdeep: %w", err))
		}
		fmt.Printf("[ssdeep] ready (threshold=%d)\n", *threshold)
	}

	var files []string
	sizes := map[string]int64{}
	extOK := buildExtFilter()
	collect := func(p string, size int64) {
		ext := strings.ToLower(filepath.Ext(p))
		if !extOK[ext] {
			return
		}
		files = append(files, p)
		sizes[p] = size
	}
	if st.IsDir() {
		_ = filepath.WalkDir(abs, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			info, e := d.Info()
			if e != nil {
				return nil
			}
			collect(p, info.Size())
			return nil
		})
	} else {
		collect(abs, st.Size())
	}
	sort.Strings(files)
	fmt.Printf("[enum] %d eligible file(s)\n", len(files))
	if len(files) == 0 {
		os.Exit(0)
	}

	started := time.Now()
	yaraMap := map[string][]string{}
	ssdeepMap := map[string]ssdeepscan.Match{}

	switch *mode {
	case "yara":
		runYara(scanner, entries, files, yaraMap)
	case "ssdeep":
		runSsdeep(matcher, files, sizes, ssdeepMap)
	case "dual":
		// Independent: every file goes through both engines.
		runYara(scanner, entries, files, yaraMap)
		runSsdeep(matcher, files, sizes, ssdeepMap)
	default: // both = agent default (YARA-first, ssdeep only on misses)
		runYara(scanner, entries, files, yaraMap)
		var clean []string
		for _, f := range files {
			if _, ok := yaraMap[strings.ToLower(f)]; !ok {
				clean = append(clean, f)
			}
		}
		fmt.Printf("[ssdeep] candidates after YARA miss: %d / %d\n", len(clean), len(files))
		runSsdeep(matcher, clean, sizes, ssdeepMap)
	}

	var hits []hit
	for _, f := range files {
		key := strings.ToLower(f)
		yHits := yaraMap[key]
		sHit, sOK := ssdeepMap[key]
		switch *mode {
		case "dual":
			for _, r := range yHits {
				hits = append(hits, hit{Path: f, Engine: "yara", Rule: r})
			}
			if sOK {
				hits = append(hits, hit{
					Path: f, Engine: "ssdeep",
					Rule: ssdeepscan.RuleLabelWithFamily(sHit.Name, sHit.Family, sHit.Score), Score: sHit.Score,
				})
			}
		case "ssdeep":
			if sOK {
				hits = append(hits, hit{
					Path: f, Engine: "ssdeep",
					Rule: ssdeepscan.RuleLabelWithFamily(sHit.Name, sHit.Family, sHit.Score), Score: sHit.Score,
				})
			}
		case "yara":
			for _, r := range yHits {
				hits = append(hits, hit{Path: f, Engine: "yara", Rule: r})
			}
		default: // both: prefer yara, else ssdeep (matches agent)
			if len(yHits) > 0 {
				for _, r := range yHits {
					hits = append(hits, hit{Path: f, Engine: "yara", Rule: r})
				}
			} else if sOK {
				hits = append(hits, hit{
					Path: f, Engine: "ssdeep",
					Rule: ssdeepscan.RuleLabelWithFamily(sHit.Name, sHit.Family, sHit.Score), Score: sHit.Score,
				})
			}
		}
	}

	yaraFiles := 0
	ssdeepFiles := 0
	bothFiles := 0
	seenY := map[string]bool{}
	seenS := map[string]bool{}
	for _, h := range hits {
		k := strings.ToLower(h.Path)
		if h.Engine == "yara" {
			if !seenY[k] {
				yaraFiles++
				seenY[k] = true
			}
		} else {
			if !seenS[k] {
				ssdeepFiles++
				seenS[k] = true
			}
		}
	}
	for k := range seenY {
		if seenS[k] {
			bothFiles++
		}
	}
	infected := 0
	if *mode == "dual" {
		union := map[string]bool{}
		for k := range seenY {
			union[k] = true
		}
		for k := range seenS {
			union[k] = true
		}
		infected = len(union)
	} else {
		infected = yaraFiles + ssdeepFiles
	}
	cleanN := len(files) - infected

	fmt.Println("--------------------------------------------------")
	fmt.Printf(" scanned:  %d\n", len(files))
	fmt.Printf(" infected: %d  (yara-files=%d ssdeep-files=%d overlap=%d)\n", infected, yaraFiles, ssdeepFiles, bothFiles)
	fmt.Printf(" clean:    %d\n", cleanN)
	fmt.Printf(" duration: %s\n", time.Since(started).Round(time.Millisecond))
	fmt.Println("--------------------------------------------------")
	if len(hits) == 0 {
		fmt.Println("(no threats detected)")
		return
	}
	fmt.Printf("%-8s %-6s %s\n", "ENGINE", "SCORE", "RULE / FILE")
	for _, h := range hits {
		rel := h.Path
		if r, err := filepath.Rel(abs, h.Path); err == nil && !strings.HasPrefix(r, "..") {
			rel = r
		} else {
			rel = filepath.Base(h.Path)
		}
		score := "-"
		if h.Engine == "ssdeep" {
			score = fmt.Sprintf("%d", h.Score)
		}
		fmt.Printf("%-8s %-6s %s\n         %s\n", h.Engine, score, h.Rule, rel)
	}
}

func runYara(scanner *scan.Scanner, entries, files []string, yaraMap map[string][]string) {
	fmt.Printf("[yara] scanning %d file(s)…\n", len(files))
	yaraHits, err := scanner.ScanBatch(entries, files)
	if err != nil {
		fatal(fmt.Errorf("yara scan: %w", err))
	}
	for _, m := range yaraHits {
		key := strings.ToLower(m.FilePath)
		yaraMap[key] = append(yaraMap[key], m.Rule)
	}
	fmt.Printf("[yara] matches: %d rule-hits across %d file(s)\n", len(yaraHits), len(yaraMap))
}

func runSsdeep(matcher *ssdeepscan.Matcher, files []string, sizes map[string]int64, ssdeepMap map[string]ssdeepscan.Match) {
	fmt.Printf("[ssdeep] scanning %d file(s)…\n", len(files))
	ssdeepHits, err := matcher.ScanCleanFiles(files, sizes, nil, nil)
	if err != nil {
		fatal(fmt.Errorf("ssdeep scan: %w", err))
	}
	for _, h := range ssdeepHits {
		ssdeepMap[strings.ToLower(h.Path)] = h
	}
	fmt.Printf("[ssdeep] matches: %d file(s)\n", len(ssdeepHits))
}

func buildExtFilter() map[string]bool {
	out := map[string]bool{}
	for _, e := range strings.Split(settings.DefaultScanExtensions, ",") {
		e = strings.ToLower(strings.TrimSpace(e))
		if e != "" {
			out[e] = true
		}
	}
	return out
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "ERROR:", err)
	os.Exit(1)
}
