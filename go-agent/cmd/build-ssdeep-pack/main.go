// Command build-ssdeep-pack creates a readable ssdeep JSON+ZIP pack from sample files.
//
// Usage:
//
//	go run ./cmd/build-ssdeep-pack -in samples/webshells -category webshells -out ./out
//
// Naming:
//
//	pack file:  ssdeep_<category>_<YYYYMMDD>.zip
//	version:    <category>-<YYYY.MM.DD>
//	signature:  <Category>.<Stem>  (+ optional family from parent folder)
package main

import (
	"archive/zip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/sosecure/insite-agent/internal/ssdeepscan"
)

type sigRow struct {
	Name   string `json:"name"`
	Family string `json:"family,omitempty"`
	Ssdeep string `json:"ssdeep"`
}

func main() {
	inDir := flag.String("in", "", "input directory of sample files (or samples/<category>/…)")
	category := flag.String("category", "", "pack category: webshells|malware|ransomware|trojan|mixed|other")
	title := flag.String("title", "", "human title for Center upload (optional)")
	outDir := flag.String("out", ".", "output directory for json/zip")
	date := flag.String("date", time.Now().Format("20060102"), "pack date YYYYMMDD")
	flag.Parse()

	if strings.TrimSpace(*inDir) == "" {
		fatal("missing -in directory")
	}
	cat := normalizeCategory(*category)
	if cat == "" {
		// Infer from last path segment when -in is …/samples/webshells
		cat = normalizeCategory(filepath.Base(filepath.Clean(*inDir)))
	}
	if cat == "" {
		fatal("missing -category (or use -in …/<category>)")
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fatal(err.Error())
	}

	rows, skipped, err := collect(*inDir, cat)
	if err != nil {
		fatal(err.Error())
	}
	if len(rows) == 0 {
		fatal(fmt.Sprintf("no signatures produced (hashed=0, skipped=%d)", skipped))
	}

	day := *date
	if len(day) != 8 {
		fatal("-date must be YYYYMMDD")
	}
	version := fmt.Sprintf("%s-%s.%s.%s", cat, day[0:4], day[4:6], day[6:8])
	baseName := fmt.Sprintf("ssdeep_%s_%s", cat, day)
	jsonPath := filepath.Join(*outDir, baseName+".json")
	zipPath := filepath.Join(*outDir, baseName+".zip")

	b, err := json.MarshalIndent(rows, "", "  ")
	if err != nil {
		fatal(err.Error())
	}
	if err := os.WriteFile(jsonPath, b, 0o644); err != nil {
		fatal(err.Error())
	}
	if err := zipFile(zipPath, filepath.Base(jsonPath), jsonPath); err != nil {
		fatal(err.Error())
	}

	humanTitle := strings.TrimSpace(*title)
	if humanTitle == "" {
		humanTitle = fmt.Sprintf("%s fuzzy hashes %s-%s-%s", categoryLabel(cat), day[0:4], day[4:6], day[6:8])
	}

	fmt.Printf("signatures: %d (skipped %d)\n", len(rows), skipped)
	fmt.Printf("json:       %s\n", jsonPath)
	fmt.Printf("zip:        %s\n", zipPath)
	fmt.Println()
	fmt.Println("Center upload fields:")
	fmt.Printf("  Category:    %s\n", cat)
	fmt.Printf("  Title:       %s\n", humanTitle)
	fmt.Printf("  Version:     %s\n", version)
	fmt.Printf("  Pack file:   %s\n", filepath.Base(zipPath))
	fmt.Printf("  Description: Built from %s (%d signatures)\n", *inDir, len(rows))
}

func collect(root, category string) ([]sigRow, int, error) {
	var rows []sigRow
	skipped := 0
	catLabel := categoryLabel(category)
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		// Skip obvious non-samples
		name := info.Name()
		if strings.HasPrefix(name, ".") {
			skipped++
			return nil
		}
		hash := ssdeepscan.FuzzyHashFile(path)
		if hash == "" {
			skipped++
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		family := familyFromRel(rel)
		stem := sanitizeToken(strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)))
		if stem == "" {
			stem = "sample"
		}
		sigName := catLabel + "." + stem
		if family != "" && !strings.EqualFold(family, stem) {
			sigName = catLabel + "." + family + "." + stem
		}
		rows = append(rows, sigRow{
			Name:   sigName,
			Family: family,
			Ssdeep: hash,
		})
		return nil
	})
	return rows, skipped, err
}

func familyFromRel(rel string) string {
	rel = filepath.ToSlash(rel)
	parts := strings.Split(rel, "/")
	if len(parts) < 2 {
		return ""
	}
	return sanitizeToken(parts[0])
}

func categoryLabel(cat string) string {
	switch cat {
	case "webshells":
		return "Webshell"
	case "ransomware":
		return "Ransomware"
	case "trojan":
		return "Trojan"
	case "malware":
		return "Malware"
	case "mixed":
		return "Mixed"
	default:
		if cat == "" {
			return "Other"
		}
		r := []rune(cat)
		r[0] = unicode.ToUpper(r[0])
		return string(r)
	}
}

var nonToken = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func sanitizeToken(s string) string {
	s = strings.TrimSpace(s)
	s = nonToken.ReplaceAllString(s, "_")
	s = strings.Trim(s, "._-")
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}

func normalizeCategory(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "webshell", "webshells":
		return "webshells"
	case "malware", "ransomware", "trojan", "mixed", "other":
		return s
	default:
		return s
	}
}

func zipFile(zipPath, entryName, srcPath string) error {
	out, err := os.Create(zipPath)
	if err != nil {
		return err
	}
	defer out.Close()
	zw := zip.NewWriter(out)
	defer zw.Close()
	w, err := zw.Create(entryName)
	if err != nil {
		return err
	}
	in, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer in.Close()
	_, err = io.Copy(w, in)
	return err
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "error:", msg)
	os.Exit(1)
}
