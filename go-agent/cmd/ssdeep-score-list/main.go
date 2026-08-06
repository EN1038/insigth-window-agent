// List best ssdeep similarity score for every file in a folder (no threshold cut).
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/glaslos/ssdeep"
	"github.com/sosecure/insite-agent/internal/config"
	"github.com/sosecure/insite-agent/internal/ssdeepscan"
)

type row struct {
	File   string
	Score  int
	Name   string
	Family string
	Hash   string
	Err    string
}

func main() {
	target := `C:\Users\USER\Downloads\test-malware\test-malware`
	if len(os.Args) > 1 {
		target = os.Args[1]
	}
	abs, err := filepath.Abs(target)
	if err != nil {
		fatal(err)
	}

	baseDir := config.DataBaseDir()
	m := ssdeepscan.NewMatcher(baseDir, 1)
	if err := m.EnsureReady(); err != nil {
		fatal(err)
	}
	store := m.Store()
	idx, err := store.LoadIndex()
	if err != nil || idx == nil {
		fatal(fmt.Errorf("ssdeep index: %v", err))
	}

	// Preload all shards once.
	shards := map[int][]ssdeepscan.Signature{}
	for bsStr := range idx.Blocks {
		bs, _ := strconv.Atoi(bsStr)
		if bs <= 0 {
			continue
		}
		list, err := store.LoadShard(bs)
		if err != nil {
			fatal(err)
		}
		shards[bs] = list
	}

	var files []string
	_ = filepath.WalkDir(abs, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		files = append(files, p)
		return nil
	})
	sort.Strings(files)

	fmt.Printf("Target: %s\n", abs)
	fmt.Printf("Signatures: %d  shards: %d\n", idx.Total, len(shards))
	fmt.Println("--------------------------------------------------------------------------------")
	fmt.Printf("%-6s %-42s %-8s %s\n", "SCORE", "FILE", "HIT?", "BEST MATCH")
	fmt.Println("--------------------------------------------------------------------------------")

	var rows []row
	for _, path := range files {
		r := row{File: filepath.Base(path)}
		hash, err := ssdeep.FuzzyFilename(path)
		if err != nil || strings.TrimSpace(hash) == "" {
			if err != nil {
				r.Err = err.Error()
			} else {
				r.Err = "empty hash"
			}
			rows = append(rows, r)
			continue
		}
		r.Hash = hash
		parts := strings.Split(hash, ":")
		if len(parts) < 3 {
			r.Err = "bad hash format"
			rows = append(rows, r)
			continue
		}
		blockSize, err := strconv.Atoi(parts[0])
		if err != nil {
			r.Err = "bad block size"
			rows = append(rows, r)
			continue
		}
		best := -1
		bestName := ""
		bestFamily := ""
		for _, bs := range []int{blockSize / 2, blockSize, blockSize * 2} {
			if bs <= 0 {
				continue
			}
			for _, sig := range shards[bs] {
				score, err := ssdeep.Distance(hash, sig.Hash)
				if err != nil {
					continue
				}
				if score > best {
					best = score
					bestName = sig.Name
					bestFamily = sig.Family
				}
			}
		}
		r.Score = best
		r.Name = bestName
		r.Family = bestFamily
		rows = append(rows, r)
	}

	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Score != rows[j].Score {
			return rows[i].Score > rows[j].Score
		}
		return rows[i].File < rows[j].File
	})

	hitN := 0
	for _, r := range rows {
		hit := ""
		match := "-"
		scoreStr := "-"
		if r.Err != "" {
			match = "ERR: " + r.Err
		} else if r.Score >= 0 {
			scoreStr = fmt.Sprintf("%d", r.Score)
			if r.Score >= 20 {
				hit = "YES"
				hitN++
			} else {
				hit = "no"
			}
			label := r.Name
			if r.Family != "" && !strings.Contains(strings.ToLower(label), strings.ToLower(r.Family)) {
				label = label + "/" + r.Family
			}
			if label == "" {
				label = "(no nearby signature)"
			}
			match = label
		}
		fmt.Printf("%-6s %-42s %-8s %s\n", scoreStr, trunc(r.File, 42), hit, match)
	}
	fmt.Println("--------------------------------------------------------------------------------")
	fmt.Printf("files=%d  hit@>=20=%d  below-threshold=%d\n", len(rows), hitN, len(rows)-hitN)
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "ERROR:", err)
	os.Exit(1)
}
