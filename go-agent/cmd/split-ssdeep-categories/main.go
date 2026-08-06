// Command split-ssdeep-categories exports the local encrypted ssdeep store,
// splits signatures into readable category packs, and replaces the local store.
//
//	go run ./cmd/split-ssdeep-categories -out ./bin/tools/ssdeep_by_category
package main

import (
	"archive/zip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"github.com/sosecure/insite-agent/internal/config"
	"github.com/sosecure/insite-agent/internal/settings"
	"github.com/sosecure/insite-agent/internal/ssdeepscan"
)

type sigRow struct {
	Name   string `json:"name"`
	Family string `json:"family,omitempty"`
	Ssdeep string `json:"ssdeep"`
}

func main() {
	outDir := flag.String("out", filepath.Join("bin", "tools", "ssdeep_by_category"), "output directory for category packs")
	date := flag.String("date", time.Now().Format("20060102"), "pack date YYYYMMDD")
	dry := flag.Bool("dry-run", false, "split packs only; do not replace local store")
	flag.Parse()

	base := config.DataBaseDir()
	store := ssdeepscan.NewStore(base)
	idx, err := store.LoadIndex()
	if err != nil {
		fatal(err.Error())
	}
	if idx == nil || idx.Total == 0 {
		fatal("local ssdeep store is empty")
	}

	all, err := loadAll(store, idx)
	if err != nil {
		fatal(err.Error())
	}
	fmt.Printf("loaded local signatures: %d\n", len(all))

	byCat := map[string][]sigRow{}
	for _, sig := range all {
		cat := ssdeepscan.CategorizeSignature(sig.Name, sig.Family)
		newName, family := ssdeepscan.RenameForSignature(cat, sig.Name)
		byCat[cat] = append(byCat[cat], sigRow{
			Name:   newName,
			Family: family,
			Ssdeep: sig.Hash,
		})
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fatal(err.Error())
	}

	cats := make([]string, 0, len(byCat))
	for c := range byCat {
		cats = append(cats, c)
	}
	sort.Strings(cats)

	day := *date
	var merged []ssdeepscan.Signature
	for _, cat := range cats {
		rows := byCat[cat]
		fmt.Printf("  %-12s %d\n", cat, len(rows))
		baseName := fmt.Sprintf("ssdeep_%s_%s", cat, day)
		jsonPath := filepath.Join(*outDir, baseName+".json")
		zipPath := filepath.Join(*outDir, baseName+".zip")
		b, _ := json.MarshalIndent(rows, "", "  ")
		if err := os.WriteFile(jsonPath, b, 0o644); err != nil {
			fatal(err.Error())
		}
		if err := zipOne(zipPath, filepath.Base(jsonPath), jsonPath); err != nil {
			fatal(err.Error())
		}
		version := fmt.Sprintf("%s-%s.%s.%s", cat, day[0:4], day[4:6], day[6:8])
		fmt.Printf("    -> %s  (Center: category=%s version=%s title=%s fuzzy hashes)\n",
			filepath.Base(zipPath), cat, version, ssdeepscan.CategoryLabel(cat))
		for _, r := range rows {
			merged = append(merged, ssdeepscan.Signature{Name: r.Name, Family: r.Family, Hash: r.Ssdeep})
		}
	}

	if *dry {
		fmt.Println("dry-run: local store unchanged")
		return
	}

	fmt.Println("replacing local store with categorized signatures…")
	if err := store.Clear(); err != nil {
		fatal(err.Error())
	}
	total, err := store.MergeSignatures(merged)
	if err != nil {
		fatal(err.Error())
	}

	st := settings.New(base)
	_ = st.Load()
	ver := fmt.Sprintf("categorized-%s.%s.%s", day[0:4], day[4:6], day[6:8])
	st.Set(settings.KeySsdeepDBVersion, ver)
	st.Set(settings.KeySsdeepBundledTotal, strconv.Itoa(total))
	_ = st.Save()

	fmt.Printf("DONE local total=%d version=%s\n", total, ver)
	fmt.Println("Upload the zip packs from", *outDir, "to Center (Add Ssdeep Pack) and assign to site.")
	fmt.Println("Then run: php scripts/retire_ssdeep_part_packs.php")
}

func loadAll(store *ssdeepscan.Store, idx *ssdeepscan.Index) ([]ssdeepscan.Signature, error) {
	keys := make([]int, 0, len(idx.Blocks))
	for k := range idx.Blocks {
		n, _ := strconv.Atoi(k)
		keys = append(keys, n)
	}
	sort.Ints(keys)
	var all []ssdeepscan.Signature
	for _, bs := range keys {
		list, err := store.LoadShard(bs)
		if err != nil {
			return nil, err
		}
		all = append(all, list...)
	}
	return all, nil
}

func zipOne(zipPath, entry, src string) error {
	out, err := os.Create(zipPath)
	if err != nil {
		return err
	}
	defer out.Close()
	zw := zip.NewWriter(out)
	defer zw.Close()
	w, err := zw.Create(entry)
	if err != nil {
		return err
	}
	in, err := os.Open(src)
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
