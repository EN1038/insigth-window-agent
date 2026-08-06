package main

import (
	"fmt"

	"github.com/sosecure/insite-agent/internal/api"
	"github.com/sosecure/insite-agent/internal/config"
	"github.com/sosecure/insite-agent/internal/history"
	"github.com/sosecure/insite-agent/internal/rules"
	"github.com/sosecure/insite-agent/internal/runtime"
	"github.com/sosecure/insite-agent/internal/settings"
	"github.com/sosecure/insite-agent/internal/ssdeepscan"
)

func main() {
	baseDir := config.DataBaseDir()
	cfg, err := config.Load(baseDir)
	if err != nil {
		fmt.Printf("Config load error: %v\n", err)
		return
	}

	st := settings.New(baseDir)
	_ = st.Load()

	hist := history.New(baseDir)
	client := api.New(cfg)

	r := &runtime.Runner{
		BaseDir:  baseDir,
		Config:   cfg,
		Settings: st,
		History:  hist,
		API:      client,
	}

	fmt.Println("==================================================")
	fmt.Println("  Running Full YARA & SSDEEP Rules Sync from Center")
	fmt.Println("==================================================")

	// Execute full YARA rules sync
	nRules := r.SyncRulesNow()
	fmt.Printf("[+] YARA Rules Sync Complete! Downloaded & Imported: %d rule items\n", nRules)

	// Execute full SSDEEP signatures sync
	nSsdeep := r.SyncSsdeepNow()
	fmt.Printf("[+] SSDEEP Signatures Sync Complete! Downloaded & Imported: %d items\n", nSsdeep)

	// Inspect store index
	rStore := rules.New(baseDir)
	rIdx, _ := rStore.LoadIndex()
	fmt.Printf("[+] Current Encrypted YARA Store Index: %d rules records registered\n", len(rIdx.Files))

	sStore := ssdeepscan.NewStore(baseDir)
	sIdx, _ := sStore.LoadIndex()
	fmt.Printf("[+] Current Encrypted SSDEEP Store Index Version: %s\n", sIdx.Version)

	fmt.Println("==================================================")
}
