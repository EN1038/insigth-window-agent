package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/sosecure/insite-agent/internal/config"
	"github.com/sosecure/insite-agent/internal/rules"
	"github.com/sosecure/insite-agent/internal/ssdeepscan"
)

func main() {
	baseDir := config.DataBaseDir()

	fmt.Println("==================================================")
	fmt.Printf(" Data Dir Path: %s\n", baseDir)
	fmt.Println("==================================================")

	// 1. Check YARA Rules Store
	rStore := rules.New(baseDir)
	rIdx, errR := rStore.LoadIndex()

	blobsDir := filepath.Join(baseDir, "Data", "rules", "blobs")
	blobFiles, _ := os.ReadDir(blobsDir)

	fmt.Println("[1] YARA Rules Store (Data\\rules):")
	if errR != nil {
		fmt.Printf("    [!] Error loading YARA index: %v\n", errR)
	} else if rIdx == nil {
		fmt.Println("    [!] YARA Index is nil")
	} else {
		fmt.Printf("    [+] Total Registered Rule Items in Index: %d records\n", len(rIdx.Files))
		fmt.Printf("    [+] Total Physical Encrypted Blob Files (.blobenc): %d files\n", len(blobFiles))
		fmt.Printf("    [+] Index Version: %s, Updated At: %s\n", rIdx.Version, rIdx.UpdatedAt)
	}

	fmt.Println("\n--------------------------------------------------")

	// 2. Check SSDEEP Store
	sStore := ssdeepscan.NewStore(baseDir)
	sIdx, errS := sStore.LoadIndex()

	shardsDir := filepath.Join(baseDir, "Data", "ssdeep", "shards")
	shardFiles, _ := os.ReadDir(shardsDir)

	fmt.Println("[2] SSDEEP Signatures Store (Data\\ssdeep):")
	if errS != nil {
		fmt.Printf("    [!] Error loading SSDEEP index: %v\n", errS)
	} else if sIdx == nil {
		fmt.Println("    [!] SSDEEP Index is nil")
	} else {
		fmt.Printf("    [+] Total Malware Signatures in Index: %d signatures\n", sIdx.Total)
		fmt.Printf("    [+] Total Block Size Groups (Shards): %d shards\n", len(sIdx.Blocks))
		fmt.Printf("    [+] Total Physical Encrypted Shard Files (.shardenc): %d files\n", len(shardFiles))
		fmt.Printf("    [+] Index Version: %d, Updated At: %s\n", sIdx.Version, sIdx.UpdatedAt)

		fmt.Println("\n    [Breakdown of SSDEEP Signatures by Block Size]:")
		for bs, count := range sIdx.Blocks {
			fmt.Printf("      - Block Size %6s : %7d signatures\n", bs, count)
		}
	}

	fmt.Println("==================================================")
}
