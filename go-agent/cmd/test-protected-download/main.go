package main

import (
	"fmt"
	"os"

	"github.com/sosecure/insite-agent/internal/api"
	"github.com/sosecure/insite-agent/internal/config"
)

func main() {
	baseDir := config.DataBaseDir()
	cfg, err := config.Load(baseDir)
	if err != nil {
		fmt.Printf("Config load error: %v\n", err)
		return
	}

	client := api.New(cfg)

	fmt.Println("==================================================")
	fmt.Println(" Testing DownloadProtectedFile for ssdeep_files/signatures_part001.zip")
	fmt.Println("==================================================")

	tmp := "test_ssdeep.zip"
	err = client.DownloadProtectedFile("ssdeep", "ssdeep_files/signatures_part001.zip", tmp)
	if err != nil {
		fmt.Printf("[!] DownloadProtectedFile error: %v\n", err)
	} else {
		fi, _ := os.Stat(tmp)
		fmt.Printf("[+] SUCCESS! Downloaded signatures_part001.zip size: %d bytes\n", fi.Size())
		_ = os.Remove(tmp)
	}

	fmt.Println("\n==================================================")
	fmt.Println(" Testing DownloadProtectedFile for rule_files/tests.zip")
	fmt.Println("==================================================")
	tmpRule := "test_rule.zip"
	err = client.DownloadProtectedFile("rule", "rule_files/tests.zip", tmpRule)
	if err != nil {
		fmt.Printf("[!] DownloadProtectedFile error: %v\n", err)
	} else {
		fi, _ := os.Stat(tmpRule)
		fmt.Printf("[+] SUCCESS! Downloaded tests.zip size: %d bytes\n", fi.Size())
		_ = os.Remove(tmpRule)
	}
	fmt.Println("==================================================")
}
