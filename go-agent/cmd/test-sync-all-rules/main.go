package main

import (
	"fmt"

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
	fmt.Println("  1. Testing API.GetRule()")
	fmt.Println("==================================================")
	resp, raw, err := client.GetRule()
	if err != nil {
		fmt.Printf("[!] GetRule error: %v\n", err)
	} else {
		fmt.Printf("[+] Status: %d, Error: '%s'\nRaw: %s\n", resp.StatusCode, resp.Error, string(raw))
	}

	fmt.Println("\n==================================================")
	fmt.Println("  4. Testing API.GetSsdeep()")
	fmt.Println("==================================================")
	resp, raw, err = client.GetSsdeep(cfg.SiteID)
	if err != nil {
		fmt.Printf("[!] GetSsdeep error: %v\n", err)
	} else {
		fmt.Printf("[+] Status: %d, Error: '%s'\nRaw: %s\n", resp.StatusCode, resp.Error, string(raw))
	}

	fmt.Println("\n==================================================")
	fmt.Println("  5. Testing API.DownloadSsdeepSite()")
	fmt.Println("==================================================")
	resp, raw, err = client.DownloadSsdeepSite(cfg.SiteID)
	if err != nil {
		fmt.Printf("[!] DownloadSsdeepSite error: %v\n", err)
	} else {
		fmt.Printf("[+] Status: %d, Error: '%s'\nRaw: %s\n", resp.StatusCode, resp.Error, string(raw))
	}
	fmt.Println("==================================================")
}
