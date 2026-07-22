package main

import (
	"fmt"
	"os"

	"github.com/sosecure/insite-agent/internal/config"
	"github.com/sosecure/insite-agent/internal/ssdeepscan"
)

// One-shot: migrate legacy signatures.db → AES-GCM shards, then wipe SQLite.
func main() {
	base := config.DataBaseDir()
	store := ssdeepscan.NewStore(base)
	src := store.LegacySQLitePath()
	if len(os.Args) > 1 {
		src = os.Args[1]
	}
	fmt.Println("base:", base)
	fmt.Println("from:", src)
	n, err := store.ImportFromSQLite(src)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("imported %d signatures into encrypted shards\n", n)
	if src == store.LegacySQLitePath() {
		if err := os.Remove(src); err != nil {
			fmt.Println("warn: could not remove sqlite:", err)
		} else {
			fmt.Println("removed legacy signatures.db")
		}
	}
}
