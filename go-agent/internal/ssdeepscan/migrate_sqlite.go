package ssdeepscan

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	_ "modernc.org/sqlite"
)

// ImportFromSQLite is a one-time migration helper from the legacy plaintext
// signatures.db. Runtime scanning does not use SQLite afterward.
func (s *Store) ImportFromSQLite(dbPath string) (int, error) {
	if _, err := os.Stat(dbPath); err != nil {
		return 0, err
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return 0, err
	}
	defer db.Close()

	if err := os.MkdirAll(s.root, 0o700); err != nil {
		return 0, err
	}
	_ = clearDir(filepath.Join(s.root, "shards"))

	bsRows, err := db.Query(`SELECT DISTINCT block_size FROM signatures WHERE block_size > 0`)
	if err != nil {
		return 0, fmt.Errorf("list block sizes: %w", err)
	}
	var blockSizes []int
	for bsRows.Next() {
		var bs int
		if err := bsRows.Scan(&bs); err != nil {
			continue
		}
		blockSizes = append(blockSizes, bs)
	}
	_ = bsRows.Close()

	idx := &Index{Version: 1, Blocks: map[string]int{}}
	total := 0
	stmt, err := db.Prepare(`SELECT malware_name, ssdeep_full FROM signatures WHERE block_size = ?`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	for _, bs := range blockSizes {
		rows, err := stmt.Query(bs)
		if err != nil {
			return 0, err
		}
		var list []Signature
		for rows.Next() {
			var name, hash string
			if err := rows.Scan(&name, &hash); err != nil {
				continue
			}
			hash = stringsTrim(hash)
			name = stringsTrim(name)
			if hash == "" {
				continue
			}
			if name == "" {
				name = "unknown"
			}
			list = append(list, Signature{Name: name, Hash: hash})
		}
		_ = rows.Close()
		if len(list) == 0 {
			continue
		}
		if err := s.SaveShard(bs, list); err != nil {
			return 0, err
		}
		idx.Blocks[strconv.Itoa(bs)] = len(list)
		total += len(list)
	}
	idx.Total = total
	if err := s.SaveIndex(idx); err != nil {
		return 0, err
	}
	return total, nil
}
