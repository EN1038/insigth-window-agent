package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sosecure/insite-agent/internal/crypto"
	"github.com/sosecure/insite-agent/internal/keystore"
)

func main() {
	// Prefer cwd = go-agent (module root). Fallback: walk up looking for _crypto-demo.
	cwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	demoDir := filepath.Join(filepath.Dir(cwd), "_crypto-demo")
	if _, err := os.Stat(filepath.Join(demoDir, "rules_clean.yar")); err != nil {
		demoDir = filepath.Join(cwd, "_crypto-demo")
	}
	if _, err := os.Stat(filepath.Join(demoDir, "rules_clean.yar")); err != nil {
		panic(fmt.Errorf("demo YARA not found near %s", cwd))
	}

	src := filepath.Join(demoDir, "rules_clean.yar")
	plain, err := os.ReadFile(src)
	if err != nil {
		panic(err)
	}

	vaultPath := filepath.Join(demoDir, "vault.bin")
	outPath := filepath.Join(demoDir, "rules_clean.blobenc")

	kek, err := keystore.EnsureKEK(vaultPath)
	if err != nil {
		panic(err)
	}
	key, err := crypto.DeriveSubkey(kek, "rules-blob")
	if err != nil {
		panic(err)
	}

	relPath := "rules_clean.yar"
	aad := []byte("rules-blob|v1|" + relPath)
	env, err := crypto.SealAESGCM(key, plain, aad)
	if err != nil {
		panic(err)
	}
	out, err := crypto.Marshal(env)
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(outPath, out, 0o600); err != nil {
		panic(err)
	}

	var pretty map[string]any
	_ = json.Unmarshal(out, &pretty)
	if ct, ok := pretty["ct_b64"].(string); ok && len(ct) > 96 {
		pretty["ct_b64"] = ct[:96] + "...(truncated," + fmt.Sprint(len(ct)) + " chars)"
	}
	prettyBytes, _ := json.MarshalIndent(pretty, "", "  ")

	fmt.Println("=== Plaintext (original YARA) ===")
	fmt.Println(string(plain))
	fmt.Println()
	fmt.Println("=== Encrypted envelope (same as Data/rules/blobs/*.blobenc) ===")
	fmt.Println(string(prettyBytes))
	fmt.Println()
	fmt.Println("Wrote:", outPath)
	fmt.Println("Vault (DPAPI-wrapped KEK only — not printed):", vaultPath)

	env2, err := crypto.Unmarshal(out)
	if err != nil {
		panic(err)
	}
	back, err := crypto.OpenAESGCM(key, env2, aad)
	if err != nil {
		panic(err)
	}
	if string(back) != string(plain) {
		panic("decrypt mismatch")
	}
	fmt.Println("Round-trip decrypt: OK")
}
