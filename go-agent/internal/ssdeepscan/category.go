package ssdeepscan

import (
	"path/filepath"
	"strings"
)

// Category names used for readable packs / Center metadata.
const (
	CategoryWebshells   = "webshells"
	CategoryMalware     = "malware"
	CategoryRansomware  = "ransomware"
	CategoryTrojan      = "trojan"
	CategoryMixed       = "mixed"
	CategoryOther       = "other"
)

// CategorizeSignature assigns a pack category from name/family/extension heuristics.
// Old local DB entries look like "<sha>.php" or "<sha>.ps1 (c2)".
func CategorizeSignature(name, family string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	f := strings.ToLower(strings.TrimSpace(family))
	blob := n + " " + f

	if strings.Contains(blob, "ransom") || strings.Contains(blob, "lockbit") || strings.Contains(blob, "wannacry") {
		return CategoryRansomware
	}
	if strings.Contains(blob, "(c2)") || strings.Contains(blob, " backdoor") || strings.Contains(blob, "trojan") {
		return CategoryTrojan
	}
	if strings.Contains(blob, "webshell") || strings.Contains(blob, "c99") || strings.Contains(blob, "r57") {
		return CategoryWebshells
	}

	ext := extensionFromName(n)
	switch ext {
	case ".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".phps", ".phar",
		".asp", ".aspx", ".ashx", ".asmx", ".jsp", ".jspx", ".cfm":
		return CategoryWebshells
	case ".exe", ".dll", ".sys", ".scr", ".com", ".msi", ".cpl", ".elf", ".so", ".apk", ".jar":
		return CategoryMalware
	case ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
		".hta", ".sh", ".py", ".pl", ".rb":
		return CategoryMixed
	case ".unknown", "":
		if strings.Contains(blob, "(c2)") {
			return CategoryTrojan
		}
		return CategoryOther
	default:
		return CategoryOther
	}
}

// CategoryLabel returns PascalCase label for signature naming (Webshell, Malware, …).
func CategoryLabel(category string) string {
	switch normalizeCategory(category) {
	case CategoryWebshells:
		return "Webshell"
	case CategoryRansomware:
		return "Ransomware"
	case CategoryTrojan:
		return "Trojan"
	case CategoryMalware:
		return "Malware"
	case CategoryMixed:
		return "Mixed"
	default:
		return "Other"
	}
}

func normalizeCategory(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "webshell", "webshells":
		return CategoryWebshells
	case "malware", "ransomware", "trojan", "mixed", "other":
		return s
	default:
		if s == "" {
			return CategoryOther
		}
		return s
	}
}

func extensionFromName(name string) string {
	// strip trailing " (c2)" style tags
	if i := strings.Index(name, " ("); i > 0 {
		name = name[:i]
	}
	name = strings.TrimSpace(name)
	ext := strings.ToLower(filepath.Ext(name))
	return ext
}

// RenameForCategory builds Category.Stem from an old opaque name.
func RenameForSignature(category, oldName string) (name string, family string) {
	cat := normalizeCategory(category)
	label := CategoryLabel(cat)
	stem := strings.TrimSpace(oldName)
	if i := strings.Index(stem, " ("); i > 0 {
		stem = stem[:i]
	}
	stem = strings.TrimSuffix(stem, filepath.Ext(stem))
	if len(stem) > 48 {
		stem = stem[:48]
	}
	stem = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			return r
		default:
			return '_'
		}
	}, stem)
	stem = strings.Trim(stem, "._-")
	if stem == "" {
		stem = "sample"
	}
	return label + "." + stem, cat
}
