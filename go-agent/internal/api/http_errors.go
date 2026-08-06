package api

import (
	"fmt"
	"net"
	"strings"
	"unicode"
)

// DecodeHTTPError turns non-JSON / gateway bodies into a short operator-facing message.
func DecodeHTTPError(httpStatus int, raw []byte, cause error) string {
	body := strings.TrimSpace(string(raw))
	low := strings.ToLower(body)
	switch {
	case httpStatus == 502 || strings.Contains(low, "502 bad gateway"):
		return "Center unreachable (502 Bad Gateway). Check Site Client / reverse proxy."
	case httpStatus == 503 || strings.Contains(low, "503 service"):
		return "Center unavailable (503). Try again in a moment."
	case httpStatus == 504 || strings.Contains(low, "504 gateway"):
		return "Center timed out (504 Gateway Timeout)."
	case looksLikeHTML(body):
		return fmt.Sprintf("Center returned an HTML error page (HTTP %d) instead of JSON. Site Client may be down.", httpStatus)
	case body == "":
		return fmt.Sprintf("Empty response from Center (HTTP %d).", httpStatus)
	default:
		snip := compactSnippet(body, 80)
		if cause != nil {
			return fmt.Sprintf("Invalid Center response (HTTP %d: %s).", httpStatus, snip)
		}
		return fmt.Sprintf("Invalid Center response (HTTP %d: %s).", httpStatus, snip)
	}
}

// IsUnreachable reports transport / gateway failures where credentials cannot be verified online.
func IsUnreachable(err error) bool {
	if err == nil {
		return false
	}
	if _, ok := err.(net.Error); ok {
		return true
	}
	s := strings.ToLower(err.Error())
	needles := []string{
		"502", "503", "504",
		"bad gateway", "gateway timeout", "service unavailable",
		"connection refused", "connection reset", "i/o timeout",
		"no such host", "network is unreachable", "tls:",
		"html error page", "center unreachable", "center unavailable", "center timed out",
		"empty response from center", "invalid center response",
		"looking for beginning of value",
	}
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

func looksLikeHTML(s string) bool {
	t := strings.TrimLeftFunc(s, unicode.IsSpace)
	if t == "" {
		return false
	}
	low := strings.ToLower(t)
	return strings.HasPrefix(low, "<!doctype") ||
		strings.HasPrefix(low, "<html") ||
		strings.HasPrefix(low, "<head") ||
		strings.HasPrefix(low, "<title") ||
		strings.Contains(low, "<center><h1>")
}

func compactSnippet(s string, max int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	for strings.Contains(s, "  ") {
		s = strings.ReplaceAll(s, "  ", " ")
	}
	s = strings.TrimSpace(s)
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
