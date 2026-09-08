package ui

import (
	"os"
	"strings"
)

// ResolveLanguage is local-only: the setting never changes account or vault data.
func ResolveLanguage(value string) string {
	if value == "zh-CN" || value == "en" {
		return value
	}
	for _, key := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if v := os.Getenv(key); v != "" {
			if strings.HasPrefix(strings.ToLower(v), "zh") {
				return "zh-CN"
			}
			return "en"
		}
	}
	return "en"
}
func Text(language, en, zh string) string {
	if ResolveLanguage(language) == "zh-CN" {
		return zh
	}
	return en
}
