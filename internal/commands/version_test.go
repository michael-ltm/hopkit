package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller could not locate version_test.go")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
}

func readJSONFile(t *testing.T, path string, dst any) {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(contents, dst); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
}

func TestDeclaredVersionsMatch(t *testing.T) {
	const want = "0.6.0"
	root := repositoryRoot(t)

	var pluginManifest struct {
		Version string `json:"version"`
	}
	readJSONFile(t, filepath.Join(root, "plugins", "sshm-skill", ".claude-plugin", "plugin.json"), &pluginManifest)

	var marketplace struct {
		Version string `json:"version"`
		Plugins []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"plugins"`
	}
	readJSONFile(t, filepath.Join(root, ".claude-plugin", "marketplace.json"), &marketplace)

	marketplacePluginVersion := ""
	for _, plugin := range marketplace.Plugins {
		if plugin.Name == "sshm-skill" {
			marketplacePluginVersion = plugin.Version
			break
		}
	}

	for name, got := range map[string]string{
		"source Version":             Version,
		"plugin manifest version":    pluginManifest.Version,
		"marketplace version":        marketplace.Version,
		"marketplace plugin version": marketplacePluginVersion,
	} {
		if got != want {
			t.Errorf("%s = %q; want %q", name, got, want)
		}
	}
}
