package integrations

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	sshmassets "github.com/michael-ltm/sshm/plugins/sshm-skill"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

const marker = ".sshm-managed.json"

type Manifest struct {
	Owner   string            `json:"owner"`
	Version string            `json:"version"`
	Files   map[string]string `json:"files"`
}
type Status struct {
	App     string `json:"app"`
	Path    string `json:"path"`
	Managed bool   `json:"managed"`
	Plugin  bool   `json:"plugin_managed"`
	Version string `json:"version,omitempty"`
	Exists  bool   `json:"exists"`
}

func Path(home, app string) (string, error) {
	switch app {
	case "codex":
		return filepath.Join(home, ".agents", "skills", "sshm-server-ops"), nil
	case "claude":
		return filepath.Join(home, ".claude", "skills", "sshm-server-ops"), nil
	}
	return "", errors.New("choose codex, claude or all")
}
func Inspect(home, app string) (Status, error) {
	path, e := Path(home, app)
	if e != nil {
		return Status{}, e
	}
	s := Status{App: app, Path: path}
	_, e = os.Stat(path)
	s.Exists = e == nil
	b, e := os.ReadFile(filepath.Join(path, marker))
	var m Manifest
	if e == nil && json.Unmarshal(b, &m) == nil && m.Owner == "sshm-managed-v1" {
		s.Managed = true
		s.Version = m.Version
	}
	cache := filepath.Join(home, ".codex", "plugins", "cache", "sshm")
	if app == "claude" {
		cache = filepath.Join(home, ".claude", "plugins", "cache", "sshm")
	}
	_, e = os.Stat(cache)
	s.Plugin = e == nil
	return s, nil
}
func hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func Install(home, app, version string, refresh bool) (string, error) {
	status, e := Inspect(home, app)
	if e != nil {
		return "", e
	}
	if status.Plugin && !status.Managed {
		return "plugin-managed installation retained; update the SSHM plugin in the app", nil
	}
	if refresh && !status.Managed {
		return "not SSHM-managed; skipped", nil
	}
	if status.Exists && !status.Managed {
		return "", errors.New("existing skill is not SSHM-managed; retained without changes")
	}
	var previous Manifest
	if status.Managed {
		b, e := os.ReadFile(filepath.Join(status.Path, marker))
		if e != nil {
			return "", e
		}
		if e = json.Unmarshal(b, &previous); e != nil {
			return "", e
		}
		for name, expected := range previous.Files {
			if !fs.ValidPath(name) {
				return "", errors.New("invalid integration manifest")
			}
			b, e := os.ReadFile(filepath.Join(status.Path, filepath.FromSlash(name)))
			if e != nil || hash(b) != expected {
				return "", fmt.Errorf("locally edited skill file retained: %s", name)
			}
		}
	}
	parent := filepath.Dir(status.Path)
	if e = os.MkdirAll(parent, 0700); e != nil {
		return "", e
	}
	stage, e := os.MkdirTemp(parent, ".sshm-skill-")
	if e != nil {
		return "", e
	}
	defer os.RemoveAll(stage)
	if status.Exists {
		if e = os.CopyFS(stage, os.DirFS(status.Path)); e != nil {
			return "", fmt.Errorf("cannot preserve existing skill files: %w", e)
		}
	}
	current := Manifest{Owner: "sshm-managed-v1", Version: version, Files: map[string]string{}}
	root := "skills/sshm-server-ops"
	files, e := fs.ReadDir(sshmassets.Skills, root)
	if e != nil {
		return "", e
	}
	for _, entry := range files {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		b, e := sshmassets.Skills.ReadFile(root + "/" + name)
		if e != nil {
			return "", e
		}
		if e = os.WriteFile(filepath.Join(stage, name), b, 0600); e != nil {
			return "", e
		}
		current.Files[name] = hash(b)
	}
	for name := range previous.Files {
		if _, ok := current.Files[name]; !ok {
			if e = os.Remove(filepath.Join(stage, name)); e != nil {
				return "", e
			}
		}
	}
	b, e := json.MarshalIndent(current, "", "  ")
	if e != nil {
		return "", e
	}
	if e = os.WriteFile(filepath.Join(stage, marker), b, 0600); e != nil {
		return "", e
	}
	backup := ""
	if status.Exists {
		backup = status.Path + fmt.Sprintf(".backup-%d", time.Now().UnixNano())
		if e = os.Rename(status.Path, backup); e != nil {
			return "", e
		}
	}
	if e = os.Rename(stage, status.Path); e != nil {
		if backup != "" {
			_ = os.Rename(backup, status.Path)
		}
		return "", e
	}
	return "installed " + status.Path, nil
}
