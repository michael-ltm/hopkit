package integrations

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	hopkitassets "github.com/michael-ltm/hopkit/plugins/hopkit-skill"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

const marker = ".sshm-managed.json"

const (
	skillName = "hopkit-server-ops"
	// legacySkillName is where releases before the hopkit rename installed the skill.
	legacySkillName = "sshm-server-ops"
)

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

func skillsDir(home, app string) (string, error) {
	switch app {
	case "codex":
		return filepath.Join(home, ".agents", "skills"), nil
	case "claude":
		return filepath.Join(home, ".claude", "skills"), nil
	}
	return "", errors.New("choose codex, claude or all")
}

func Path(home, app string) (string, error) {
	dir, e := skillsDir(home, app)
	if e != nil {
		return "", e
	}
	return filepath.Join(dir, skillName), nil
}

// backupPath keeps replaced skill directories next to, not inside, the skills
// directory: agents load every directory under skills/ as a skill, so a backup
// left there would register a duplicate skill.
func backupPath(skillPath string) (string, error) {
	dir := filepath.Join(filepath.Dir(filepath.Dir(skillPath)), "skill-backups")
	if e := os.MkdirAll(dir, 0700); e != nil {
		return "", e
	}
	return filepath.Join(dir, fmt.Sprintf("%s.backup-%d", filepath.Base(skillPath), time.Now().UnixNano())), nil
}

// readManaged returns the manifest of a managed skill directory whose files
// are all unmodified. ok is false for unmanaged or locally edited skills.
func readManaged(path string) (m Manifest, ok bool, e error) {
	b, e := os.ReadFile(filepath.Join(path, marker))
	if e != nil {
		if os.IsNotExist(e) {
			return m, false, nil
		}
		return m, false, e
	}
	if json.Unmarshal(b, &m) != nil || m.Owner != "sshm-managed-v1" {
		return Manifest{}, false, nil
	}
	for name, expected := range m.Files {
		if !fs.ValidPath(name) {
			return m, false, errors.New("invalid integration manifest")
		}
		b, e := os.ReadFile(filepath.Join(path, filepath.FromSlash(name)))
		if e != nil || hash(b) != expected {
			return m, false, nil
		}
	}
	return m, true, nil
}

// retireLegacy moves an unmodified sshm-era skill out of the skills directory.
func retireLegacy(home, app string) (string, error) {
	dir, e := skillsDir(home, app)
	if e != nil {
		return "", e
	}
	legacy := filepath.Join(dir, legacySkillName)
	if _, e = os.Stat(legacy); os.IsNotExist(e) {
		return "", nil
	}
	if _, ok, e := readManaged(legacy); e != nil {
		return "", e
	} else if !ok {
		return "; legacy " + legacy + " is not managed or was edited, retained", nil
	}
	backup, e := backupPath(legacy)
	if e != nil {
		return "", e
	}
	if e = os.Rename(legacy, backup); e != nil {
		return "", e
	}
	return "; legacy " + legacySkillName + " moved to " + backup, nil
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
	caches := filepath.Join(home, ".codex", "plugins", "cache")
	if app == "claude" {
		caches = filepath.Join(home, ".claude", "plugins", "cache")
	}
	for _, name := range []string{"hopkit", "sshm"} {
		if _, e = os.Stat(filepath.Join(caches, name)); e == nil {
			s.Plugin = true
		}
	}
	return s, nil
}
func hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func Install(home, app, version string, refresh bool) (string, error) {
	status, e := Inspect(home, app)
	if e != nil {
		return "", e
	}
	if status.Plugin && !status.Managed {
		return "plugin-managed installation retained; update the hopkit plugin in the app", nil
	}
	dir, e := skillsDir(home, app)
	if e != nil {
		return "", e
	}
	_, legacyManaged, e := readManaged(filepath.Join(dir, legacySkillName))
	if e != nil {
		return "", e
	}
	if refresh && !status.Managed && !legacyManaged {
		return "not hopkit-managed; skipped", nil
	}
	if status.Exists && !status.Managed {
		return "", errors.New("existing skill is not hopkit-managed; retained without changes")
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
	stage, e := os.MkdirTemp(parent, ".hopkit-skill-")
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
	root := "skills/hopkit-server-ops"
	files, e := fs.ReadDir(hopkitassets.Skills, root)
	if e != nil {
		return "", e
	}
	for _, entry := range files {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		b, e := hopkitassets.Skills.ReadFile(root + "/" + name)
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
		if backup, e = backupPath(status.Path); e != nil {
			return "", e
		}
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
	note, e := retireLegacy(home, app)
	if e != nil {
		return "installed " + status.Path + "; legacy skill cleanup failed: " + e.Error(), nil
	}
	return "installed " + status.Path + note, nil
}
