package cloudsync

import (
	"errors"
	"fmt"
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/inventory"
	gssh "golang.org/x/crypto/ssh"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
)

var accountPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,63}$`)
var idPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{8,100}$`)

func ValidAccount(s string) bool { return accountPattern.MatchString(s) }
func validID(s string) bool      { return idPattern.MatchString(s) }

type Credential struct {
	Kind        string `json:"kind"`
	Key         []byte `json:"key,omitempty"`
	Passphrase  []byte `json:"passphrase,omitempty"`
	Password    string `json:"password,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}
type Source struct {
	Device string        `json:"device"`
	Alias  string        `json:"alias"`
	Server config.Server `json:"server"`
}
type Entry struct {
	ID            string            `json:"id"`
	Aliases       []string          `json:"aliases"`
	Server        config.Server     `json:"server"`
	CredentialIDs []string          `json:"credentials"`
	Sources       map[string]Source `json:"sources"`
}
type Conflict struct {
	Local  *Entry `json:"local"`
	Remote *Entry `json:"remote"`
}
type Data struct {
	Hardware    map[string]*inventory.Snapshot `json:"hardware,omitempty"`
	Activity    map[string]Activity            `json:"activity,omitempty"`
	Version     int                            `json:"version"`
	Entries     map[string]Entry               `json:"entries"`
	Credentials map[string]Credential          `json:"credentials"`
	Deleted     map[string]bool                `json:"deleted"`
	Conflicts   map[string]Conflict            `json:"conflicts"`
}

func NewData() Data {
	return Data{Hardware: map[string]*inventory.Snapshot{}, Version: 1, Entries: map[string]Entry{}, Credentials: map[string]Credential{}, Activity: map[string]Activity{}, Deleted: map[string]bool{}, Conflicts: map[string]Conflict{}}
}
func (d Data) Validate() error {
	if d.Version != 1 || d.Entries == nil || d.Credentials == nil || d.Deleted == nil || d.Conflicts == nil || len(d.Entries) > 2000 || len(d.Credentials) > 4000 {
		return errors.New("unsupported or invalid vault format")
	}
	if len(d.Activity) > 2000 {
		return errors.New("too many activity records")
	}
	if len(d.Hardware) > 256 {
		return errors.New("too many device observations")
	}
	for id, h := range d.Hardware {
		if !validID(id) || !h.Valid() {
			return errors.New("invalid device hardware")
		}
	}
	for id, a := range d.Activity {
		if !a.Hardware.Valid() {
			return errors.New("invalid server hardware")
		}
		if !validID(id) || a.LastConnected < 0 || a.LastSeen < 0 || a.CheckedAt < 0 || a.SSHCheckedAt < 0 || len(a.SSHError) > 64 || len(a.Status) > 16 || a.SSHMCheckedAt < 0 || len(a.SSHMStatus) > 16 || len(a.SSHMVersion) > 100 {
			return errors.New("invalid activity")
		}
		if _, e := config.NormalizePlatform(a.Platform); e != nil {
			return errors.New("invalid activity platform")
		}
	}
	for id, e := range d.Entries {
		if !validID(id) || id != e.ID || len(e.Aliases) == 0 || len(e.Aliases) > 200 || len(e.CredentialIDs) > 200 || len(e.Sources) > 200 || strings.ContainsAny(e.Server.Host+e.Server.User, "\x00\r\n") || e.Server.Host == "" || e.Server.Port < 1 || e.Server.Port > 65535 {
			return errors.New("invalid vault entry")
		}
		if e.Server.KeyPath != "" {
			return errors.New("device key paths cannot enter vault configuration")
		}
		if strings.TrimSpace(e.Server.User) == "" || (e.Server.Auth != config.AuthKey && e.Server.Auth != config.AuthAgent && e.Server.Auth != config.AuthPassword) {
			return errors.New("invalid vault login identity")
		}
		if err := config.ValidateServerMetadataBounds(e.Server.Label, e.Server.Description, e.Server.Tags, e.Server.Group, e.Server.Notes); err != nil {
			return errors.New("invalid vault metadata")
		}
		for _, alias := range e.Aliases {
			if strings.TrimSpace(alias) == "" || len(alias) > 256 || strings.ContainsAny(alias, "\x00\r\n\x1b") {
				return errors.New("invalid vault alias")
			}
		}
		for _, c := range e.CredentialIDs {
			if _, ok := d.Credentials[c]; !ok {
				return errors.New("missing vault credential")
			}
		}
	}
	for id, c := range d.Credentials {
		if !validID(id) || (c.Kind != "key" && c.Kind != "password") || len(c.Key) > 1024*1024 || len(c.Password) > 65536 || len(c.Passphrase) > 65536 {
			return errors.New("invalid credential shape")
		}
	}
	return nil
}
func (d Data) Close() {
	for _, c := range d.Credentials {
		Wipe(c.Key)
		Wipe(c.Passphrase)
	}
}
func (v *Vault) Close() { Wipe(v.Master); v.Data.Close() }
func cleanServer(s config.Server) config.Server {
	s.CloudEntry = ""
	s.CloudVault = ""
	s.Hardware = nil
	s.KeyPath = ""
	s.CreatedAt = s.CreatedAt.UTC()
	s.LastUsed = config.Server{}.LastUsed
	s.LastSeen = config.Server{}.LastSeen
	s.LastChecked = config.Server{}.LastChecked
	s.LastStatus = ""
	s.LastSSHChecked = config.Server{}.LastSSHChecked
	s.LastSSHError = ""
	s.Platform = ""
	s.SSHMStatus = ""
	s.SSHMVersion = ""
	s.SSHMCheckedAt = config.Server{}.SSHMCheckedAt
	s.IdentityChangedAt = config.Server{}.IdentityChangedAt
	s.CreatedAt = config.Server{}.CreatedAt
	if s.Port == 0 {
		s.Port = 22
	}
	s.Host = strings.ToLower(strings.TrimSpace(s.Host))
	return s
}
func EntryID(s config.Server) string {
	return Digest(struct {
		Host                             string
		Port                             int
		User, Auth, Jump, Command, Proxy string
		Forwards                         []string
	}{s.Host, s.Port, s.User, s.Auth, s.ProxyJump, s.ProxyCommand, s.Proxy, s.Forwards})
}
func union(a, b []string) []string {
	m := map[string]bool{}
	for _, v := range append(append([]string{}, a...), b...) {
		m[v] = true
	}
	out := make([]string, 0, len(m))
	for v := range m {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

type ImportReport struct{ Added, Existing, Keys, LockedKeys, AgentOnly, NeedsPasswords, SkippedDeleted int }

// Import reads only the configured key files. It never reads agent key material.
// Encrypted keys without a recovery sidecar remain encrypted and are reported.
func (d *Data) Import(cfg *config.Config, device string, includeKeys bool) (ImportReport, error) {
	var report ImportReport
	for alias, p := range cfg.Servers {
		if p == nil || p.CloudEntry != "" {
			continue
		}
		s := cleanServer(*p)
		id := EntryID(s)
		if d.Deleted[id] {
			report.SkippedDeleted++
			continue
		}
		e, exists := d.Entries[id]
		if exists {
			report.Existing++
		} else {
			e = Entry{ID: id, Server: s, Sources: map[string]Source{}}
			report.Added++
		}
		e.Aliases = union(e.Aliases, []string{alias})
		if e.Sources == nil {
			e.Sources = map[string]Source{}
		}
		e.Sources[Digest([]string{device, alias})] = Source{Device: device, Alias: alias, Server: s}
		if s.Auth == config.AuthAgent {
			report.AgentOnly++
		}
		if s.Auth == config.AuthPassword {
			report.NeedsPasswords++
		}
		if s.Auth == config.AuthKey && includeKeys {
			path := p.KeyPath
			if strings.HasPrefix(path, "~/") || strings.HasPrefix(path, "~\\") {
				h, err := os.UserHomeDir()
				if err != nil {
					return report, err
				}
				path = filepath.Join(h, path[2:])
			}
			info, err := os.Stat(path)
			if err != nil || info.Size() > 1024*1024 {
				return report, fmt.Errorf("key for alias %q missing or exceeds limit", alias)
			}
			key, err := os.ReadFile(path)
			if err != nil {
				return report, fmt.Errorf("cannot read key for alias %q", alias)
			}
			c := Credential{Kind: "key", Key: key}
			signer, parseErr := gssh.ParsePrivateKey(key)
			if parseErr != nil {
				var missing *gssh.PassphraseMissingError
				if !errors.As(parseErr, &missing) {
					return report, fmt.Errorf("invalid key for alias %q", alias)
				}
				if missing.PublicKey != nil {
					c.Fingerprint = gssh.FingerprintSHA256(missing.PublicKey)
				}
				if st, err := os.Stat(path + ".passphrase"); err == nil && st.Size() < 65536 {
					recovery, err := os.ReadFile(path + ".passphrase")
					if err != nil {
						return report, fmt.Errorf("cannot read recovery file for alias %q", alias)
					}
					for _, line := range strings.Split(string(recovery), "\n") {
						line = strings.TrimSuffix(line, "\r")
						if line != "" && !strings.HasPrefix(line, "#") {
							c.Passphrase = []byte(line)
							break
						}
					}
					Wipe(recovery)
					signer, parseErr = gssh.ParsePrivateKeyWithPassphrase(key, c.Passphrase)
					if parseErr != nil {
						Wipe(c.Passphrase)
						c.Passphrase = nil
					}
				}
				if parseErr != nil {
					report.LockedKeys++
				}
			}
			if signer != nil {
				c.Fingerprint = gssh.FingerprintSHA256(signer.PublicKey())
			}
			cid := Digest(c)
			d.Credentials[cid] = c
			e.CredentialIDs = union(e.CredentialIDs, []string{cid})
			report.Keys++
		}
		d.Entries[id] = e
	}
	d.ImportActivity(cfg)
	return report, d.Validate()
}
func (d *Data) SetPassword(id, password string) error {
	e, ok := d.Entries[id]
	if !ok {
		return errors.New("entry not found")
	}
	if e.Server.Auth != config.AuthPassword {
		return errors.New("selected connection does not use password authentication")
	}
	c := Credential{Kind: "password", Password: password}
	cid := Digest(c)
	d.Credentials[cid] = c
	e.CredentialIDs = []string{cid}
	d.Entries[id] = e
	return nil
}
func (d Data) Find(alias string) (Entry, error) {
	if e, ok := d.Entries[alias]; ok {
		if _, bad := d.Conflicts[alias]; bad {
			return Entry{}, errors.New("resolve the entry conflict before connecting")
		}
		return e, nil
	}
	var found []Entry
	for _, e := range d.Entries {
		for _, a := range e.Aliases {
			if a == alias {
				found = append(found, e)
				break
			}
		}
	}
	if len(found) == 0 {
		return Entry{}, errors.New("cloud entry not found")
	}
	if len(found) > 1 {
		return Entry{}, errors.New("alias has multiple connection variants; use the entry ID from cloud list")
	}
	if _, bad := d.Conflicts[found[0].ID]; bad {
		return Entry{}, errors.New("resolve the entry conflict before connecting")
	}
	return found[0], nil
}
func (d *Data) Remove(id string) {
	delete(d.Entries, id)
	delete(d.Activity, id)
	delete(d.Conflicts, id)
	d.Deleted[id] = true
}
func pointer(d Data, id string) *Entry {
	if e, ok := d.Entries[id]; ok {
		return &e
	}
	return nil
}

// Merge is a three-way merge. Deletions are explicit and conflicting edits are
// retained encrypted on both sides, blocking use until explicitly resolved.
func Merge(base, local, remote Data) (Data, error) {
	out := NewData()
	for _, src := range []Data{remote, local} {
		for id, h := range src.Hardware {
			out.Hardware[id] = inventory.Newer(out.Hardware[id], h)
		}
		for id, a := range src.Activity {
			out.Activity[id] = mergeActivity(out.Activity[id], a)
		}
		for id, c := range src.Credentials {
			if old, ok := out.Credentials[id]; ok && !reflect.DeepEqual(old, c) {
				return out, errors.New("immutable credential conflict")
			}
			c.Key = append([]byte(nil), c.Key...)
			c.Passphrase = append([]byte(nil), c.Passphrase...)
			out.Credentials[id] = c
		}
	}
	// Merge tombstones and resolutions against the common baseline, so an
	// explicit restore/resolution is not undone by an unchanged remote copy.
	allDeleted := map[string]bool{}
	allConflicts := map[string]bool{}
	for _, src := range []Data{base, local, remote} {
		for id := range src.Deleted {
			allDeleted[id] = true
		}
		for id := range src.Conflicts {
			allConflicts[id] = true
		}
	}
	for id := range allDeleted {
		b, l, r := base.Deleted[id], local.Deleted[id], remote.Deleted[id]
		chosen := r
		if l == r || r == b {
			chosen = l
		}
		if chosen {
			out.Deleted[id] = true
		}
	}
	conflictAt := func(d Data, id string) *Conflict {
		if c, ok := d.Conflicts[id]; ok {
			return &c
		}
		return nil
	}
	for id := range allConflicts {
		b, l, r := conflictAt(base, id), conflictAt(local, id), conflictAt(remote, id)
		chosen := r
		if reflect.DeepEqual(l, r) || reflect.DeepEqual(b, r) {
			chosen = l
		}
		if chosen != nil {
			out.Conflicts[id] = *chosen
		}
	}
	ids := map[string]bool{}
	for _, src := range []Data{base, local, remote} {
		for id := range src.Entries {
			ids[id] = true
		}
	}
	for id := range ids {
		b, l, r := pointer(base, id), pointer(local, id), pointer(remote, id)
		var selected *Entry
		switch {
		case reflect.DeepEqual(l, r):
			selected = l
		case reflect.DeepEqual(b, l):
			selected = r
		case reflect.DeepEqual(b, r):
			selected = l
		case compatibleEntries(l, r):
			merged := mergeAdditions(*l, *r)
			selected = &merged
		case b == nil && l != nil && r != nil && EntryID(l.Server) == EntryID(r.Server):
			merged := *r
			merged.Aliases = union(l.Aliases, r.Aliases)
			merged.CredentialIDs = union(l.CredentialIDs, r.CredentialIDs)
			merged.Sources = map[string]Source{}
			for k, v := range r.Sources {
				merged.Sources[k] = v
			}
			for k, v := range l.Sources {
				merged.Sources[k] = v
			}
			selected = &merged
		default:
			out.Conflicts[id] = Conflict{Local: l, Remote: r}
			selected = r
		}
		// An old offline importer cannot resurrect a tombstone without a resolution.
		if out.Deleted[id] && selected != nil {
			out.Conflicts[id] = Conflict{Local: l, Remote: r}
			selected = nil
		}
		if selected != nil {
			out.Entries[id] = *selected
		}
	}
	for id := range out.Activity {
		if _, ok := out.Entries[id]; !ok {
			delete(out.Activity, id)
		}
	}
	out.RepairCompatibleConflicts()
	return out, out.Validate()
}
func (d *Data) Resolve(id, side string) error {
	c, ok := d.Conflicts[id]
	if !ok {
		return errors.New("conflict not found")
	}
	var e *Entry
	switch side {
	case "local":
		e = c.Local
	case "remote":
		e = c.Remote
	default:
		return errors.New("choose local or remote")
	}
	if e == nil {
		d.Remove(id)
	} else {
		d.Entries[id] = *e
		delete(d.Deleted, id)
		delete(d.Conflicts, id)
	}
	return nil
}
