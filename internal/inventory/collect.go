// Package inventory collects bounded, read-only hardware observations. It never
// includes serial numbers, machine UUIDs, environment variables or credentials.
package inventory

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

const MaxOutput = 512 * 1024

type Disk struct {
	ID         string   `json:"id"`
	Parent     string   `json:"parent,omitempty"`
	Model      string   `json:"model,omitempty"`
	Kind       string   `json:"kind"`
	Filesystem string   `json:"filesystem,omitempty"`
	Mounts     []string `json:"mounts,omitempty"`
	Total      uint64   `json:"total,omitempty"`
	Free       *uint64  `json:"free,omitempty"`
}
type Snapshot struct {
	AttemptedAt     int64    `json:"attempted_at,omitempty"`
	RefreshFailed   bool     `json:"refresh_failed,omitempty"`
	CheckedAt       int64    `json:"checked_at"`
	Status          string   `json:"status"`
	Platform        string   `json:"platform,omitempty"`
	OS              string   `json:"os,omitempty"`
	Arch            string   `json:"arch,omitempty"`
	CPU             string   `json:"cpu,omitempty"`
	Cores           int      `json:"cores,omitempty"`
	Threads         int      `json:"threads,omitempty"`
	MemoryTotal     uint64   `json:"memory_total,omitempty"`
	MemoryAvailable *uint64  `json:"memory_available,omitempty"`
	Disks           []Disk   `json:"disks,omitempty"`
	Notes           []string `json:"notes,omitempty"`
}

//go:embed linux.sh
var linuxScript string

//go:embed macos.sh
var macScript string

//go:embed windows.ps1
var windowsScript string

func script(platform string) string {
	switch platform {
	case "linux":
		return linuxScript
	case "macos", "darwin":
		return macScript
	case "windows":
		return windowsScript
	}
	return ""
}
func EncodedPowerShell(s string) string {
	words := utf16.Encode([]rune(s))
	raw := make([]byte, len(words)*2)
	for i, v := range words {
		binary.LittleEndian.PutUint16(raw[i*2:], v)
	}
	return base64.StdEncoding.EncodeToString(raw)
}
func Command(platform string) string {
	s := script(platform)
	if s == "" {
		return ""
	}
	if platform == "windows" {
		return "powershell.exe -NoProfile -NonInteractive -EncodedCommand " + EncodedPowerShell(s)
	}
	return "sh -c '" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

// Output rejects oversize output instead of accepting a truncated disk list.
type Output struct{ bytes.Buffer }

func (b *Output) Write(p []byte) (int, error) {
	if b.Len()+len(p) > MaxOutput {
		return 0, errors.New("inventory output too large")
	}
	return b.Buffer.Write(p)
}
func Collect(ctx context.Context) *Snapshot {
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", EncodedPowerShell(windowsScript))
	} else {
		cmd = exec.CommandContext(ctx, "sh", "-c", script(runtime.GOOS))
	}
	var out Output
	cmd.Stdout = &out
	cmd.WaitDelay = 250 * time.Millisecond
	err := cmd.Run()
	return Parse(runtime.GOOS, out.String(), err)
}
func Parse(platform, raw string, runErr error) *Snapshot {
	if platform == "darwin" {
		platform = "macos"
	}
	s := &Snapshot{CheckedAt: time.Now().UnixMilli(), Platform: platform, Status: "unavailable"}
	if runErr != nil || len(raw) > MaxOutput {
		return s
	}
	raw = strings.TrimPrefix(strings.TrimSpace(raw), "\ufeff")
	if platform == "windows" {
		if json.Unmarshal([]byte(raw), s) != nil {
			return &Snapshot{CheckedAt: time.Now().UnixMilli(), Platform: platform, Status: "unavailable"}
		}
		s.CheckedAt = time.Now().UnixMilli()
		s.Platform = platform
	} else {
		sections := map[string]string{}
		key := ""
		for _, line := range strings.Split(raw, "\n") {
			if strings.HasPrefix(line, "SSHM_HW_") {
				key = strings.TrimPrefix(line, "SSHM_HW_")
				continue
			}
			if key != "" {
				sections[key] += line + "\n"
			}
		}
		s.OS = strings.TrimSpace(sections["OS"])
		s.Arch = strings.TrimSpace(sections["ARCH"])
		s.CPU = strings.TrimSpace(sections["CPU"])
		s.Threads = int(number(strings.TrimSpace(sections["THREADS"])))
		s.Cores = int(number(strings.TrimSpace(sections["CORES"])))
		if platform == "linux" {
			parseLinux(s, sections)
		} else if platform == "macos" {
			parseMac(s, sections)
		}
		parseDF(s, sections["DF"])
	}
	if s.OS != "" || s.CPU != "" || s.MemoryTotal > 0 || len(s.Disks) > 0 {
		s.Status = "ok"
		if s.OS == "" || s.CPU == "" || s.MemoryTotal == 0 || len(s.Disks) == 0 || len(s.Notes) > 0 {
			s.Status = "partial"
		}
	}
	if s.MemoryAvailable != nil && *s.MemoryAvailable > s.MemoryTotal {
		s.MemoryAvailable = nil
	}
	if len(s.Disks) > 256 {
		s.Disks = s.Disks[:256]
		s.Notes = append(s.Notes, "disk_limit")
		s.Status = "partial"
	}
	return s
}
func number(v string) uint64 {
	n, _ := strconv.ParseUint(strings.Trim(v, "\" .\r\n\t"), 10, 64)
	return n
}
func pointer(n uint64) *uint64 { return &n }
func (s *Snapshot) Valid() bool {
	if s == nil {
		return true
	}
	if s.AttemptedAt < 0 || s.AttemptedAt > time.Now().Add(24*time.Hour).UnixMilli() || s.CheckedAt < 0 || s.CheckedAt > time.Now().Add(24*time.Hour).UnixMilli() || len(s.Disks) > 256 || len(s.Notes) > 16 || len(s.OS) > 512 || len(s.CPU) > 512 || len(s.Arch) > 64 || s.Cores < 0 || s.Threads < 0 {
		return false
	}
	if s.Status != "ok" && s.Status != "partial" && s.Status != "unavailable" {
		return false
	}
	for _, d := range s.Disks {
		if len(d.ID) > 1024 || len(d.Model) > 512 || len(d.Parent) > 1024 || len(d.Mounts) > 128 || len(d.Kind) > 32 || len(d.Filesystem) > 64 {
			return false
		}
		for _, m := range d.Mounts {
			if len(m) > 4096 {
				return false
			}
		}
	}
	return true
}

// Newer preserves the last successful sample during a failed refresh. The UI
// uses the sample timestamp to make stale data explicit, never calls it live.
func Newer(a, b *Snapshot) *Snapshot {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	at := max(a.CheckedAt, a.AttemptedAt)
	bt := max(b.CheckedAt, b.AttemptedAt)
	if bt <= at {
		return a
	}
	if b.Status == "unavailable" && a.Status != "unavailable" {
		copy := *a
		copy.AttemptedAt = bt
		copy.RefreshFailed = true
		return &copy
	}
	return b
}
