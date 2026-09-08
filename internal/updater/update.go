// Package updater authenticates releases before replacing a standalone binary.
package updater

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const FeedURL = "https://sshm.yunmini.net/downloads/release.json"

// Public verification key only. The signing key is kept outside the repository.
const PublicKey = "ihdgSJDRX-pBIH6ORAanzGs4-JwAFNcmYreMXR2R8wU"
const MaxDownload = 64 * 1024 * 1024

type Asset struct {
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}
type Release struct {
	Protocol  int     `json:"protocol"`
	Version   string  `json:"version"`
	Published int64   `json:"published"`
	Expires   int64   `json:"expires"`
	Assets    []Asset `json:"assets"`
}
type Signed struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

var versionRE = regexp.MustCompile(`^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$`)

func Compare(a, b string) (int, error) {
	aa, bb := versionRE.FindStringSubmatch(a), versionRE.FindStringSubmatch(b)
	if aa == nil || bb == nil {
		return 0, errors.New("unrecognized version")
	}
	for i := 1; i <= 3; i++ {
		x, e := strconv.ParseUint(aa[i], 10, 64)
		if e != nil {
			return 0, e
		}
		y, e := strconv.ParseUint(bb[i], 10, 64)
		if e != nil {
			return 0, e
		}
		if x < y {
			return -1, nil
		}
		if x > y {
			return 1, nil
		}
	}
	if aa[4] == bb[4] {
		return 0, nil
	}
	if aa[4] == "" {
		return 1, nil
	}
	if bb[4] == "" {
		return -1, nil
	}
	ap, bp := strings.Split(aa[4], "."), strings.Split(bb[4], ".")
	for i := 0; i < len(ap) && i < len(bp); i++ {
		x, y := ap[i], bp[i]
		if x == y {
			continue
		}
		nx, ex := strconv.ParseUint(x, 10, 64)
		ny, ey := strconv.ParseUint(y, 10, 64)
		if ex == nil && ey == nil {
			if nx < ny {
				return -1, nil
			}
			return 1, nil
		}
		if ex == nil {
			return -1, nil
		}
		if ey == nil {
			return 1, nil
		}
		return strings.Compare(x, y), nil
	}
	if len(ap) < len(bp) {
		return -1, nil
	}
	return 1, nil
}
func Verify(b []byte, public string, now time.Time) (*Release, error) {
	if len(b) > 64*1024 {
		return nil, errors.New("release manifest exceeds limit")
	}
	var signed Signed
	if json.Unmarshal(b, &signed) != nil {
		return nil, errors.New("invalid release manifest")
	}
	key, e := base64.RawURLEncoding.DecodeString(public)
	if e != nil || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("release verification key unavailable")
	}
	sig, e := base64.RawURLEncoding.DecodeString(signed.Signature)
	if e != nil || !ed25519.Verify(key, []byte(signed.Payload), sig) {
		return nil, errors.New("release signature verification failed")
	}
	var r Release
	if json.Unmarshal([]byte(signed.Payload), &r) != nil || r.Protocol != 1 || len(r.Assets) == 0 || len(r.Assets) > 20 {
		return nil, errors.New("invalid release data")
	}
	if _, e := Compare(r.Version, r.Version); e != nil {
		return nil, e
	}
	if r.Published > now.Add(24*time.Hour).Unix() || r.Expires < now.Unix() || r.Expires <= r.Published {
		return nil, errors.New("release metadata expired or clock is incorrect")
	}
	seen := map[string]bool{}
	for _, a := range r.Assets {
		u, e := url.Parse(a.URL)
		digest, e2 := hex.DecodeString(a.SHA256)
		id := a.OS + "/" + a.Arch
		if e != nil || u.Scheme != "https" || u.Host != "sshm.yunmini.net" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !strings.HasPrefix(u.Path, "/downloads/sshm-") || e2 != nil || len(digest) != 32 || a.Size < 1 || a.Size > MaxDownload || seen[id] {
			return nil, errors.New("invalid release asset")
		}
		seen[id] = true
	}
	return &r, nil
}
func client(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return errors.New("update redirects are not allowed") }}
}
func Check(ctx context.Context) (*Release, []byte, error) {
	req, e := http.NewRequestWithContext(ctx, "GET", FeedURL, nil)
	if e != nil {
		return nil, nil, e
	}
	req.Header.Set("User-Agent", "sshm-updater")
	r, e := client(15 * time.Second).Do(req)
	if e != nil {
		return nil, nil, errors.New("could not reach update service")
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return nil, nil, fmt.Errorf("update service returned HTTP %d", r.StatusCode)
	}
	b, e := io.ReadAll(io.LimitReader(r.Body, 64*1024+1))
	if e != nil {
		return nil, nil, e
	}
	release, e := Verify(b, PublicKey, time.Now())
	return release, b, e
}
func (r Release) Asset() (Asset, error) {
	for _, a := range r.Assets {
		if a.OS == runtime.GOOS && a.Arch == runtime.GOARCH {
			return a, nil
		}
	}
	return Asset{}, errors.New("no signed download for this platform")
}
func Download(ctx context.Context, a Asset, directory string) (string, error) {
	f, e := os.CreateTemp(directory, ".sshm-update-*")
	if e != nil {
		return "", e
	}
	path := f.Name()
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(path)
		}
	}()
	req, e := http.NewRequestWithContext(ctx, "GET", a.URL, nil)
	if e != nil {
		return "", e
	}
	req.Header.Set("User-Agent", "sshm-updater")
	r, e := client(3 * time.Minute).Do(req)
	if e != nil {
		return "", errors.New("release download failed")
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return "", fmt.Errorf("download returned HTTP %d", r.StatusCode)
	}
	h := sha256.New()
	n, e := io.Copy(io.MultiWriter(f, h), io.LimitReader(r.Body, a.Size+1))
	if e != nil || n != a.Size || hex.EncodeToString(h.Sum(nil)) != a.SHA256 {
		return "", errors.New("download size or SHA-256 mismatch; existing binary was not changed")
	}
	if e = f.Sync(); e != nil {
		return "", e
	}
	if e = f.Close(); e != nil {
		return "", e
	}
	if e = os.Chmod(path, 0755); e != nil {
		return "", e
	}
	ok = true
	return path, nil
}
func Target() (string, error) {
	p, e := os.Executable()
	if e != nil {
		return "", e
	}
	p, e = filepath.EvalSymlinks(p)
	if e != nil {
		return "", e
	}
	normal := strings.ToLower(filepath.ToSlash(p))
	if strings.Contains(normal, "/cellar/") || strings.Contains(normal, "/scoop/apps/") {
		return "", errors.New("package-manager installation: use brew upgrade or scoop update, or install the standalone cloud client")
	}
	return p, nil
}

// Replace preserves a uniquely named backup and restores it if activation fails.
func Replace(target, staged string) (string, error) {
	if filepath.Dir(target) != filepath.Dir(staged) {
		return "", errors.New("update staging must share the installation directory")
	}
	info, e := os.Lstat(target)
	if e != nil || !info.Mode().IsRegular() {
		return "", errors.New("installation target is not a regular file")
	}
	backup := target + ".backup-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	if e = os.Rename(target, backup); e != nil {
		return "", fmt.Errorf("cannot preserve old binary: %w", e)
	}
	if e = os.Rename(staged, target); e != nil {
		if restore := os.Rename(backup, target); restore != nil {
			return backup, fmt.Errorf("activation and restore failed; backup retained at %s", backup)
		}
		return "", fmt.Errorf("activation failed; old binary restored: %w", e)
	}
	return backup, nil
}
