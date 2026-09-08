package updater

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSignedManifestAndVersionBoundaries(t *testing.T) {
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, e)
	now := time.Now()
	r := Release{Protocol: 1, Version: "0.8.0-cloud-preview.3", Published: now.Unix(), Expires: now.Add(time.Hour).Unix(), Assets: []Asset{{OS: "darwin", Arch: "arm64", URL: "https://sshm.yunmini.net/downloads/sshm-darwin-arm64", Size: 1, SHA256: hex.EncodeToString(make([]byte, 32))}}}
	p, e := json.Marshal(r)
	require.NoError(t, e)
	s := Signed{Payload: string(p), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, p))}
	b, _ := json.Marshal(s)
	key := base64.RawURLEncoding.EncodeToString(pub)
	_, e = Verify(b, key, now)
	require.NoError(t, e)
	s.Payload += " "
	bad, _ := json.Marshal(s)
	_, e = Verify(bad, key, now)
	require.Error(t, e)
	_, e = Verify(b, key, now.Add(2*time.Hour))
	require.Error(t, e)
	for _, pair := range [][2]string{{"0.8.0-cloud-preview.10", "0.8.0-cloud-preview.3"}, {"0.8.0", "0.8.0-cloud-preview.10"}, {"0.8.0-cloud-preview.3", "0.7.0+old"}} {
		n, e := Compare(pair[0], pair[1])
		require.NoError(t, e)
		require.Greater(t, n, 0)
	}
	n, e := Compare("0.8.0+one", "0.8.0+two")
	require.NoError(t, e)
	require.Zero(t, n)
}
func TestCorruptDownloadAndFailedActivationPreserveOldBinary(t *testing.T) {
	body := []byte("synthetic executable")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(body) }))
	defer server.Close()
	dir := t.TempDir()
	target := filepath.Join(dir, "sshm")
	require.NoError(t, os.WriteFile(target, []byte("old binary"), 0700))
	h := sha256.Sum256(body)
	asset := Asset{URL: server.URL, Size: int64(len(body)), SHA256: hex.EncodeToString(h[:])}
	bad := asset
	bad.SHA256 = hex.EncodeToString(make([]byte, 32))
	_, e := Download(context.Background(), bad, dir)
	require.Error(t, e)
	before, _ := os.ReadFile(target)
	require.Equal(t, "old binary", string(before))
	_, e = Replace(target, filepath.Join(dir, "missing"))
	require.Error(t, e)
	before, _ = os.ReadFile(target)
	require.Equal(t, "old binary", string(before))
	stage, e := Download(context.Background(), asset, dir)
	require.NoError(t, e)
	backup, e := Replace(target, stage)
	require.NoError(t, e)
	after, _ := os.ReadFile(target)
	require.Equal(t, body, after)
	old, _ := os.ReadFile(backup)
	require.Equal(t, "old binary", string(old))
}
