//go:build !windows

package cloudsync

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/stretchr/testify/require"
	gssh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestHardenConfirmsBackupBeforeReplacingAndRemovingRecovery(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "protected", true: "backup-failed"}[fail], func(t *testing.T) {
			dir, e := os.MkdirTemp("/tmp", "sh-")
			require.NoError(t, e)
			defer os.RemoveAll(dir)
			socket := filepath.Join(dir, "agent")
			listener, e := net.Listen("unix", socket)
			require.NoError(t, e)
			defer listener.Close()
			t.Setenv("SSH_AUTH_SOCK", socket)
			ring := agent.NewKeyring()
			go func() {
				for {
					c, e := listener.Accept()
					if e != nil {
						return
					}
					go func() { defer c.Close(); _ = agent.ServeAgent(ring, c) }()
				}
			}()
			_, private, e := ed25519.GenerateKey(rand.Reader)
			require.NoError(t, e)
			block, e := gssh.MarshalPrivateKey(private, "synthetic")
			require.NoError(t, e)
			original := pem.EncodeToMemory(block)
			key := filepath.Join(dir, "key")
			require.NoError(t, os.WriteFile(key, original, 0600))
			sidecar := []byte("synthetic recovery text\n")
			require.NoError(t, os.WriteFile(key+".passphrase", sidecar, 0600))
			cfg := config.New()
			cfg.Servers["fixture"] = &config.Server{Host: "test.invalid", Port: 22, User: "test", Auth: "key", KeyPath: key}
			v, _, e := NewVault("harden-test", []byte("test-unlock"))
			require.NoError(t, e)
			defer v.Close()
			snap, e := v.Snapshot(0, RandomID())
			require.NoError(t, e)
			snap.Revision = 1
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if fail {
					w.WriteHeader(503)
					return
				}
				if r.Method == "PUT" {
					require.NoError(t, json.NewDecoder(r.Body).Decode(&snap))
					snap.Revision = snap.BaseRevision + 1
				}
				json.NewEncoder(w).Encode(snap)
			}))
			defer server.Close()
			s := &State{URL: server.URL, Username: "harden-test", DeviceID: "test_device", Token: "synthetic", Base: snap, Draft: snap}
			path := filepath.Join(dir, "state.json")
			report, e := s.HardenLocal(context.Background(), v, cfg, path)
			after, _ := os.ReadFile(key)
			if fail {
				require.Error(t, e)
				require.Equal(t, original, after)
				remaining, _ := os.ReadFile(key + ".passphrase")
				require.Equal(t, sidecar, remaining)
				return
			}
			require.NoError(t, e)
			require.Equal(t, 1, report.Encrypted)
			require.Equal(t, 1, report.RecoveryRemoved)
			require.Equal(t, 1, report.AgentLoaded)
			_, e = gssh.ParseRawPrivateKey(after)
			require.Error(t, e)
			_, e = os.Stat(key + ".passphrase")
			require.True(t, os.IsNotExist(e))
			backup, e := UnlockMaster("harden-test", snap, v.Master)
			require.NoError(t, e)
			defer backup.Close()
			foundOriginal, foundSidecar, foundReplacement := false, false, false
			for _, c := range backup.Data.Credentials {
				if string(c.Key) == string(original) {
					foundOriginal = true
				}
				if c.Password == string(sidecar) {
					foundSidecar = true
				}
				if string(c.Key) == string(after) {
					raw, e := gssh.ParseRawPrivateKeyWithPassphrase(c.Key, c.Passphrase)
					require.NoError(t, e)
					signer, e := gssh.NewSignerFromKey(raw)
					require.NoError(t, e)
					require.Equal(t, gssh.FingerprintSHA256(signer.PublicKey()), c.Fingerprint)
					foundReplacement = true
				}
			}
			require.True(t, foundOriginal && foundSidecar && foundReplacement)
			pub, e := os.ReadFile(key + ".pub")
			require.NoError(t, e)
			public, _, _, _, e := gssh.ParseAuthorizedKey(pub)
			require.NoError(t, e)
			sig, e := ring.Sign(public, []byte("proof"))
			require.NoError(t, e)
			require.NoError(t, public.Verify([]byte("proof"), sig))
		})
	}
}
