//go:build !windows

package commands

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/michael-ltm/sshm/internal/cloudsync"
	"github.com/michael-ltm/sshm/internal/config"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	gssh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestCloudAgentPreloadsAfterUnlockAndFreshSync(t *testing.T) {
	for _, fresh := range []bool{false, true} {
		t.Run(map[bool]string{false: "local-unlock-before-auth-failure", true: "fresh-sync"}[fresh], func(t *testing.T) {
			dir, err := os.MkdirTemp("", "sshm-ca-")
			require.NoError(t, err)
			t.Cleanup(func() { _ = os.RemoveAll(dir) })
			listener, err := net.Listen("unix", filepath.Join(dir, "a"))
			require.NoError(t, err)
			t.Cleanup(func() { _ = listener.Close() })
			ring := agent.NewKeyring()
			go func() {
				for {
					c, err := listener.Accept()
					if err != nil {
						return
					}
					go func() { defer c.Close(); _ = agent.ServeAgent(ring, c) }()
				}
			}()
			t.Setenv("SSH_AUTH_SOCK", filepath.Join(dir, "a"))
			oldConfig := flagConfigPath
			flagConfigPath = filepath.Join(dir, "config.toml")
			t.Cleanup(func() { flagConfigPath = oldConfig })
			_, raw, err := ed25519.GenerateKey(rand.Reader)
			require.NoError(t, err)
			block, err := gssh.MarshalPrivateKey(raw, "fixture")
			require.NoError(t, err)
			signer, err := gssh.NewSignerFromKey(raw)
			require.NoError(t, err)
			v, _, err := cloudsync.NewVault("agent-fixture", []byte("fixture-unlock"))
			require.NoError(t, err)
			defer v.Close()
			entry := cloudsync.Entry{ID: "entry-fixture", Aliases: []string{"fixture"}, Server: config.Server{Host: "fixture.invalid", Port: 22, User: "deploy", Auth: config.AuthKey}, CredentialIDs: []string{"credential-fixture"}}
			installKey := func() {
				v.Data.Entries[entry.ID] = entry
				v.Data.Credentials["credential-fixture"] = cloudsync.Credential{Kind: "key", Key: pem.EncodeToMemory(block), Fingerprint: gssh.FingerprintSHA256(signer.PublicKey())}
			}
			if !fresh {
				installKey()
			}
			base, err := v.Snapshot(0, cloudsync.RandomID())
			require.NoError(t, err)
			base.Revision = 1
			remote := base
			if fresh {
				installKey()
				remote, err = v.Snapshot(1, cloudsync.RandomID())
				require.NoError(t, err)
				remote.Revision = 2
				v.Data.Close()
				v.Data = cloudsync.NewData()
			}
			endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/v1/heartbeat":
					if fresh {
						w.WriteHeader(204)
					} else {
						w.WriteHeader(401)
					}
				case r.URL.Path == "/v1/vault" && r.Method == "GET":
					_ = json.NewEncoder(w).Encode(remote)
				case r.URL.Path == "/v1/vault" && r.Method == "PUT":
					var snapshot cloudsync.Snapshot
					if json.NewDecoder(r.Body).Decode(&snapshot) != nil {
						w.WriteHeader(400)
						return
					}
					snapshot.Revision = snapshot.BaseRevision + 1
					_ = json.NewEncoder(w).Encode(snapshot)
				case r.URL.Path == "/v1/jobs/poll":
					w.WriteHeader(401)
				default:
					w.WriteHeader(204)
				}
			}))
			defer endpoint.Close()
			state := &cloudsync.State{URL: endpoint.URL, Username: "agent-fixture", DeviceID: "device-fixture", Token: "fixture-token", Base: base, Draft: base}
			require.NoError(t, state.Save(cloudsync.StatePath(configPath())))
			target := entry.Server
			target.Auth, target.CloudEntry, target.CloudVault = config.AuthCloud, entry.ID, cloudsync.InventoryIdentity(state)
			cfg := config.New()
			cfg.Servers["fixture"] = &target
			require.NoError(t, config.Save(configPath(), cfg))
			cmd := &cobra.Command{}
			var output bytes.Buffer
			cmd.SetOut(&output)
			cmd.SetErr(&output)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			err = runCloudAgent(ctx, cmd, state, v, false)
			var api *cloudsync.APIError
			require.ErrorAs(t, err, &api)
			require.Equal(t, 401, api.Status)
			sig, err := ring.Sign(signer.PublicKey(), []byte("after-command-exit"))
			require.NoError(t, err)
			require.NoError(t, signer.PublicKey().Verify([]byte("after-command-exit"), sig))
			require.True(t, sshpkg.HasLocalAuth(&target, sshpkg.BuildOpts{ConfigPath: configPath()}))
			require.NotContains(t, output.String(), "PRIVATE KEY")
		})
	}
}
