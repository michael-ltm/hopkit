package cloudsync

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"github.com/michael-ltm/sshm/internal/config"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
	"github.com/stretchr/testify/require"
	gssh "golang.org/x/crypto/ssh"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// Opt-in integration against local workerd or the deployed service. All accounts,
// passwords and key material are synthetic and the account is deleted afterward.
func TestCloudRoundTrip(t *testing.T) {
	endpoint := os.Getenv("SSHM_CLOUD_TEST_ENDPOINT")
	if endpoint == "" {
		t.Skip("set SSHM_CLOUD_TEST_ENDPOINT to exercise a live test service")
	}
	ctx := context.Background()
	user := "test-" + Digest(RandomID())[:15]
	pass := []byte(RandomID()[:6])
	unlock := []byte(RandomID()[:6])
	v, recovery, err := NewVault(user, unlock)
	require.NoError(t, err)
	defer v.Close()
	a, err := Register(ctx, endpoint, user, "test-mac", pass, v, recovery)
	require.NoError(t, err)
	t.Cleanup(func() {
		e := a.Request(ctx, "DELETE", "/v1/account", map[string]string{"password": string(pass)}, nil)
		if e != nil {
			t.Errorf("synthetic account cleanup: %v", e)
		}
	})
	dir := t.TempDir()
	ap := filepath.Join(dir, "a.json")
	require.NoError(t, a.Save(ap))
	_, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	block, err := gssh.MarshalPrivateKey(private, "synthetic-test")
	require.NoError(t, err)
	keypath := filepath.Join(dir, "key")
	require.NoError(t, os.WriteFile(keypath, pem.EncodeToMemory(block), 0600))
	cfg := config.New()
	cfg.Servers["synthetic-key"] = &config.Server{Host: "key.example.invalid", Port: 22, User: "test", Auth: "key", KeyPath: keypath}
	cfg.Servers["synthetic-password"] = &config.Server{Host: "password.example.invalid", Port: 22, User: "test", Auth: "password"}
	_, err = v.Data.Import(cfg, a.DeviceID, true)
	require.NoError(t, err)
	e, err := v.Data.Find("synthetic-password")
	require.NoError(t, err)
	require.NoError(t, v.Data.SetPassword(e.ID, "synthetic-server-password"))
	require.NoError(t, a.SaveDraft(v, ap))
	require.NoError(t, a.Sync(ctx, v, ap))
	require.EqualValues(t, 2, a.Base.Revision)
	b, err := Login(ctx, endpoint, user, "test-windows", pass)
	require.NoError(t, err)
	bv, err := Unlock(user, b.Draft, unlock, false)
	require.NoError(t, err)
	defer bv.Close()
	require.Len(t, bv.Data.Entries, 2)
	require.Len(t, bv.Data.Credentials, 2)
	keyEntry, err := bv.Data.Find("synthetic-key")
	require.NoError(t, err)
	key := bv.Data.Credentials[keyEntry.CredentialIDs[0]]
	signer, err := gssh.ParsePrivateKey(key.Key)
	require.NoError(t, err)
	signature, err := signer.Sign(rand.Reader, []byte("real signing check"))
	require.NoError(t, err)
	require.NoError(t, signer.PublicKey().Verify([]byte("real signing check"), signature))
	pEntry, err := bv.Data.Find("synthetic-password")
	require.NoError(t, err)
	require.Equal(t, "synthetic-server-password", bv.Data.Credentials[pEntry.CredentialIDs[0]].Password)
	verifySSHCredentials(t, signer, bv.Data.Credentials[pEntry.CredentialIDs[0]].Password)
	// Concurrent independent edits from a shared baseline merge without losing either.
	av, err := Unlock(user, a.Draft, unlock, false)
	require.NoError(t, err)
	defer av.Close()
	ae := av.Data.Entries[keyEntry.ID]
	ae.Server.Description = "Mac edit"
	av.Data.Entries[keyEntry.ID] = ae
	require.NoError(t, a.SaveDraft(av, ap))
	require.NoError(t, a.Sync(ctx, av, ap))
	be := bv.Data.Entries[pEntry.ID]
	be.Server.Description = "Windows edit"
	bv.Data.Entries[pEntry.ID] = be
	bp := filepath.Join(dir, "b.json")
	require.NoError(t, b.SaveDraft(bv, bp))
	require.NoError(t, b.Sync(ctx, bv, bp))
	merged, err := Unlock(user, b.Draft, unlock, false)
	require.NoError(t, err)
	defer merged.Close()
	require.Equal(t, "Mac edit", merged.Data.Entries[keyEntry.ID].Server.Description)
	require.Equal(t, "Windows edit", merged.Data.Entries[pEntry.ID].Server.Description)
	// Retry a committed request after a simulated lost response with its original ID.
	committed := b.Draft
	b.Pending = &committed
	b.Dirty = true
	require.NoError(t, b.Save(bp))
	require.NoError(t, b.Sync(ctx, merged, bp))
	require.False(t, b.Dirty)
	other := *a
	other.Username = "another-" + Digest(RandomID())[:12]
	var out Snapshot
	err = other.Request(ctx, "GET", "/v1/vault", nil, &out)
	require.Error(t, err)
	require.NoError(t, a.Request(ctx, "DELETE", "/v1/devices/"+b.DeviceID, nil, nil))
	err = b.Request(ctx, "GET", "/v1/vault", nil, &out)
	require.Error(t, err)
	recovered, err := Unlock(user, a.Draft, []byte(recovery), true)
	require.NoError(t, err)
	recovered.Close()
	// Rotate the vault root, revoke a logged-in device, and prove old unlock
	// material no longer decrypts the current ciphertext.
	oldDevice, err := Login(ctx, endpoint, user, "test-before-rotation", pass)
	require.NoError(t, err)
	require.NoError(t, a.Sync(ctx, av, ap))
	require.Equal(t, "Windows edit", av.Data.Entries[pEntry.ID].Server.Description, "clean pull must refresh the in-memory vault before a subsequent import")
	next, nextRecovery, err := NewVault(user, []byte("synthetic-next-unlock-phrase"))
	require.NoError(t, err)
	defer next.Close()
	next.Data, err = Merge(NewData(), av.Data, av.Data)
	require.NoError(t, err)
	snap, err := next.Snapshot(a.Base.Revision, RandomID())
	require.NoError(t, err)
	auth, err := RecoveryAuth(nextRecovery)
	require.NoError(t, err)
	rotation := map[string]any{"base_revision": snap.BaseRevision, "operation_id": snap.OperationID, "blob": snap.Blob, "signature": snap.Signature, "root_public": snap.RootPublic, "recovery_auth": auth, "authorization": av.RotationAuthorization(snap, auth)}
	require.NoError(t, a.Request(ctx, "PUT", "/v1/rotate", rotation, &out))
	_, err = Unlock(user, out, unlock, false)
	require.Error(t, err)
	rotated, err := Unlock(user, out, []byte("synthetic-next-unlock-phrase"), false)
	require.NoError(t, err)
	rotated.Close()
	require.Error(t, oldDevice.Request(ctx, "GET", "/v1/vault", nil, &out))
	// Recovery resets account access, still requiring client-side recovery
	// decryption. It also makes the previous recovery verifier unusable.
	newPass := []byte(RandomID()[:6])
	var login LoginResult
	require.NoError(t, a.Request(ctx, "POST", "/v1/recover", map[string]string{"recovery_auth": auth, "password": string(newPass), "device_id": RandomID(), "label": "test-recovery"}, &login))
	a.Token = login.Token
	pass = newPass // cleanup uses the recovered password and session
	recovered, err = Unlock(user, login.Snapshot, []byte(nextRecovery), true)
	require.NoError(t, err)
	recovered.Close()
	t.Log("verified encrypted keys/passwords, SSH key/password logins, merge, retry, isolation, root rotation, recovery and revocation")
}

// The ephemeral loopback SSH service accepts only synthetic cloud-restored
// credentials. Host-key checks are disabled ONLY for this disposable test host.
func verifySSHCredentials(t *testing.T, signer gssh.Signer, password string) {
	t.Helper()
	_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	hostSigner, err := gssh.NewSignerFromKey(hostPrivate)
	require.NoError(t, err)
	cfg := &gssh.ServerConfig{
		PublicKeyCallback: func(_ gssh.ConnMetadata, p gssh.PublicKey) (*gssh.Permissions, error) {
			if string(p.Marshal()) != string(signer.PublicKey().Marshal()) {
				return nil, errors.New("wrong synthetic key")
			}
			return nil, nil
		},
		PasswordCallback: func(_ gssh.ConnMetadata, p []byte) (*gssh.Permissions, error) {
			if string(p) != password {
				return nil, errors.New("wrong synthetic password")
			}
			return nil, nil
		},
	}
	cfg.AddHostKey(hostSigner)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(10 * time.Second))
				sc, chans, reqs, err := gssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				defer sc.Close()
				go gssh.DiscardRequests(reqs)
				for incoming := range chans {
					ch, requests, err := incoming.Accept()
					if err != nil {
						return
					}
					for r := range requests {
						if r.Type == "exec" {
							r.Reply(true, nil)
							ch.Write([]byte("cloud-ssh-ok"))
							ch.SendRequest("exit-status", false, gssh.Marshal(struct{ Status uint32 }{0}))
							ch.Close()
							break
						}
						r.Reply(false, nil)
					}
				}
			}()
		}
	}()
	_, portText, err := net.SplitHostPort(l.Addr().String())
	require.NoError(t, err)
	port, err := strconv.Atoi(portText)
	require.NoError(t, err)
	for _, auth := range []string{config.AuthKey, config.AuthPassword} {
		client, err := sshpkg.Dial(&config.Server{Host: "127.0.0.1", Port: port, User: "test", Auth: auth}, sshpkg.BuildOpts{Signers: []gssh.Signer{signer}, Password: password, Insecure: true, Timeout: 5 * time.Second})
		require.NoError(t, err)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		result, err := client.Exec(ctx, "test")
		cancel()
		client.Close()
		require.NoError(t, err)
		require.Equal(t, "cloud-ssh-ok", result.Stdout)
	}
}
