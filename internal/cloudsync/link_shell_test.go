package cloudsync

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLinkPinsVaultAndDecryptsOnlyForTarget(t *testing.T) {
	v, _, e := NewVault("link-test", []byte("test-phrase"))
	require.NoError(t, e)
	defer v.Close()
	snap, e := v.Snapshot(0, RandomID())
	require.NoError(t, e)
	snap.Revision = 1
	for _, bad := range []bool{false, true} {
		t.Run(map[bool]string{false: "valid", true: "substituted-root"}[bad], func(t *testing.T) {
			r, e := NewLinkRequest("test_device", "test", v.Public(), true)
			require.NoError(t, e)
			r.Expires = time.Now().Add(time.Minute).UnixMilli()
			browser, e := ecdh.P256().GenerateKey(rand.Reader)
			require.NoError(t, e)
			shared, e := browser.ECDH(r.private.PublicKey())
			require.NoError(t, e)
			nonce, ciphertext, e := seal(linkKey(shared, "link-test", r.ID), v.Master, linkAAD("link-test", r.ID, r.PublicKey))
			require.NoError(t, e)
			b, _ := json.Marshal(LinkGrant{1, encoding.EncodeToString(browser.PublicKey().Bytes()), nonce, ciphertext})
			grant := string(b)
			replySnap := snap
			if bad {
				replySnap.RootPublic = encoding.EncodeToString(random(32))
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				json.NewEncoder(w).Encode(map[string]any{"status": "approved", "device_id": r.DeviceID, "request_expires": r.Expires, "snapshot": replySnap, "grant": grant, "signature": encoding.EncodeToString(ed25519.Sign(v.private(), LinkMessage("link-test", r, grant))), "token": encoding.EncodeToString(random(32)), "expires": time.Now().Add(time.Hour).UnixMilli()})
			}))
			defer server.Close()
			s := State{URL: server.URL, Username: "link-test"}
			opened, e := s.WaitLink(context.Background(), r)
			if bad {
				require.Error(t, e)
				require.Empty(t, s.Token)
			} else {
				require.NoError(t, e)
				require.Equal(t, v.Master, opened.Master)
				opened.Close()
			}
			require.Nil(t, r.private)
			require.Empty(t, r.Secret)
		})
	}
}
func TestShellFramesRejectReplayTamperingAndWrongDirection(t *testing.T) {
	master := random(32)
	a, _ := NewShellCipher(master, "user", "device", "epoch", "session", "c2a")
	b, _ := NewShellCipher(master, "user", "device", "epoch", "session", "c2a")
	wrong, _ := NewShellCipher(master, "user", "device", "epoch", "session", "a2c")
	f, e := a.Seal(ShellPayload{Type: "input", Data: "aGVsbG8"})
	require.NoError(t, e)
	_, e = wrong.Open(f)
	require.Error(t, e)
	tampered := f
	tampered.Ciphertext = encoding.EncodeToString(random(40))
	_, e = b.Open(tampered)
	require.Error(t, e)
	p, e := b.Open(f)
	require.NoError(t, e)
	require.Equal(t, "aGVsbG8", p.Data)
	_, e = b.Open(f)
	require.Error(t, e)
	f, e = a.Seal(ShellPayload{Type: "resize", Cols: 100, Rows: 30})
	require.NoError(t, e)
	_, e = b.Open(f)
	require.NoError(t, e)
}

func TestContinuousShellPolicyIsSignedAndAdmissionStillExpires(t *testing.T) {
	v, _, err := NewVault("shell-policy", []byte("test-phrase"))
	require.NoError(t, err)
	defer v.Close()
	for _, mode := range []string{"", "ssh"} {
		r := ShellOpen{Lifetime: "connection", Mode: mode, Type: "open", Device: "test_device", Epoch: "test_epoch", Session: RandomID(), Expires: time.Now().Add(time.Minute).UnixMilli()}
		v.SignShell(&r, "shell-policy")
		require.True(t, v.VerifyShell(r, "shell-policy", r.Device, r.Epoch))
		changed := r
		changed.Lifetime = ""
		require.False(t, v.VerifyShell(changed, "shell-policy", r.Device, r.Epoch), "session policy cannot be stripped")
		changed = r
		changed.Mode = "ssh"
		if mode == "ssh" {
			changed.Mode = ""
		}
		require.False(t, v.VerifyShell(changed, "shell-policy", r.Device, r.Epoch))
		changed = r
		changed.Expires = time.Now().Add(-time.Second).UnixMilli()
		v.SignShell(&changed, "shell-policy")
		require.False(t, v.VerifyShell(changed, "shell-policy", r.Device, r.Epoch))
		changed = r
		changed.Lifetime = "forever"
		v.SignShell(&changed, "shell-policy")
		require.False(t, v.VerifyShell(changed, "shell-policy", r.Device, r.Epoch))
	}
}
