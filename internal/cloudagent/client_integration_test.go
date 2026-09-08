package cloudagent

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/michael-ltm/sshm/internal/cloudsync"
	"github.com/stretchr/testify/require"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestNativeClientToClientEncryptedTerminal(t *testing.T) {
	endpoint := os.Getenv("SSHM_CLOUD_TEST_ENDPOINT")
	if endpoint == "" {
		t.Skip("set SSHM_CLOUD_TEST_ENDPOINT for real relay acceptance")
	}
	hold, _ := time.ParseDuration(os.Getenv("SSHM_TEST_HOLD_SESSION"))
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Second+hold)
	defer cancel()
	user := "test-" + cloudsync.Digest(cloudsync.RandomID())[:14]
	password, phrase := []byte(cloudsync.RandomID()), []byte(cloudsync.RandomID())
	v, recovery, err := cloudsync.NewVault(user, phrase)
	require.NoError(t, err)
	defer v.Close()
	a, err := cloudsync.Register(ctx, endpoint, user, "native-device-a", password, v, recovery)
	require.NoError(t, err)
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		require.NoError(t, a.Request(cleanup, "DELETE", "/v1/account", map[string]string{"password": string(password)}, nil))
	}()
	b, err := cloudsync.Login(ctx, endpoint, user, "native-device-b", password)
	require.NoError(t, err)
	bv, err := cloudsync.Unlock(user, b.Draft, phrase, false)
	require.NoError(t, err)
	defer bv.Close()
	a.RuntimeVersion, b.RuntimeVersion = "0.8.0-live-version-a", "0.8.0-live-version-b"
	doneA, doneB := make(chan error, 1), make(chan error, 1)
	go func() { doneA <- Serve(ctx, a, v) }()
	go func() { doneB <- Serve(ctx, b, bv) }()
	defer func() { cancel(); <-doneA; <-doneB }()
	require.Eventually(t, func() bool { agents, e := a.Agents(ctx); return e == nil && len(agents) == 2 }, 15*time.Second, 200*time.Millisecond)
	caps, e := a.Agents(ctx)
	require.NoError(t, e)
	for _, cap := range caps {
		want := a.RuntimeVersion
		if cap.DeviceID == b.DeviceID {
			want = b.RuntimeVersion
		}
		require.Equal(t, want, cap.RuntimeVersion)
	}
	for _, direction := range []struct {
		from  *cloudsync.State
		vault *cloudsync.Vault
		to    string
	}{{a, v, b.DeviceID}, {b, bv, a.DeviceID}} {
		terminal, e := cloudsync.OpenDeviceTerminal(ctx, direction.from, direction.vault, direction.to)
		require.NoError(t, e)
		require.NoError(t, terminal.Send(cloudsync.ShellPayload{Type: "resize", Cols: 90, Rows: 24}))
		delay := time.Duration(0)
		if direction.from == a && hold > 0 {
			delay = hold
			t.Logf("Keeping encrypted PTY open for %s before checking output", hold)
		}
		command := "printf 'SSHM_NATIVE_%s_DONE\\n' VERIFIED\r"
		if runtime.GOOS == "windows" {
			command = "Write-Output ('SSHM_NATIVE_' + 'VERIFIED_DONE')\r"
		}
		if delay > 0 {
			if runtime.GOOS == "windows" {
				command = fmt.Sprintf("Start-Sleep -Seconds %d; ", int(delay.Seconds())) + command
			} else {
				command = fmt.Sprintf("sleep %d; ", int(delay.Seconds())) + command
			}
		}
		require.NoError(t, terminal.Send(cloudsync.ShellPayload{Type: "input", Data: base64.RawURLEncoding.EncodeToString([]byte(command))}))
		result := ""
		for !strings.Contains(result, "SSHM_NATIVE_VERIFIED_DONE") {
			p, e := terminal.Receive(ctx)
			require.NoError(t, e)
			require.Equal(t, "output", p.Type)
			raw, e := base64.RawURLEncoding.DecodeString(p.Data)
			require.NoError(t, e)
			result += string(raw)
		}
		terminal.Close()
	}
	// An account token without the correct vault signing key cannot open a shell.
	wrong, _, err := cloudsync.NewVault(user, []byte("wrong-test-phrase"))
	require.NoError(t, err)
	defer wrong.Close()
	_, err = cloudsync.OpenDeviceTerminal(ctx, a, wrong, b.DeviceID)
	require.Error(t, err)
	terminal, err := cloudsync.OpenDeviceTerminal(ctx, a, v, b.DeviceID)
	require.NoError(t, err)
	defer terminal.Close()
	require.NoError(t, a.Request(ctx, "DELETE", "/v1/devices/"+b.DeviceID, nil, nil))
	closedCtx, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	for {
		p, e := terminal.Receive(closedCtx)
		if e != nil || p.Type == "closed" {
			break
		}
	}
	require.NoError(t, closedCtx.Err(), "revocation must close the session without waiting for its deadline")
	t.Log("PASS: two native clients connected in both directions; forged vault key rejected; device revocation closed the active terminal")
}
