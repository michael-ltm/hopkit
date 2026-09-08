//go:build windows

package ssh

import (
	"crypto/rand"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh/agent"
)

func TestWindowsAgentRecovery(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	require.Equal(t, []string{windowsAgentPipe}, agentPaths())
	t.Setenv("SSH_AUTH_SOCK", "/tmp/cygwin-agent.sock")
	require.Equal(t, []string{windowsAgentPipe}, agentPaths())
	pipe := fmt.Sprintf(`\\.\pipe\sshm-test-%d-%d`, os.Getpid(), time.Now().UnixNano())
	listener, err := winio.ListenPipe(pipe, nil)
	require.NoError(t, err)
	defer listener.Close()
	key := genEd25519(t)
	kr := agent.NewKeyring()
	require.NoError(t, kr.Add(agent.AddedKey{PrivateKey: key}))
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _ = agent.ServeAgent(kr, conn) }()
		}
	}()
	t.Setenv("SSH_AUTH_SOCK", pipe)
	require.Equal(t, []string{pipe}, agentPaths())
	signer, closer, err := loadKeySigner(writeEncryptedTempKey(t, key))
	require.NoError(t, err)
	defer closer.Close()
	sig, err := signer.Sign(rand.Reader, []byte("windows-mcp-proof"))
	require.NoError(t, err)
	require.NoError(t, signer.PublicKey().Verify([]byte("windows-mcp-proof"), sig))
	t.Setenv("SSH_AUTH_SOCK", pipe+"-missing")
	conn, err := dialAgent()
	require.Error(t, err, "explicit pipe must not silently use another agent")
	require.Nil(t, conn)
}
