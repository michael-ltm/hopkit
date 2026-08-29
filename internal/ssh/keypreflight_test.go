package ssh

import (
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	gssh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestCheckKeyPairUsablePlainKey(t *testing.T) {
	path := writeTempKey(t)
	writeSiblingPublicKey(t, path, path)

	publicKey, err := CheckKeyPairUsable(path)
	require.NoError(t, err)
	require.Contains(t, publicKey, "ssh-ed25519")
}

func TestCheckKeyPairUsableRejectsMismatchedPublicKey(t *testing.T) {
	privatePath := writeTempKey(t)
	otherPath := writeTempKey(t)
	writeSiblingPublicKey(t, privatePath, otherPath)

	_, err := CheckKeyPairUsable(privatePath)
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not match")
}

func TestCheckKeyPairUsableEncryptedKeySignsThroughAgent(t *testing.T) {
	skipIfNoUnixSockets(t)
	privateKey := genEd25519(t)
	path := writeEncryptedTempKey(t, privateKey)
	signer, err := gssh.NewSignerFromKey(privateKey)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path+".pub", gssh.MarshalAuthorizedKey(signer.PublicKey()), 0o644))
	t.Setenv("SSH_AUTH_SOCK", serveTestAgent(t, privateKey))

	_, err = CheckKeyPairUsable(path)
	require.NoError(t, err)
}

func TestCheckKeyPairUsableRejectsAgentThatListsButCannotSign(t *testing.T) {
	skipIfNoUnixSockets(t)
	privateKey := genEd25519(t)
	path := writeEncryptedTempKey(t, privateKey)
	signer, err := gssh.NewSignerFromKey(privateKey)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path+".pub", gssh.MarshalAuthorizedKey(signer.PublicKey()), 0o644))
	keyring := agent.NewKeyring()
	require.NoError(t, keyring.Add(agent.AddedKey{PrivateKey: privateKey}))
	t.Setenv("SSH_AUTH_SOCK", serveAgentBackend(t, rejectingSignAgent{Agent: keyring}))

	_, err = CheckKeyPairUsable(path)
	require.Error(t, err)
	require.Contains(t, err.Error(), "sign with key")
}

type rejectingSignAgent struct {
	agent.Agent
}

func (rejectingSignAgent) Sign(gssh.PublicKey, []byte) (*gssh.Signature, error) {
	return nil, errors.New("signing disabled")
}

func writeSiblingPublicKey(t *testing.T, destinationPrivatePath, publicSourcePrivatePath string) {
	t.Helper()
	data, err := os.ReadFile(publicSourcePrivatePath)
	require.NoError(t, err)
	signer, err := gssh.ParsePrivateKey(data)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(destinationPrivatePath+".pub", gssh.MarshalAuthorizedKey(signer.PublicKey()), 0o644))
}
