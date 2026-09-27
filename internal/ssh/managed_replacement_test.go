package ssh

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/localstore"
	"github.com/michael-ltm/sshm/internal/testutil"
	"github.com/stretchr/testify/require"
	gssh "golang.org/x/crypto/ssh"
	"os"
	"path/filepath"
	"testing"
)

func TestReviewEncryptedReplacementRejectsStalePub(t *testing.T) {
	path := writeTempKey(t)
	old, err := os.ReadFile(path)
	require.NoError(t, err)
	signer, err := gssh.ParsePrivateKey(old)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path+".pub", gssh.MarshalAuthorizedKey(signer.PublicKey()), 0600))
	store := localstore.New(filepath.Join(t.TempDir(), "config"))
	store.Protector = testutil.NewDeviceProtector()
	require.NoError(t, store.RememberKeyFile(context.Background(), path, localstore.Credential{Key: old}))
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	block, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key), []byte("replacement-pass"), x509.PEMCipherAES256)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(block), 0600))
	_, _, err = BuildClientConfig(&config.Server{Host: "fixture", User: "fixture", Auth: config.AuthKey, KeyPath: path}, BuildOpts{LocalStore: store, Insecure: true})
	require.Error(t, err, "must not silently use old saved key after encrypted private file replacement")
}
