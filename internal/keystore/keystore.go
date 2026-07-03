package keystore

import (
	"fmt"
	"os"

	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
	gssh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Result describes what StoreAndLoad achieved on this platform.
type Result struct {
	Persisted bool   // survives reboot/logout without re-entering the passphrase
	Note      string // human-readable caveat (may be empty)
}

// agentAdd parses the encrypted key at keyPath with passphrase and adds the
// decrypted identity to the running ssh-agent. It does not persist the
// passphrase; persistence is a per-OS concern handled by StoreAndLoad.
func agentAdd(keyPath, passphrase string) error {
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("read key %s: %w", keyPath, err)
	}
	raw, err := gssh.ParseRawPrivateKeyWithPassphrase(data, []byte(passphrase))
	if err != nil {
		return fmt.Errorf("decrypt key %s: %w", keyPath, err)
	}
	conn, err := sshpkg.DialAgent()
	if err != nil {
		return fmt.Errorf("dial agent: %w", err)
	}
	defer conn.Close()
	if err := agent.NewClient(conn).Add(agent.AddedKey{PrivateKey: raw}); err != nil {
		return fmt.Errorf("add key to agent: %w", err)
	}
	return nil
}
