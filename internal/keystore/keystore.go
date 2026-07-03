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

// BestEffort turns a StoreAndLoad outcome into one callers can always use
// without failing: when err is nil, res is returned unchanged; when err is
// non-nil (e.g. no ssh-agent running on a headless host, or the keychain is
// unreachable), it is downgraded to a non-fatal Result carrying an
// explanatory Note instead. Callers should never abort key generation solely
// because the agent/keystore step failed — the encrypted key file already
// written to disk is the primary deliverable and remains valid regardless.
//
// Typical use: store = keystore.BestEffort(keystore.StoreAndLoad(keyPath, passphrase)).
func BestEffort(res Result, err error) Result {
	if err == nil {
		return res
	}
	return Result{Note: fmt.Sprintf(
		"not loaded into agent: %s (key is encrypted on disk but not loaded into an agent — load it when an agent is available)", err)}
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
