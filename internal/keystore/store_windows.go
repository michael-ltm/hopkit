//go:build windows

package keystore

// StoreAndLoad loads the decrypted key into the Windows OpenSSH agent, which
// persists added identities across reboots (DPAPI). Persisted is true.
func StoreAndLoad(keyPath, passphrase string) (Result, error) {
	if err := agentAdd(keyPath, passphrase); err != nil {
		return Result{}, err
	}
	return Result{Persisted: true}, nil
}
