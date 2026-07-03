//go:build linux

package keystore

// StoreAndLoad loads the decrypted key into the running ssh-agent. The default
// Linux ssh-agent does not persist identities across logout/reboot, so
// Persisted is false and the note explains it.
func StoreAndLoad(keyPath, passphrase string) (Result, error) {
	if err := agentAdd(keyPath, passphrase); err != nil {
		return Result{}, err
	}
	return Result{
		Persisted: false,
		Note:      "loaded into ssh-agent for this session; Linux ssh-agent does not persist across reboot — re-run `sshm` after login, or use a keyring agent (gnome-keyring/keychain) for persistence",
	}, nil
}
