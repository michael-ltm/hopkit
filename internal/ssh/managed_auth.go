package ssh

import (
	"context"
	"errors"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/localstore"
	gssh "golang.org/x/crypto/ssh"
)

// CheckLocalCredentials preserves explicit lock/protection errors for callers
// deciding whether a missing password should be prompted in a local terminal.
func CheckLocalCredentials(target *config.Server, opts BuildOpts) error {
	_, _, err := managedAuth(target, opts)
	return err
}

// managedAuth is shared by CLI, MCP and transfers. No cloud call or daemon
// connection is necessary to recover credentials on a trusted device.
func managedAuth(target *config.Server, opts BuildOpts) ([]gssh.AuthMethod, bool, error) {
	store := opts.LocalStore
	if store == nil {
		store = localstore.New(opts.ConfigPath)
	}
	if err := store.CheckLocked(); err != nil {
		return nil, true, localCredentialError(err)
	}
	// An explicit browser session has already applied its own authorization;
	// do not replace its supplied credentials with another authentication source.
	if len(opts.Signers) > 0 || opts.Password != "" {
		return nil, false, nil
	}
	if !store.Enabled() {
		return nil, false, nil
	}
	credentials, err := store.Resolve(context.Background(), target)
	if errors.Is(err, localstore.ErrNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, true, localCredentialError(err)
	}
	defer localstore.CloseCredentials(credentials)
	var signers []gssh.Signer
	var methods []gssh.AuthMethod
	for _, credential := range credentials {
		if len(credential.Password) > 0 {
			methods = append(methods, gssh.Password(string(credential.Password)))
			continue
		}
		signer, err := credential.Signer()
		if err != nil {
			return nil, true, localCredentialError(err)
		}
		signers = append(signers, signer)
	}
	if len(signers) > 0 {
		methods = append([]gssh.AuthMethod{gssh.PublicKeys(signers...)}, methods...)
	}
	if len(methods) == 0 {
		return nil, true, localCredentialError(localstore.ErrCorrupt)
	}
	return methods, true, nil
}

func localCredentialError(err error) error {
	code := "local_credential_unavailable"
	if errors.Is(err, localstore.ErrLocked) {
		code = "local_device_locked"
	}
	if errors.Is(err, localstore.ErrInactive) {
		code = "local_credential_inactive"
	}
	return &LocalAuthError{Code: code, Message: err.Error()}
}
