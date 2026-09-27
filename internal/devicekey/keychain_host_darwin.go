//go:build darwin

package devicekey

import (
	"context"
	_ "embed"
	"encoding/json"
)

// Apple's stable signed host keeps file-Keychain application/partition identity
// unchanged across SSHM upgrades. The script is fixed; secret data travels only
// through stdin/stdout pipes, never argv, environment, or a temporary script.
//
//go:embed keychain_host.js
var keychainHostScript string

func keychainHostOperation(ctx context.Context, ref string, key []byte) ([]byte, error) {
	if _, err := reference("keychain-host:"+ref, "keychain-host"); err != nil {
		return nil, ErrUnavailable
	}
	request := struct {
		Operation string `json:"operation"`
		Ref       string `json:"ref"`
		Key       []byte `json:"key,omitempty"`
	}{Operation: "read", Ref: ref}
	if key != nil {
		if len(key) != 32 {
			return nil, ErrUnavailable
		}
		request.Operation, request.Key = "create", key
	}
	input, err := json.Marshal(request)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer clear(input)
	output, err := runCommand(ctx, input, "/usr/bin/osascript", "-l", "JavaScript", "-e", keychainHostScript)
	defer clear(output)
	if err != nil {
		return nil, err
	}
	var response struct {
		Status *int   `json:"status"`
		Key    []byte `json:"key"`
	}
	if err := json.Unmarshal(output, &response); err != nil || response.Status == nil || *response.Status != 0 {
		clear(response.Key)
		return nil, ErrUnavailable
	}
	if key != nil {
		clear(response.Key)
		return nil, nil
	}
	if len(response.Key) != 32 {
		clear(response.Key)
		return nil, ErrUnavailable
	}
	return response.Key, nil
}
