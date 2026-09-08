// Package desktopsession runs opt-in commands in the same macOS user's GUI
// login session. Credentials remain in the OS keychain; there is no token export.
package desktopsession

import "errors"

var ErrUnsupported = errors.New("desktop sessions require macOS; Linux and Windows use their native execution environment")

type Status struct {
	Supported bool   `json:"supported"`
	Enabled   bool   `json:"enabled"`
	Running   bool   `json:"running"`
	Version   string `json:"version,omitempty"`
}

type request struct {
	Protocol  int    `json:"protocol"`
	Op        string `json:"op"`
	Command   string `json:"command,omitempty"`
	Directory string `json:"directory,omitempty"`
}

type frame struct {
	Kind    string `json:"kind"`
	Data    []byte `json:"data,omitempty"`
	Code    int    `json:"code,omitempty"`
	Version string `json:"version,omitempty"`
	Error   string `json:"error,omitempty"`
}
