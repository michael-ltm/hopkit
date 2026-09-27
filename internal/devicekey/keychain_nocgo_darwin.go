//go:build darwin && !cgo

package devicekey

import "fmt"

// The security command can prompt even on a read. Do not silently substitute
// it in automation builds that lack the noninteractive native Keychain API.
func readKeychainKey(string) ([]byte, error) {
	return nil, fmt.Errorf("this macOS build needs CGO and Security.framework for local device protection: %w", ErrUnavailable)
}
func addKeychainKey(string, []byte) error {
	_, err := readKeychainKey("")
	return err
}
