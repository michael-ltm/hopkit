//go:build !linux

package localservice

import "os"

func startupCommandEnvironment() ([]string, error) {
	return os.Environ(), nil
}
