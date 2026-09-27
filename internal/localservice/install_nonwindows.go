//go:build !windows

package localservice

import "errors"

func installWindows(string, string, string) error {
	return errors.New("Windows startup is unavailable")
}
