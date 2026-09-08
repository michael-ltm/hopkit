package ssh

import "testing"

func TestPlatformFromAuthenticatedOutput(t *testing.T) {
	for _, tc := range []struct{ input, want string }{{"Linux\n", "linux"}, {"Darwin\r\n", "macos"}, {"Microsoft Windows [Version 10.0.26100.1]\r\n", "windows"}, {"MINGW64_NT-10.0", "windows"}, {"ubuntu-server", ""}, {"command not found: uname", ""}, {"", ""}} {
		if got := PlatformFromOutput(tc.input); got != tc.want {
			t.Errorf("%q: got %q want %q", tc.input, got, tc.want)
		}
	}
}
