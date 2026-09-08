//go:build windows

package commands

import (
	"github.com/charmbracelet/x/conpty"
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestHomeNativeWindowsConPTY(t *testing.T) {
	binary := os.Getenv("SSHM_CLI_TEST_BINARY")
	if binary == "" {
		t.Skip("set SSHM_CLI_TEST_BINARY for native ConPTY acceptance")
	}
	cfg := config.New()
	cfg.UI.Language = "en"
	cfg.UI.Icons = "ascii"
	path := filepath.Join(t.TempDir(), "config.toml")
	require.NoError(t, config.Save(path, cfg))
	tty, e := conpty.New(100, 28, 0)
	require.NoError(t, e)
	defer tty.Close()
	_, handle, e := tty.Spawn(binary, []string{binary, "--config", path, "--no-color"}, &syscall.ProcAttr{Env: append(os.Environ(), "SSHM_NO_UPDATE_CHECK=1")})
	require.NoError(t, e)
	process := windows.Handle(handle)
	defer windows.CloseHandle(process)
	defer windows.TerminateProcess(process, 1)
	chunks := make(chan string, 128)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		buf := make([]byte, 8192)
		for {
			n, e := tty.Read(buf)
			if n > 0 {
				select {
				case chunks <- string(buf[:n]):
				case <-stop:
					return
				}
			}
			if e != nil {
				return
			}
		}
	}()
	wait := func(want string) {
		t.Helper()
		text := ""
		timer := time.NewTimer(12 * time.Second)
		defer timer.Stop()
		for !strings.Contains(text, want) {
			select {
			case chunk := <-chunks:
				text += chunk
			case <-timer.C:
				t.Fatalf("Windows menu did not show %q: %q", want, text)
			}
		}
	}
	send := func(key string) { t.Helper(); _, e := tty.Write([]byte(key)); require.NoError(t, e) }
	wait("Servers")
	send("s")
	wait("Search servers")
	send("q")
	wait("Servers")
	send(",")
	wait("Language / ")
	send("\x1b")
	wait("Servers")
	send("q")
	result, e := windows.WaitForSingleObject(process, 8000)
	require.NoError(t, e)
	require.Equal(t, uint32(windows.WAIT_OBJECT_0), result)
	t.Log("PASS: native Windows home, list, back, settings, Esc and exit")
}
