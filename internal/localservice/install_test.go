package localservice

import (
	"encoding/xml"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInstallTemplatesQuoteLiteralPaths(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "a \"quote\" %name$", "sshm")
	path := filepath.Join(dir, "config %test$.toml")
	unit, e := renderSystemd(binary, path)
	require.NoError(t, e)
	require.Contains(t, unit, `\"quote\"`)
	require.Contains(t, unit, "%%name$$")
	require.Contains(t, unit, "Restart=on-failure")
	require.NotContains(t, unit, "/bin/sh")
	_, e = renderSystemd(binary+"\n[Service]", path)
	require.Error(t, e)
	plist, e := renderLaunchAgent("test-label", binary, path)
	require.NoError(t, e)
	decoder := xml.NewDecoder(strings.NewReader(plist))
	for {
		_, e = decoder.Token()
		if e != nil {
			break
		}
	}
	require.Equal(t, "EOF", e.Error())
	require.Contains(t, plist, "&#34;quote&#34;")
	task := renderWindowsTask("S-1-test", binary, "--config \"a&b\" service run")
	decoder = xml.NewDecoder(strings.NewReader(task))
	for {
		_, e = decoder.Token()
		if e != nil {
			break
		}
	}
	require.Equal(t, "EOF", e.Error())
	require.Contains(t, task, "a&amp;b")
	require.Contains(t, task, "InteractiveToken")
	var parsed struct {
		Settings struct {
			Restart struct {
				Interval string `xml:"Interval"`
				Count    int    `xml:"Count"`
			} `xml:"RestartOnFailure"`
		} `xml:"Settings"`
	}
	require.NoError(t, xml.Unmarshal([]byte(task), &parsed))
	require.Equal(t, "PT1M", parsed.Settings.Restart.Interval)
	require.Positive(t, parsed.Settings.Restart.Count)
}
func TestSystemInstallExplicitlyUnsupported(t *testing.T) {
	require.ErrorContains(t, Install("config.toml", "/bin/sshm", true), "system")
}

// Reinstalling over a loaded launchd job must unload it first: bootstrap alone
// fails while the label is loaded and launchd keeps the old ProgramArguments.
func TestLaunchdRegistrationReloadsExistingJob(t *testing.T) {
	steps := launchdRegistration(501, "sshm-local-abc", "/Users/u/Library/LaunchAgents/sshm-local-abc.plist")
	if len(steps) != 2 {
		t.Fatalf("steps = %v, want bootout then bootstrap", steps)
	}
	if got := strings.Join(steps[0].args, " "); got != "bootout gui/501/sshm-local-abc" || !steps[0].mayFail {
		t.Fatalf("first step = %+v, want a bootout that may fail when nothing is loaded", steps[0])
	}
	if got := strings.Join(steps[1].args, " "); got != "bootstrap gui/501 /Users/u/Library/LaunchAgents/sshm-local-abc.plist" || steps[1].mayFail {
		t.Fatalf("second step = %+v, want a required bootstrap", steps[1])
	}
}

// enable --now leaves an already-running unit on its old ExecStart, so a
// reinstall must restart it explicitly.
func TestSystemdRegistrationRestartsRunningUnit(t *testing.T) {
	var got []string
	for _, step := range systemdRegistration("sshm-local-abc.service") {
		got = append(got, strings.Join(step.args, " "))
	}
	want := []string{"--user daemon-reload", "--user enable sshm-local-abc.service", "--user restart sshm-local-abc.service"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("systemd steps = %v, want %v", got, want)
	}
}
