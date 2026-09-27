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
