package localservice

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/michael-ltm/sshm/internal/localstore"
)

func validPath(path string) bool {
	return filepath.IsAbs(path) && !strings.ContainsAny(path, "\x00\r\n")
}
func unitQuote(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	s = strings.ReplaceAll(s, "%", "%%")
	s = strings.ReplaceAll(s, "$", "$$")
	return "\"" + s + "\""
}
func renderSystemd(binary, configPath string) (string, error) {
	if !validPath(binary) || !validPath(configPath) {
		return "", errors.New("service requires absolute paths without control characters")
	}
	return "[Unit]\nDescription=sshm local credential service\n\n[Service]\nType=simple\nExecStart=" + unitQuote(binary) + " --config " + unitQuote(configPath) + " service run --supervise\nRestart=on-failure\nRestartSec=3\nUMask=0077\nStandardOutput=null\nStandardError=null\n\n[Install]\nWantedBy=default.target\n", nil
}
func xmlText(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}
func renderLaunchAgent(label, binary, configPath string) (string, error) {
	if !validPath(binary) || !validPath(configPath) {
		return "", errors.New("service requires absolute paths without control characters")
	}
	return `<?xml version="1.0" encoding="UTF-8"?>` + "\n" + `<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n" + `<plist version="1.0"><dict><key>Label</key><string>` + xmlText(label) + `</string><key>ProgramArguments</key><array><string>` + xmlText(binary) + `</string><string>--config</string><string>` + xmlText(configPath) + `</string><string>service</string><string>run</string><string>--supervise</string></array><key>RunAtLoad</key><true/><key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict><key>StandardOutPath</key><string>/dev/null</string><key>StandardErrorPath</key><string>/dev/null</string></dict></plist>`, nil
}

func renderWindowsTask(sid, binary, args string) string {
	return `<?xml version="1.0" encoding="UTF-8"?><Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Triggers><LogonTrigger><Enabled>true</Enabled><UserId>` + xmlText(sid) + `</UserId></LogonTrigger></Triggers><Principals><Principal id="Author"><UserId>` + xmlText(sid) + `</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals><Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><StartWhenAvailable>true</StartWhenAvailable><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure></Settings><Actions Context="Author"><Exec><Command>` + xmlText(binary) + `</Command><Arguments>` + xmlText(args) + `</Arguments></Exec></Actions></Task>`
}
func startupPath(configPath string) string {
	home, _ := os.UserHomeDir()
	name := "sshm-local-" + instance(configPath)
	switch runtime.GOOS {
	case "linux":
		return filepath.Join(home, ".config", "systemd", "user", name+".service")
	case "darwin":
		return filepath.Join(home, "Library", "LaunchAgents", name+".plist")
	case "windows":
		return localstore.New(configPath).ConfigPath + ".local/startup.xml"
	}
	return ""
}
func startupInstalled(configPath string) bool {
	path := startupPath(configPath)
	if path == "" {
		return false
	}
	st, e := os.Lstat(path)
	return e == nil && st.Mode().IsRegular()
}

// Install configures a per-user startup manager. System installations require
// a separate identity design and are deliberately refused.
func Install(configPath, executable string, system bool) error {
	if system {
		return errors.New("system service installation is unsupported; install for the credential-owning user")
	}
	configPath = localstore.New(configPath).ConfigPath
	binary, e := filepath.Abs(executable)
	if e != nil {
		return e
	}
	path := startupPath(configPath)
	var data string
	switch runtime.GOOS {
	case "linux":
		data, e = renderSystemd(binary, configPath)
	case "darwin":
		data, e = renderLaunchAgent("sshm-local-"+instance(configPath), binary, configPath)
	case "windows":
		return installWindows(configPath, binary, path)
	default:
		return errors.New("local service startup is unsupported on this platform")
	}
	if e != nil {
		return e
	}
	environment, e := startupCommandEnvironment()
	if e != nil {
		return e
	}
	if e = privateWrite(path, []byte(data)); e != nil {
		return e
	}
	run := func(binary string, args ...string) error {
		cmd := exec.Command(binary, args...)
		cmd.Env = environment
		if e := cmd.Run(); e != nil {
			return errors.New("could not register local service startup")
		}
		return nil
	}
	if runtime.GOOS == "linux" {
		if e = run("systemctl", "--user", "daemon-reload"); e != nil {
			return e
		}
		return run("systemctl", "--user", "enable", "--now", filepath.Base(path))
	}
	return run("launchctl", "bootstrap", fmt.Sprintf("gui/%d", os.Getuid()), path)
}
