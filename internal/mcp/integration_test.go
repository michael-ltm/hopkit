//go:build integration

package mcp

import (
	"bufio"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/michael-ltm/sshm/internal/config"
	"github.com/stretchr/testify/require"
)

// TestIntegration_McpStdioListServers builds the binary, starts `sshm mcp`,
// performs the MCP initialize handshake, calls list_servers, and asserts the
// configured alias appears in the response.
func TestIntegration_McpStdioListServers(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	cfg := config.New()
	cfg.Servers["prod"] = &config.Server{Host: "1.2.3.4", User: "u", Auth: config.AuthAgent}
	require.NoError(t, config.Save(cfgPath, cfg))

	bin := filepath.Join(dir, "sshm")
	build := exec.Command("go", "build", "-o", bin, "github.com/michael-ltm/sshm/cmd/sshm")
	out, err := build.CombinedOutput()
	require.NoError(t, err, "go build failed: %s", out)

	cmd := exec.Command(bin, "--config", cfgPath, "mcp")
	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())
	defer func() { _ = cmd.Process.Kill() }()

	w := func(v any) {
		b, _ := json.Marshal(v)
		_, _ = stdin.Write(append(b, '\n'))
	}
	r := bufio.NewReader(stdout)

	// Step 1: send initialize
	w(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "test", "version": "0"},
		},
	})

	// Read lines until we get the initialize response (id=1)
	initDone := make(chan error, 1)
	go func() {
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				initDone <- err
				return
			}
			t.Logf("init line: %s", line)
			var msg map[string]any
			if json.Unmarshal([]byte(line), &msg) == nil {
				if id, ok := msg["id"]; ok {
					switch v := id.(type) {
					case float64:
						if v == 1 {
							initDone <- nil
							return
						}
					}
				}
			}
		}
	}()

	select {
	case err := <-initDone:
		require.NoError(t, err, "reading initialize response")
	case <-time.After(10 * time.Second):
		t.Fatal("no initialize response within 10s")
	}

	// Step 2: send notifications/initialized
	w(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})

	// Step 3: call list_servers
	w(map[string]any{
		"jsonrpc": "2.0", "id": 2, "method": "tools/call",
		"params": map[string]any{"name": "list_servers", "arguments": map[string]any{}},
	})

	// Read lines until we find the tools/call response (id=2)
	done := make(chan string, 1)
	go func() {
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				done <- line
				return
			}
			t.Logf("tools/call line: %s", line)
			if strings.Contains(line, `"id":2`) || strings.Contains(line, `"id": 2`) {
				done <- line
				return
			}
		}
	}()

	select {
	case line := <-done:
		require.Contains(t, line, "prod")
	case <-time.After(10 * time.Second):
		t.Fatal("no response from mcp server within 10s")
	}
}
