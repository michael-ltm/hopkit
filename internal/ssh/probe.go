package ssh

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/michael-ltm/sshm/internal/config"
)

// ProbeRoute opens only the selected transport, without direct fallback. Jump
// routes authenticate their intermediary, while the final target is only
// checked for transport reachability. ProxyCommand must emit an SSH banner
// because spawning its process alone does not prove target reachability.
// The returned route is a safe transport name, never a command or proxy URL.
func ProbeRoute(ctx context.Context, target *config.Server, opts BuildOpts) (string, error) {
	if target == nil {
		return "direct", errors.New("SSH target is required")
	}
	kind, _, _ := resolveRouteTransportKind(target, opts.StrictRoute)
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	opts.ProbeOnly = true
	type result struct {
		route string
		err   error
	}
	done := make(chan result)
	go func() {
		conn, aux, used, err := dialTransportKind(target, opts, timeout, false)
		if aux != nil {
			defer aux.Close()
		}
		if conn != nil {
			defer conn.Close()
		}
		if err == nil {
			closed := make(chan struct{})
			defer close(closed)
			go func() {
				select {
				case <-ctx.Done():
					_ = conn.Close()
				case <-closed:
				}
			}()
			if used == kindProxyCommand {
				_ = conn.SetReadDeadline(time.Now().Add(timeout))
				reader := bufio.NewReaderSize(conn, 1024)
				err = fmt.Errorf("proxy-command did not reach an SSH endpoint")
				for i := 0; i < 50; i++ {
					line, readErr := reader.ReadSlice('\n')
					if readErr != nil {
						err = readErr
						break
					}
					if len(line) >= 4 && string(line[:4]) == "SSH-" {
						err = nil
						break
					}
				}
			}
		}
		select {
		case done <- result{used.String(), err}:
		case <-ctx.Done():
		}
	}()
	select {
	case r := <-done:
		return r.route, r.err
	case <-ctx.Done():
		return kind.String(), ctx.Err()
	}
}
