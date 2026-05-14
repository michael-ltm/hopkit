// Package status provides cheap reachability probes for the server list.
//
// v0.1 uses TCP-connect probe only — it surfaces "is the SSH port open?"
// without needing credentials. v0.2 layers an SSH handshake probe on top.
package status

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/michael-ltm/sshm/internal/config"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
)

// Result is a single probe outcome.
type Result struct {
	Reachable bool
	Latency   time.Duration
	Error     string
}

// Probe attempts a TCP connect to the server within timeout.
func Probe(ctx context.Context, s *config.Server, timeout time.Duration) Result {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", sshpkg.Address(s))
	if err != nil {
		return Result{Reachable: false, Error: fmt.Sprintf("%v", err)}
	}
	_ = conn.Close()
	return Result{Reachable: true, Latency: time.Since(start)}
}

// ProbeMany runs Probe across all servers concurrently (bounded to 16).
func ProbeMany(ctx context.Context, servers map[string]*config.Server, timeout time.Duration) map[string]Result {
	const maxConc = 16
	sem := make(chan struct{}, maxConc)
	type item struct {
		alias string
		r     Result
	}
	out := make(chan item, len(servers))
	for alias, s := range servers {
		sem <- struct{}{}
		go func(a string, srv *config.Server) {
			defer func() { <-sem }()
			out <- item{a, Probe(ctx, srv, timeout)}
		}(alias, s)
	}
	results := map[string]Result{}
	for i := 0; i < len(servers); i++ {
		it := <-out
		results[it.alias] = it.r
	}
	return results
}
