// Package status provides cheap reachability probes for the server list.
//
// Probes follow the selected SSH transport. Jump hosts require their own
// authentication; final targets are checked without requesting credentials.
package status

import (
	"context"
	"time"

	"github.com/michael-ltm/sshm/internal/config"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
)

// defaultProbeTimeout is the TCP-connect deadline used when the caller
// passes a non-positive timeout. It is deliberately shorter than the SSH
// handshake timeout in internal/ssh — a probe only checks port reachability.
const defaultProbeTimeout = 3 * time.Second

// Result is a single probe outcome.
type Result struct {
	Route     string        `json:"route"`
	Reachable bool          `json:"reachable"`
	Latency   time.Duration `json:"latency_ns,omitempty"` // zero when Reachable is false
	Error     string        `json:"error,omitempty"`      // empty when Reachable is true
	// ObservedAt is the completion time of this specific probe. It is kept out
	// of command JSON because it is internal ordering metadata used when
	// persisting concurrent results.
	ObservedAt time.Time `json:"-"`
}

// Probe checks reachability through the selected SSH route within timeout.
func Probe(ctx context.Context, s *config.Server, timeout time.Duration) (result Result) {
	return ProbeWithOptions(ctx, s, timeout, sshpkg.BuildOpts{})
}

// ProbeWithOptions shares the connection route and jump-host config with SSH.
func ProbeWithOptions(ctx context.Context, s *config.Server, timeout time.Duration, opts sshpkg.BuildOpts) (result Result) {
	defer func() {
		result.ObservedAt = time.Now().UTC()
	}()
	if timeout <= 0 {
		timeout = defaultProbeTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	opts.Timeout = timeout
	route, err := sshpkg.ProbeRoute(ctx, s, opts)
	if err != nil {
		return Result{Reachable: false, Error: err.Error(), Route: route}
	}
	return Result{Reachable: true, Latency: time.Since(start), Route: route}
}

// ProbeMany runs Probe across all servers concurrently (bounded to 16).
// If ctx is cancelled before all goroutines are launched, no further probes
// are started and only the results of already-launched probes are returned.
func ProbeMany(ctx context.Context, servers map[string]*config.Server, timeout time.Duration) map[string]Result {
	return ProbeManyWithOptions(ctx, servers, timeout, sshpkg.BuildOpts{})
}

// ProbeManyWithOptions applies one configuration context to every target route.
func ProbeManyWithOptions(ctx context.Context, servers map[string]*config.Server, timeout time.Duration, opts sshpkg.BuildOpts) map[string]Result {
	const maxConc = 16
	sem := make(chan struct{}, maxConc)
	type item struct {
		alias string
		r     Result
	}
	out := make(chan item, len(servers))

	launched := 0
launchLoop:
	for alias, s := range servers {
		// Prefer cancellation before attempting to acquire a slot. The second
		// check after acquisition closes the small race where cancellation lands
		// while the select is choosing between two ready cases.
		if ctx.Err() != nil {
			break launchLoop
		}
		select {
		case <-ctx.Done():
			break launchLoop
		case sem <- struct{}{}:
		}
		if ctx.Err() != nil {
			<-sem
			break launchLoop
		}
		launched++
		go func(a string, srv *config.Server) {
			defer func() { <-sem }()
			out <- item{a, ProbeWithOptions(ctx, srv, timeout, opts)}
		}(alias, s)
	}

	results := map[string]Result{}
	for i := 0; i < launched; i++ {
		it := <-out
		results[it.alias] = it.r
	}
	return results
}
