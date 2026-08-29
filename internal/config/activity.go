package config

import "time"

// ClearServerActivity removes observations that belonged to a server's old
// connection identity. CreatedAt and all non-activity metadata are preserved;
// IdentityChangedAt becomes the new cleanup baseline until the replacement
// target has a successful authenticated use.
func ClearServerActivity(server *Server, at time.Time) {
	if server == nil {
		return
	}
	if at.IsZero() {
		at = time.Now()
	}
	server.IdentityChangedAt = at.UTC()
	server.LastUsed = time.Time{}
	server.LastSeen = time.Time{}
	server.LastChecked = time.Time{}
	server.LastStatus = ""
}

// ProbeObservation binds a reachability result to the server identity that was
// actually probed so a delayed result cannot be written onto a replaced alias.
type ProbeObservation struct {
	Host       string
	Port       int
	User       string
	Reachable  bool
	ObservedAt time.Time
}

func NewProbeObservation(server *Server, reachable bool, observedAt time.Time) ProbeObservation {
	observation := ProbeObservation{Reachable: reachable, ObservedAt: observedAt.UTC()}
	if server != nil {
		observation.Host = server.Host
		observation.Port = server.Port
		observation.User = server.User
	}
	return observation
}

// RecordSSHUse records a successful authenticated SSH handshake. A successful
// handshake is both a real use and proof that the server was online.
func RecordSSHUse(path, alias string, expected *Server, at time.Time) error {
	if alias == "" {
		return nil
	}
	at = at.UTC()
	return Update(path, func(cfg *Config) error {
		server, ok := cfg.Servers[alias]
		if !ok || server == nil {
			return nil
		}
		if expected != nil && (server.Host != expected.Host || server.Port != expected.Port || server.User != expected.User) {
			return nil
		}
		if server.LastUsed.IsZero() || at.After(server.LastUsed) {
			server.LastUsed = at
		}
		if server.LastSeen.IsZero() || at.After(server.LastSeen) {
			server.LastSeen = at
		}
		if server.LastChecked.IsZero() || !at.Before(server.LastChecked) {
			server.LastChecked = at
			server.LastStatus = StatusOnline
		}
		return nil
	})
}

// RecordProbes records TCP reachability checks without treating a probe as
// actual SSH use. LastSeen advances only for reachable targets.
func RecordProbes(path string, results map[string]ProbeObservation) error {
	if len(results) == 0 {
		return nil
	}
	return Update(path, func(cfg *Config) error {
		for alias, observation := range results {
			at := observation.ObservedAt.UTC()
			if at.IsZero() {
				at = time.Now().UTC()
			}
			server, ok := cfg.Servers[alias]
			if !ok || server == nil {
				continue
			}
			if server.Host != observation.Host || server.Port != observation.Port || server.User != observation.User {
				continue
			}
			if server.LastChecked.IsZero() || !at.Before(server.LastChecked) {
				server.LastChecked = at
				if observation.Reachable {
					server.LastStatus = StatusOnline
				} else {
					server.LastStatus = StatusOffline
				}
			}
			if observation.Reachable {
				if server.LastSeen.IsZero() || at.After(server.LastSeen) {
					server.LastSeen = at
				}
			}
		}
		return nil
	})
}
