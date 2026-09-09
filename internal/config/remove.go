package config

import (
	"fmt"
	"strings"
)

// ServerRemovalError describes why a configured server cannot be removed.
// ProxyJumpServers is sorted so callers get stable, actionable diagnostics
// regardless of map iteration order.
type ServerRemovalError struct {
	Alias            string
	NotFound         bool
	ProxyJumpServers []string
}

func (e *ServerRemovalError) Error() string {
	if e == nil {
		return "server removal failed"
	}
	if e.NotFound {
		return fmt.Sprintf("unknown server %q", e.Alias)
	}
	return fmt.Sprintf("server %q cannot be removed; servers using it as ProxyJump: %s; update those references first", e.Alias, strings.Join(e.ProxyJumpServers, ", "))
}

// CheckServerRemoval verifies that alias exists and no other server uses it as
// a ProxyJump. Project profiles no longer block removal; RemoveServer clears
// any project that pointed at the removed server. Call CheckServerRemoval again
// inside the same config.Update callback that performs deletion; an earlier
// UI/preflight snapshot can become stale.
func CheckServerRemoval(cfg *Config, alias string) error {
	if cfg == nil {
		return &ServerRemovalError{Alias: alias, NotFound: true}
	}
	if _, ok := cfg.Servers[alias]; !ok {
		return &ServerRemovalError{Alias: alias, NotFound: true}
	}

	proxyJumpServers := ServersUsingProxyJump(cfg, alias)
	if len(proxyJumpServers) == 0 {
		return nil
	}
	return &ServerRemovalError{Alias: alias, ProxyJumpServers: proxyJumpServers}
}

// RemoveServer removes one server from an in-memory config and clears any
// project profile that referenced it. It must be called from config.Update so
// validation and deletion share the same locked snapshot.
func RemoveServer(cfg *Config, alias string) error {
	if err := CheckServerRemoval(cfg, alias); err != nil {
		return err
	}
	delete(cfg.Servers, alias)
	for _, project := range cfg.Projects {
		if project != nil && project.Server == alias {
			project.Server = ""
		}
	}
	if cfg.Default == alias {
		cfg.Default = ""
	}
	return nil
}
