package config

import (
	"fmt"
	"strings"
)

// ServerRemovalError describes why a configured server cannot be removed.
// ProjectProfiles and ProxyJumpServers are sorted so callers get stable,
// actionable diagnostics regardless of map iteration order.
type ServerRemovalError struct {
	Alias            string
	NotFound         bool
	ProjectProfiles  []string
	ProxyJumpServers []string
}

func (e *ServerRemovalError) Error() string {
	if e == nil {
		return "server removal failed"
	}
	if e.NotFound {
		return fmt.Sprintf("unknown server %q", e.Alias)
	}

	references := make([]string, 0, 2)
	if len(e.ProjectProfiles) > 0 {
		references = append(references, "project profiles: "+strings.Join(e.ProjectProfiles, ", "))
	}
	if len(e.ProxyJumpServers) > 0 {
		references = append(references, "servers using it as ProxyJump: "+strings.Join(e.ProxyJumpServers, ", "))
	}
	return fmt.Sprintf("server %q cannot be removed; references remain (%s); update those references first", e.Alias, strings.Join(references, "; "))
}

// CheckServerRemoval verifies that alias exists and has no project or
// ProxyJump dependants. Call it again inside the same config.Update callback
// that performs deletion; an earlier UI/preflight snapshot can become stale.
func CheckServerRemoval(cfg *Config, alias string) error {
	if cfg == nil {
		return &ServerRemovalError{Alias: alias, NotFound: true}
	}
	if _, ok := cfg.Servers[alias]; !ok {
		return &ServerRemovalError{Alias: alias, NotFound: true}
	}

	projects := ProjectsUsingServer(cfg, alias)
	proxyJumpServers := ServersUsingProxyJump(cfg, alias)
	if len(projects) == 0 && len(proxyJumpServers) == 0 {
		return nil
	}
	return &ServerRemovalError{
		Alias:            alias,
		ProjectProfiles:  projects,
		ProxyJumpServers: proxyJumpServers,
	}
}

// RemoveServer removes one unreferenced server from an in-memory config. It
// must be called from config.Update so validation and deletion share the same
// locked snapshot.
func RemoveServer(cfg *Config, alias string) error {
	if err := CheckServerRemoval(cfg, alias); err != nil {
		return err
	}
	delete(cfg.Servers, alias)
	if cfg.Default == alias {
		cfg.Default = ""
	}
	return nil
}
