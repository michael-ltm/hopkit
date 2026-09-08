package ssh

import (
	"context"
	"errors"
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/inventory"
)

func (c *Client) DetectHardware(ctx context.Context, platform string) *inventory.Snapshot {
	command := inventory.Command(platform)
	if command == "" {
		return inventory.Parse(platform, "", errors.New("unsupported OS"))
	}
	out, err := c.observationCommand(ctx, command, true)
	return inventory.Parse(platform, out, err)
}
func RecordHardware(path, alias string, expected *config.Server, h *inventory.Snapshot) error {
	if !h.Valid() {
		return errors.New("invalid hardware observation")
	}
	return config.Update(path, func(cfg *config.Config) error {
		s := cfg.Servers[alias]
		if s != nil && expected != nil && s.Host == expected.Host && s.Port == expected.Port && s.User == expected.User && s.Auth == expected.Auth && s.ProxyJump == expected.ProxyJump && s.ProxyCommand == expected.ProxyCommand && s.Proxy == expected.Proxy {
			s.Hardware = inventory.Newer(s.Hardware, h)
		}
		return nil
	})
}
