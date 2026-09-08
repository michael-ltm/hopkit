package cloudsync

import (
	"encoding/hex"
	"errors"
	"github.com/michael-ltm/sshm/internal/config"
	"strings"
)

// A reserved .invalid address is a backwards-compatible discriminator: old
// clients preserve it and fail DNS instead of connecting with another identity.
func DeviceServerID(s config.Server) string {
	if s.Auth != config.AuthAgent {
		return ""
	}
	return config.DeviceConnectionID(&s)
}

func (d *Data) AddDevice(device Device, name, description string) (Entry, error) {
	if !validID(device.ID) || device.Kind == "browser" {
		return Entry{}, errors.New("select a native SSHM device")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = device.Label
	}
	if name == "" {
		name = device.ID
	}
	if len(name) > 100 || strings.ContainsAny(name, "\x00\r\n\x1b") {
		return Entry{}, errors.New("device name must be 1-100 characters without control characters")
	}
	s := config.Server{Host: "sshm-device-" + hex.EncodeToString([]byte(device.ID)) + ".invalid", Port: 22, User: "sshm-client", Auth: config.AuthAgent, Label: name, Description: description, Group: device.Group, Tags: device.Tags}
	if err := config.ValidateServerMetadataBounds(s.Label, s.Description, s.Tags, s.Group, s.Notes); err != nil {
		return Entry{}, err
	}
	id := EntryID(s)
	if _, ok := d.Conflicts[id]; ok {
		return Entry{}, errors.New("resolve this device connection conflict before updating it")
	}
	e, exists := d.Entries[id]
	if !exists {
		e = Entry{ID: id, Server: s, CredentialIDs: []string{}, Sources: map[string]Source{}}
	}
	e.Aliases = []string{name}
	e.Server.Label = name
	if !exists || description != "" {
		e.Server.Description = description
	}
	d.Entries[id] = e
	delete(d.Deleted, id)
	if d.Activity == nil {
		d.Activity = map[string]Activity{}
	}
	a := d.Activity[id]
	platform, err := config.NormalizePlatform(device.Platform)
	if err != nil {
		platform = ""
	}
	a.Platform = platform
	a.LastSeen = max(a.LastSeen, device.LastSeen)
	a.SSHMStatus = "installed"
	a.SSHMVersion = device.Version
	a.SSHMCheckedAt = max(a.SSHMCheckedAt, device.LastSeen)
	d.Activity[id] = a
	return e, nil
}
