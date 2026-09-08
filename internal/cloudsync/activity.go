package cloudsync

import (
	"github.com/michael-ltm/sshm/internal/config"
	"github.com/michael-ltm/sshm/internal/inventory"
	"reflect"
	"time"
)

// Activity is encrypted observational metadata, merged independently of edits
// so routine connections do not create server-edit conflicts.
type Activity struct {
	Hardware      *inventory.Snapshot `json:"hardware,omitempty"`
	SSHMStatus    string              `json:"sshm_status,omitempty"`
	SSHMVersion   string              `json:"sshm_version,omitempty"`
	SSHMCheckedAt int64               `json:"sshm_checked_at,omitempty"`
	SSHCheckedAt  int64               `json:"ssh_checked_at,omitempty"`
	SSHError      string              `json:"ssh_error,omitempty"`
	Status        string              `json:"status,omitempty"`
	Platform      string              `json:"platform,omitempty"`
	LastConnected int64               `json:"last_connected,omitempty"`
	LastSeen      int64               `json:"last_seen,omitempty"`
	CheckedAt     int64               `json:"checked_at,omitempty"`
}

func activityTime(t time.Time) int64 {
	if t.UnixMilli() <= 0 || t.After(time.Now().Add(24*time.Hour)) {
		return 0
	}
	return t.UnixMilli()
}
func mergeActivity(a, b Activity) Activity {
	a.Hardware = inventory.Newer(a.Hardware, b.Hardware)
	if b.Platform != "" && (a.Platform == "" || b.CheckedAt > a.CheckedAt || (b.CheckedAt == a.CheckedAt && b.Platform > a.Platform)) {
		a.Platform = b.Platform
	}
	if b.SSHCheckedAt > a.SSHCheckedAt || (b.SSHCheckedAt == a.SSHCheckedAt && b.SSHError > a.SSHError) {
		a.SSHCheckedAt = b.SSHCheckedAt
		a.SSHError = b.SSHError
	}
	if b.CheckedAt > a.CheckedAt || (b.CheckedAt == a.CheckedAt && b.Status > a.Status) {
		a.Status = b.Status
	}
	if b.SSHMCheckedAt > a.SSHMCheckedAt || (b.SSHMCheckedAt == a.SSHMCheckedAt && b.SSHMVersion > a.SSHMVersion) {
		a.SSHMCheckedAt = b.SSHMCheckedAt
		a.SSHMStatus = b.SSHMStatus
		a.SSHMVersion = b.SSHMVersion
	}
	a.LastConnected = max(a.LastConnected, b.LastConnected)
	a.LastSeen = max(a.LastSeen, b.LastSeen)
	a.CheckedAt = max(a.CheckedAt, b.CheckedAt)
	return a
}
func (d *Data) ImportActivity(cfg *config.Config) bool {
	if d.Activity == nil {
		d.Activity = map[string]Activity{}
	}
	changed := false
	for _, server := range cfg.Servers {
		if server == nil {
			continue
		}
		id := EntryID(cleanServer(*server))
		if server.CloudEntry != "" {
			id = server.CloudEntry
		}
		if _, ok := d.Entries[id]; !ok {
			continue
		}
		before := d.Activity[id]
		next := mergeActivity(before, Activity{Hardware: server.Hardware, Platform: server.Platform, LastConnected: activityTime(server.LastUsed), LastSeen: activityTime(server.LastSeen), CheckedAt: activityTime(server.LastChecked), Status: server.LastStatus, SSHCheckedAt: activityTime(server.LastSSHChecked), SSHError: server.LastSSHError, SSHMStatus: server.SSHMStatus, SSHMVersion: server.SSHMVersion, SSHMCheckedAt: activityTime(server.SSHMCheckedAt)})
		if !reflect.DeepEqual(before, next) {
			d.Activity[id] = next
			changed = true
		}
	}
	return changed
}
