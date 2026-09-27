package localservice

import (
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/michael-ltm/sshm/internal/localstore"
)

type SyncStatus struct {
	State     string `json:"state"`
	CheckedAt int64  `json:"checked_at,omitempty"`
}

func syncStatusPath(path string) string {
	return localstore.New(path).ConfigPath + ".local/sync-status.json"
}
func validSyncState(state string) bool {
	switch state {
	case "ready", "offline", "sign_in_required", "locked", "not_configured", "migration_required", "device_unavailable", "verification_failed", "sync_failed", "conflict":
		return true
	}
	return false
}

// RecordSyncStatus accepts only fixed codes. Provider/cloud response text,
// endpoint URLs and credential bytes never enter status files or MCP output.
func RecordSyncStatus(path, state string) error {
	if !validSyncState(state) {
		return errors.New("invalid sync state")
	}
	data, _ := json.Marshal(SyncStatus{State: state, CheckedAt: time.Now().UnixMilli()})
	return privateWrite(syncStatusPath(path), data)
}
func readSyncStatus(path string) SyncStatus {
	f, err := os.Open(syncStatusPath(path))
	if err != nil {
		return SyncStatus{State: "not_started"}
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > 1024 {
		return SyncStatus{State: "unknown"}
	}
	var status SyncStatus
	if json.NewDecoder(f).Decode(&status) != nil || !validSyncState(status.State) {
		return SyncStatus{State: "unknown"}
	}
	return status
}
