package cloudsync

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// Only counts and sync time are kept here. Credentials and vault contents remain encrypted.
type InventorySummary struct {
	Identity string `json:"identity"`
	Revision int64  `json:"revision"`
	Count    int    `json:"count"`
	Synced   int64  `json:"synced"`
}

func summaryPath(path string) string {
	return filepath.Join(filepath.Dir(StatePath(path)), "inventory-summary.json")
}
func writeInventorySummary(path string, s *State, d Data) error {
	count := 0
	for id := range d.Entries {
		if !d.Deleted[id] {
			count++
		}
	}
	b, e := json.Marshal(InventorySummary{InventoryIdentity(s), s.Base.Revision, count, time.Now().UnixMilli()})
	if e != nil {
		return e
	}
	return WritePrivate(summaryPath(path), b)
}
func ReadInventorySummary(path string, s *State) (InventorySummary, bool) {
	var v InventorySummary
	b, e := os.ReadFile(summaryPath(path))
	if e != nil || json.Unmarshal(b, &v) != nil {
		return v, false
	}
	return v, v.Identity == InventoryIdentity(s) && v.Revision == s.Base.Revision && v.Count >= 0
}
