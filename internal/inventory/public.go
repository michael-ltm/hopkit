package inventory

import (
	"strconv"
	"strings"
)

// PublicResources is the account-visible resource view requested by the user.
// Mount paths and volume UUIDs stay in the encrypted inventory.
func PublicResources(s *Snapshot) *Snapshot {
	if s == nil {
		return nil
	}
	out := *s
	out.Disks = make([]Disk, len(s.Disks))
	for i, d := range s.Disks {
		out.Disks[i] = d
		out.Disks[i].Mounts = nil
		if strings.Contains(d.ID, "Volume{") {
			out.Disks[i].ID = "volume-" + strconv.Itoa(i)
		}
	}
	return &out
}
