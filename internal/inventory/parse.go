package inventory

import (
	"encoding/json"
	"regexp"
	"strings"
)

type block struct {
	Name        string          `json:"name"`
	Type        string          `json:"type"`
	Size        json.RawMessage `json:"size"`
	Model       string          `json:"model"`
	FSType      string          `json:"fstype"`
	Mountpoint  string          `json:"mountpoint"`
	Mountpoints []string        `json:"mountpoints"`
	Children    []block         `json:"children"`
}

func parseLinux(s *Snapshot, parts map[string]string) {
	mem := map[string]uint64{}
	for _, l := range strings.Split(parts["MEM"], "\n") {
		f := strings.Fields(l)
		if len(f) >= 2 {
			mem[strings.TrimSuffix(f[0], ":")] = number(f[1]) * 1024
		}
	}
	s.MemoryTotal = mem["MemTotal"]
	if n, ok := mem["MemAvailable"]; ok {
		s.MemoryAvailable = pointer(n)
	}
	var b struct {
		Blocks []block `json:"blockdevices"`
	}
	if json.Unmarshal([]byte(parts["DISKS"]), &b) != nil {
		s.Notes = append(s.Notes, "disks_unavailable")
		return
	}
	seen := map[string]bool{}
	var visit func(block, string)
	visit = func(b block, parent string) {
		if b.Type == "loop" || b.Type == "rom" {
			return
		}
		id := "/dev/" + b.Name
		if !seen[id] {
			seen[id] = true
			mounts := []string{}
			for _, m := range b.Mountpoints {
				if m != "" {
					mounts = append(mounts, m)
				}
			}
			if len(mounts) == 0 && b.Mountpoint != "" {
				mounts = append(mounts, b.Mountpoint)
			}
			kind := b.Type
			if kind == "part" {
				kind = "partition"
			}
			s.Disks = append(s.Disks, Disk{ID: id, Parent: parent, Kind: kind, Model: strings.TrimSpace(b.Model), Total: number(string(b.Size)), Filesystem: b.FSType, Mounts: mounts})
		}
		for _, c := range b.Children {
			visit(c, id)
		}
	}
	for _, d := range b.Blocks {
		visit(d, "")
	}
}
func parseMac(s *Snapshot, parts map[string]string) {
	s.MemoryTotal = number(strings.TrimSpace(parts["MEM"]))
	// Free + inactive + speculative is reclaimable memory, not pressure or RSS.
	page := uint64(0)
	m := regexp.MustCompile(`page size of (\d+) bytes`).FindStringSubmatch(parts["VM"])
	if len(m) == 2 {
		page = number(m[1])
	}
	available := uint64(0)
	for _, line := range strings.Split(parts["VM"], "\n") {
		f := strings.SplitN(line, ":", 2)
		if len(f) == 2 && (f[0] == "Pages free" || f[0] == "Pages inactive" || f[0] == "Pages speculative") {
			available += number(f[1])
		}
	}
	if page > 0 {
		s.MemoryAvailable = pointer(available * page)
	}
	type macDisk struct {
		DeviceIdentifier string
		Content          string
		Size             uint64
		MountPoint       string
		Partitions       []struct {
			DeviceIdentifier string
			Content          string
			Size             uint64
			MountPoint       string
		}
	}
	var list struct{ AllDisksAndPartitions []macDisk }
	if json.Unmarshal([]byte(parts["DISKS"]), &list) != nil {
		s.Notes = append(s.Notes, "disks_unavailable")
	}
	for _, d := range list.AllDisksAndPartitions {
		s.Disks = append(s.Disks, Disk{ID: "/dev/" + d.DeviceIdentifier, Kind: "disk", Total: d.Size})
		for _, p := range d.Partitions {
			v := Disk{ID: "/dev/" + p.DeviceIdentifier, Parent: "/dev/" + d.DeviceIdentifier, Kind: "partition", Total: p.Size, Filesystem: p.Content}
			if p.MountPoint != "" {
				v.Mounts = []string{p.MountPoint}
			}
			s.Disks = append(s.Disks, v)
		}
	}
	var apfs struct {
		Containers []struct {
			ContainerReference string
			CapacityCeiling    uint64
			CapacityFree       uint64
			Volumes            []struct {
				DeviceIdentifier string
				CapacityInUse    uint64
				MountPoint       string
			}
		}
	}
	if json.Unmarshal([]byte(parts["APFS"]), &apfs) != nil {
		s.Notes = append(s.Notes, "apfs_unavailable")
	} else {
		for _, c := range apfs.Containers {
			s.Disks = append(s.Disks, Disk{ID: "/dev/" + c.ContainerReference, Kind: "container", Filesystem: "APFS", Total: c.CapacityCeiling, Free: pointer(c.CapacityFree)})
			for _, v := range c.Volumes {
				d := Disk{ID: "/dev/" + v.DeviceIdentifier, Parent: "/dev/" + c.ContainerReference, Kind: "volume", Filesystem: "APFS"}
				if v.MountPoint != "" {
					d.Mounts = []string{v.MountPoint}
				}
				s.Disks = append(s.Disks, d)
			}
		}
	}
}
func parseDF(s *Snapshot, raw string) {
	for _, line := range strings.Split(raw, "\n") {
		f := strings.Fields(line)
		if len(f) < 6 || number(f[1]) == 0 {
			continue
		}
		id := f[0]
		mount := strings.Join(f[5:], " ")
		index := -1
		for i, d := range s.Disks {
			if d.ID == id {
				index = i
				break
			}
			for _, m := range d.Mounts {
				if m == mount {
					index = i
					break
				}
			}
			if index >= 0 {
				break
			}
		}
		if index < 0 {
			if !strings.HasPrefix(id, "/dev/") && id != "overlay" {
				continue
			}
			s.Disks = append(s.Disks, Disk{ID: id, Kind: "volume"})
			index = len(s.Disks) - 1
		}
		d := &s.Disks[index]
		if len(d.Mounts) == 0 {
			d.Mounts = []string{mount}
		}
		if d.Kind != "disk" {
			d.Total = number(f[1]) * 1024
		}
		d.Free = pointer(number(f[3]) * 1024)
	}
}
