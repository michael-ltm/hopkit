package inventory

import (
	"context"
	"errors"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

func TestLinuxMultiDisk(t *testing.T) {
	raw := `SSHM_HW_OS
Test Linux
SSHM_HW_CPU
CPU model
SSHM_HW_THREADS
8
SSHM_HW_MEM
MemTotal: 8192 kB
MemAvailable: 0 kB
SSHM_HW_DISKS
{"blockdevices":[{"name":"sda","type":"disk","size":100000,"children":[{"name":"sda1","type":"part","size":"90000","mountpoints":["/","/extra"]}]},{"name":"sdb","type":"disk","size":200000},{"name":"loop0","type":"loop","size":100}]}
SSHM_HW_DF
/dev/sda1 80 70 10 87% /
`
	s := Parse("linux", raw, nil)
	require.Equal(t, "ok", s.Status)
	require.Len(t, s.Disks, 3)
	require.Equal(t, uint64(200000), s.Disks[2].Total)
	require.Empty(t, s.Disks[2].Mounts)
	require.Nil(t, s.Disks[2].Free)
	require.Equal(t, uint64(0), *s.MemoryAvailable)
	require.Equal(t, []string{"/", "/extra"}, s.Disks[1].Mounts)
	require.Equal(t, uint64(10240), *s.Disks[1].Free)
}
func TestMacAPFSSharedCapacity(t *testing.T) {
	raw := `SSHM_HW_OS
macOS test
SSHM_HW_CPU
Apple test
SSHM_HW_MEM
8192
SSHM_HW_DISKS
{"AllDisksAndPartitions":[{"DeviceIdentifier":"disk0","Size":100000,"Partitions":[{"DeviceIdentifier":"disk0s1","Size":99000,"Content":"Apple_APFS"}]}]}
SSHM_HW_APFS
{"Containers":[{"ContainerReference":"disk3","CapacityCeiling":99000,"CapacityFree":10000,"Volumes":[{"DeviceIdentifier":"disk3s1","MountPoint":"/"},{"DeviceIdentifier":"disk3s2","MountPoint":"/System/Volumes/Data"}]}]}
`
	s := Parse("darwin", raw, nil)
	require.Len(t, s.Disks, 5)
	physical := uint64(0)
	for _, d := range s.Disks {
		if d.Kind == "disk" {
			physical += d.Total
		}
	}
	require.Equal(t, uint64(100000), physical)
	require.Equal(t, "container", s.Disks[2].Kind)
	require.Equal(t, uint64(0), s.Disks[3].Total)
	require.Equal(t, "/dev/disk3", s.Disks[4].Parent)
}
func TestWindowsVolumeWithoutDriveLetter(t *testing.T) {
	s := Parse("windows", `{"os":"Windows","cpu":"CPU","memory_total":8192,"disks":[{"id":"disk0","kind":"disk","total":10000},{"id":"disk1","kind":"disk","total":20000},{"id":"volume-guid","kind":"volume","total":8000,"free":0,"mounts":[]}]}`, nil)
	require.Equal(t, "ok", s.Status)
	require.Len(t, s.Disks, 3)
	require.NotNil(t, s.Disks[2].Free)
	require.Equal(t, uint64(0), *s.Disks[2].Free)
}
func TestFailedRefreshKeepsSampleAndReportsFailure(t *testing.T) {
	a := &Snapshot{CheckedAt: 100, Status: "ok", CPU: "model"}
	b := &Snapshot{CheckedAt: 200, Status: "unavailable"}
	out := Newer(a, b)
	require.Equal(t, int64(100), out.CheckedAt)
	require.Equal(t, int64(200), out.AttemptedAt)
	require.True(t, out.RefreshFailed)
	require.False(t, a.RefreshFailed)
	require.Same(t, out, Newer(out, b))
	require.Same(t, out, Newer(out, a))
	require.Equal(t, "unavailable", Parse("linux", "bad", errors.New("timeout")).Status)
	require.Equal(t, "unavailable", Parse("windows", "bad", nil).Status)
}
func TestOutputBoundRejectsTruncation(t *testing.T) {
	var out Output
	_, err := out.Write(make([]byte, MaxOutput+1))
	require.Error(t, err)
	require.Zero(t, out.Len())
}
func TestLocalHardwareAcceptance(t *testing.T) {
	if os.Getenv("SSHM_HARDWARE_ACCEPTANCE") == "" {
		t.Skip("live local hardware not requested")
	}
	s := Collect(context.Background())
	require.True(t, s.Valid())
	require.NotEqual(t, "unavailable", s.Status)
	require.NotEmpty(t, s.OS)
	require.Positive(t, s.MemoryTotal)
	require.NotEmpty(t, s.Disks)
	t.Logf("OS=%s CPU=%s threads=%d RAM=%d records=%d status=%s notes=%v", s.OS, s.CPU, s.Threads, s.MemoryTotal, len(s.Disks), s.Status, s.Notes)
}
