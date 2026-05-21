package status

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseSnapshot_ExtractsAllFields(t *testing.T) {
	raw := `=UPTIME=
up 3 days, 4 hours
=LOAD=
0.15 0.20 0.18
=MEM=
Mem: 1.8Gi 900Mi 1.0Gi
=DISK=
/dev/vda1 40G 13G 34%
=PORTS=
22 80 443 3306
=FAILED=
12
`
	s := ParseSnapshot(raw)
	require.Equal(t, "up 3 days, 4 hours", s.Uptime)
	require.Equal(t, "0.15 0.20 0.18", s.Load)
	require.Equal(t, "Mem: 1.8Gi 900Mi 1.0Gi", s.Memory)
	require.Equal(t, "/dev/vda1 40G 13G 34%", s.Disk)
	require.Equal(t, []string{"22", "80", "443", "3306"}, s.OpenPorts)
	require.Equal(t, 12, s.FailedLogins)
}

func TestParseSnapshot_ToleratesMissingSections(t *testing.T) {
	s := ParseSnapshot("=UPTIME=\nup 1 hour\n")
	require.Equal(t, "up 1 hour", s.Uptime)
	require.Empty(t, s.OpenPorts)
	require.Equal(t, 0, s.FailedLogins)
}
