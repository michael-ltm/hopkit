package status

import (
	"context"
	"strconv"
	"strings"

	"github.com/michael-ltm/sshm/internal/config"
	sshpkg "github.com/michael-ltm/sshm/internal/ssh"
)

// Snapshot is a point-in-time view of a remote host.
type Snapshot struct {
	Uptime       string   `json:"uptime,omitempty"`
	Load         string   `json:"load,omitempty"`
	Memory       string   `json:"memory,omitempty"`
	Disk         string   `json:"disk,omitempty"`
	OpenPorts    []string `json:"open_ports,omitempty"`
	FailedLogins int      `json:"failed_logins"`
}

// snapshotScript is the single remote command whose output ParseSnapshot
// consumes. Each section is delimited by an =NAME= marker line.
const snapshotScript = `echo "=UPTIME=" && uptime -p 2>/dev/null || uptime
echo "=LOAD=" && cat /proc/loadavg 2>/dev/null | awk '{print $1, $2, $3}'
echo "=MEM=" && free -h 2>/dev/null | awk '/^Mem:/{print "Mem:", $2, $3, $4}'
echo "=DISK=" && df -h / 2>/dev/null | awk 'NR==2{print $1, $2, $3, $5}'
echo "=PORTS=" && (ss -tlnH 2>/dev/null || netstat -tln 2>/dev/null) | grep -oE ':[0-9]+ ' | tr -d ': ' | sort -un | tr '\n' ' '
echo "=FAILED=" && (grep -c "Failed password" /var/log/auth.log /var/log/secure 2>/dev/null | awk -F: '{s+=$2} END{print s+0}')`

// ParseSnapshot turns the marker-delimited output of snapshotScript into a
// Snapshot. Missing sections leave their fields at the zero value.
func ParseSnapshot(raw string) Snapshot {
	var s Snapshot
	section := ""
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "=") && strings.HasSuffix(trimmed, "=") {
			section = strings.Trim(trimmed, "=")
			continue
		}
		if trimmed == "" {
			continue
		}
		switch section {
		case "UPTIME":
			s.Uptime = trimmed
		case "LOAD":
			s.Load = trimmed
		case "MEM":
			s.Memory = trimmed
		case "DISK":
			s.Disk = trimmed
		case "PORTS":
			s.OpenPorts = strings.Fields(trimmed)
		case "FAILED":
			if n, err := strconv.Atoi(trimmed); err == nil {
				s.FailedLogins = n
			}
		}
	}
	return s
}

// Collect dials the server and runs snapshotScript, returning the parsed
// Snapshot. The caller supplies a context for cancellation/timeout.
func Collect(ctx context.Context, s *config.Server) (Snapshot, error) {
	cli, err := sshpkg.Dial(s, sshpkg.BuildOpts{})
	if err != nil {
		return Snapshot{}, err
	}
	defer cli.Close()
	res, err := cli.Exec(ctx, snapshotScript)
	if err != nil {
		return Snapshot{}, err
	}
	return ParseSnapshot(res.Stdout), nil
}
