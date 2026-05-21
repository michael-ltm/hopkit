package safety

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsDangerous_BlocksKnownPatterns(t *testing.T) {
	dangerous := []string{
		"rm -rf /",
		"rm -rf /*",
		"rm -rf ~",
		"sudo rm -rf  /  ",
		"mkfs.ext4 /dev/sda",
		"dd if=/dev/zero of=/dev/sda",
		":(){ :|:& };:",
		"chmod -R 000 /",
		"echo x > /dev/sda",
		"rm -fr /",
		"/bin/rm -rf /",
		"rm -rf ~/",
		"rm -Rf /",
	}
	for _, cmd := range dangerous {
		hit, reason := IsDangerous(cmd)
		require.True(t, hit, "expected %q to be flagged", cmd)
		require.NotEmpty(t, reason)
	}
}

func TestIsDangerous_AllowsNormalCommands(t *testing.T) {
	safe := []string{
		"ls -la",
		"systemctl restart nginx",
		"rm -rf /tmp/build-cache",
		"docker compose up -d",
		"df -h",
		"tail -n 100 /var/log/app.log",
	}
	for _, cmd := range safe {
		hit, _ := IsDangerous(cmd)
		require.False(t, hit, "expected %q to be allowed", cmd)
	}
}
