export LC_ALL=C
printf 'SSHM_HW_OS\n'; printf 'macOS '; sw_vers -productVersion
printf 'SSHM_HW_ARCH\n'; uname -m
printf 'SSHM_HW_CPU\n'; sysctl -n machdep.cpu.brand_string
printf 'SSHM_HW_THREADS\n'; sysctl -n hw.logicalcpu
printf 'SSHM_HW_CORES\n'; sysctl -n hw.physicalcpu
printf 'SSHM_HW_MEM\n'; sysctl -n hw.memsize
printf 'SSHM_HW_VM\n'; vm_stat
printf 'SSHM_HW_DISKS\n'; diskutil list -plist physical 2>/dev/null | plutil -convert json -o - -- -
printf '\nSSHM_HW_APFS\n'; diskutil apfs list -plist 2>/dev/null | plutil -convert json -o - -- -
printf '\nSSHM_HW_DF\n'; df -kP -l 2>/dev/null
printf '\nSSHM_HW_END\n'
