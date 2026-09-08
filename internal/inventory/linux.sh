export LC_ALL=C
printf 'SSHM_HW_OS\n'; if [ -r /etc/os-release ]; then sed -n 's/^PRETTY_NAME=//p' /etc/os-release | tr -d '"'; else uname -s; fi
printf 'SSHM_HW_ARCH\n'; uname -m
printf 'SSHM_HW_CPU\n'; awk -F ': ' '/^(model name|Hardware|Model)[[:space:]]*:/ {print $2;exit}' /proc/cpuinfo
printf 'SSHM_HW_THREADS\n'; getconf _NPROCESSORS_ONLN
printf 'SSHM_HW_CORES\n'; lscpu -p=SOCKET,CORE 2>/dev/null | awk '!/^#/ && NF {a[$0]=1} END {for (i in a)n++;print n}'
printf 'SSHM_HW_MEM\n'; cat /proc/meminfo
printf 'SSHM_HW_DISKS\n'; lsblk -b -J -o NAME,TYPE,SIZE,MODEL,FSTYPE,MOUNTPOINTS 2>/dev/null || lsblk -b -J -o NAME,TYPE,SIZE,MODEL,FSTYPE,MOUNTPOINT 2>/dev/null
printf '\nSSHM_HW_DF\n'; df -kP 2>/dev/null
printf '\nSSHM_HW_END\n'
