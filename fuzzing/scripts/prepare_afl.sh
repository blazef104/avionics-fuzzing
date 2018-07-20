#! /bin/sh

echo "if not working run as root (not with sudo)"
echo core >/proc/sys/kernel/core_pattern
cd /sys/devices/system/cpu
echo performance | tee cpu*/cpufreq/scaling_governor
echo "done"
