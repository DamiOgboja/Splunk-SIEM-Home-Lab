#!/bin/bash
while true; do
    ifconfig
    ping 8.8.8.8 -c 4
    ls -la /opt
    whoami
    uname -a
    df -h
    ps aux > /dev/null
    echo "Baseline cycle complete - $(date)"
    sleep $((RANDOM % 600 + 600))  # sleeps between 10-20 minutes randomly
done