#!/bin/bash
while true; do
    ls -la /home
    ls -la /etc
    cat /etc/os-release
    whoami
    id
    df -h
    ps aux > /dev/null
    sudo ls /root 2>/dev/null
    echo "Baseline cycle complete - $(date)"
    sleep $((RANDOM % 600 + 600))  # sleeps between 10-20 minutes randomly
done