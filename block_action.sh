#!/bin/bash
# Usage: sudo ./block_action.sh 1.2.3.4
IP=$1
if [ -z "$IP" ]; then
  echo "usage: $0 <ip>"
  exit 1
fi
sudo iptables -I INPUT -s $IP -j DROP
echo "Blocked $IP"
