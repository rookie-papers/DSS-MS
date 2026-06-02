#!/bin/bash
set -e

if [[ $EUID -ne 0 ]]; then
    echo "Error: Cleaning rules requires root privileges. Please run with sudo."
    exit 1
fi

DEFAULT_IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
INTERFACE=${1:-$DEFAULT_IFACE}

if [[ -z "$INTERFACE" ]]; then
    echo "Error: Could not automatically detect the network interface."
    echo "Usage: sudo $0 <interface_name>"
    exit 1
fi

echo "[*] Removing all Traffic Control rules on interface: $INTERFACE ..."

# Delete the root qdisc, suppressing errors if no rules existed
tc qdisc del dev $INTERFACE root 2>/dev/null || true

echo "[SUCCESS] Interface $INTERFACE is now back to full native speed."
