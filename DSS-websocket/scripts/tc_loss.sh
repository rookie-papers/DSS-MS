#!/bin/bash
set -e

# ================= 0. Permission & Configuration Check =================
if [[ $EUID -ne 0 ]]; then
    echo "Error: Traffic Control requires root privileges. Please run with sudo."
    exit 1
fi

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
CONFIG_FILE="$SCRIPT_DIR/config.env"

if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
else
    echo "Error: Configuration file not found at $CONFIG_FILE"
    exit 1
fi

# ================= 1. Interface Auto-Detection =================
DEFAULT_IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
INTERFACE=${1:-$DEFAULT_IFACE}

if [[ -z "$INTERFACE" ]]; then
    echo "Error: Could not automatically detect the network interface."
    echo "Usage: sudo $0 <interface_name>"
    exit 1
fi

# ================= 2. Parameter Validation =================
if [[ -z "$NET_LOSS" ]]; then
    echo "Error: NET_LOSS is undefined in config.env."
    exit 1
fi

echo "[Config] Target Interface: $INTERFACE"
echo "[Params] Packet Loss Rate: $NET_LOSS"
echo "----------------------------------------------------------------"
echo "WARNING: High packet loss (>10%) may disconnect active SSH sessions!"
echo "         To reset, use: sudo ./tc_clean.sh"
echo "----------------------------------------------------------------"

# ================= 3. Apply Traffic Control Rules =================
echo "[*] Cleaning old rules..."
tc qdisc del dev $INTERFACE root 2>/dev/null || true

echo "[*] Applying Network Emulation (Random Packet Loss)..."
tc qdisc add dev $INTERFACE root netem loss "$NET_LOSS"

echo "[SUCCESS] Configuration applied. Verify using: tc qdisc show dev $INTERFACE"
