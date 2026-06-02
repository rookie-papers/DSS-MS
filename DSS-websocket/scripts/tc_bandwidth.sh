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
if [[ -z "$NET_BANDWIDTH" ]]; then
    echo "Error: NET_BANDWIDTH is undefined in config.env."
    exit 1
fi

# Apply safe default fallbacks for TBF parameters
NET_BURST=${NET_BURST:-"32kbit"}
NET_LATENCY=${NET_LATENCY:-"400ms"}

echo "[Config] Target Interface: $INTERFACE"
echo "[Params] Bandwidth: $NET_BANDWIDTH | Burst: $NET_BURST | Latency: $NET_LATENCY"
echo "----------------------------------------------------------------"
echo "WARNING: This severely limits bandwidth on '$INTERFACE'."
echo "         Large file transfers or heavy SSH usage may stall."
echo "         To reset, use: sudo ./tc_clean.sh"
echo "----------------------------------------------------------------"

# ================= 3. Apply Traffic Control Rules =================
echo "[*] Cleaning old rules..."
tc qdisc del dev $INTERFACE root 2>/dev/null || true

echo "[*] Applying Token Bucket Filter (Bandwidth Limit)..."
tc qdisc add dev $INTERFACE root tbf \
    rate "$NET_BANDWIDTH" \
    burst "$NET_BURST" \
    latency "$NET_LATENCY"

echo "[SUCCESS] Configuration applied. Verify using: tc qdisc show dev $INTERFACE"
