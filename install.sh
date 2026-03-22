#!/usr/bin/env bash

set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# 1. Require root privileges
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root. Try: sudo $0${NC}"
    exit 1
fi

echo "Starting JWG installation..."

# 2. Define download URLs (assumes architecture is AMD64, adjust if multi-arch is needed)
JWG_URL="https://github.com/Jipok/jwg/releases/latest/download/jwg"
AWG_GO_URL="https://raw.githubusercontent.com/Jipok/jwg/refs/heads/master/amneziawg-go"
COMPLETION_URL="https://raw.githubusercontent.com/Jipok/jwg/refs/heads/master/jwg-completion.bash"

BIN_DIR="/usr/local/bin"
COMPLETION_DIR="/etc/bash_completion.d"

# 3. Download binaries
echo "Downloading amneziawg-go (userspace daemon)..."
curl -sL "$AWG_GO_URL" -o "$BIN_DIR/amneziawg-go"

echo "Downloading jwg (CLI manager)..."
curl -sL "$JWG_URL" -o "$BIN_DIR/jwg"

# 4. Make binaries executable
chmod +x "$BIN_DIR/amneziawg-go"
chmod +x "$BIN_DIR/jwg"

echo -e "${GREEN}Binaries successfully installed to $BIN_DIR${NC}"

# 4a. Install bash completion
if [ -d "$COMPLETION_DIR" ]; then
    echo "Installing bash completion..."
    curl -sL "$COMPLETION_URL" -o "$COMPLETION_DIR/jwg"
    echo -e "${GREEN}Bash completion installed. Re-open your shell or run: source $COMPLETION_DIR/jwg${NC}"
fi

# 5. Check init system. Respect non-systemd distros (Void, Alpine, etc.)
if ! command -v systemctl >/dev/null 2>&1; then
    echo "Notice: systemd is not detected on this system."
    echo "You need to manually configure your init system (runit, OpenRC, etc.) to run:"
    echo "  1. $BIN_DIR/amneziawg-go -f wg0"
    echo "  2. $BIN_DIR/jwg"
    exit 0
fi

# 6. Create systemd unit file
SERVICE_PATH="/etc/systemd/system/jwg.service"

echo "Creating systemd unit at $SERVICE_PATH..."
cat << 'EOF' > "$SERVICE_PATH"
[Unit]
Description=JWG (AmneziaWG/WireGuard Manager)
After=network-online.target nss-lookup.target
Wants=network-online.target

[Service]
# 'simple' means systemd tracks the foreground process directly
Type=simple

# Restart the VPN daemon automatically if it crashes
Restart=on-failure
RestartSec=3

# Make sure the directory for the database exists
ExecStartPre=/bin/mkdir -p /var/lib/jwg

# Clean up generic tun interfaces gracefully if they were left after a hard crash
ExecStartPre=-/sbin/ip link del wg0 2>/dev/null

# Start the userspace daemon in the foreground (-f)
# This creates the wg0 interface and keeps the tunnel alive
ExecStart=/usr/local/bin/amneziawg-go -f wg0

# Wait for the wg0 interface to actually appear in the kernel before running jwg.
# Then run jwg to assign IPs, routes, NAT, and rules.
ExecStartPost=/bin/sh -c 'until /sbin/ip link show wg0 >/dev/null 2>&1; do sleep 0.1; done; /usr/local/bin/jwg'

# Clean up routing/interface on stop
ExecStopPost=-/sbin/ip link del wg0 2>/dev/null

[Install]
WantedBy=multi-user.target
EOF

# 7. Enable and start the service
echo "Reloading systemd daemon and enabling jwg.service..."
systemctl daemon-reload
systemctl enable --now jwg.service

# 8. Final success message
echo -e "${GREEN}====================================================${NC}"
echo -e "${GREEN}JWG has been successfully installed and started!${NC}"
echo -e "${GREEN}====================================================${NC}"
echo ""
echo "You can now add your first user by running:"
echo "  jwg add MyPhone"
echo ""

