#!/usr/bin/env bash

set -euo pipefail

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
JWG_URL="${JWG_URL:-https://github.com/Jipok/jwg/releases/latest/download/jwg}"
AWG_GO_URL="${AWG_GO_URL:-https://raw.githubusercontent.com/Jipok/jwg/refs/heads/master/amneziawg-go}"
COMPLETION_URL="${COMPLETION_URL:-https://raw.githubusercontent.com/Jipok/jwg/refs/heads/master/jwg-completion.bash}"

BIN_DIR="/usr/local/bin"
COMPLETION_DIR="/etc/bash_completion.d"

# Debian/Ubuntu minimal images may not have curl, nftables or iproute2 yet.
if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y curl ca-certificates iproute2 nftables
fi

mkdir -p "$BIN_DIR" /var/lib/jwg
chmod 700 /var/lib/jwg
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

# Download before replacing anything. Rename also permits upgrading a running binary.
echo "Downloading binaries..."
curl -fSL "$AWG_GO_URL" -o "$TMP_DIR/amneziawg-go"
curl -fSL "$JWG_URL" -o "$TMP_DIR/jwg"
for binary in amneziawg-go jwg; do
    install -m 755 "$TMP_DIR/$binary" "$BIN_DIR/$binary.new"
    mv -f "$BIN_DIR/$binary.new" "$BIN_DIR/$binary"
done

echo -e "${GREEN}Binaries successfully installed to $BIN_DIR${NC}"

# 4a. Install bash completion
if [ -d "$COMPLETION_DIR" ]; then
    echo "Installing bash completion..."
    curl -fSL "$COMPLETION_URL" -o "$COMPLETION_DIR/jwg"
    echo -e "${GREEN}Bash completion installed. Re-open your shell or run: source $COMPLETION_DIR/jwg${NC}"
fi

# 4b. Download default domain/IP lists and RU blocklist (never overwrite customized files)
if [ ! -e /var/lib/jwg/proxy.lst ]; then
    echo "Downloading default proxy domain list (proxy.lst)..."
    curl -fSL https://raw.githubusercontent.com/1andrevich/Re-filter-lists/main/domains_all.lst -o "$TMP_DIR/proxy.lst"
    test -s "$TMP_DIR/proxy.lst"
    install -m 600 "$TMP_DIR/proxy.lst" /var/lib/jwg/proxy.lst
fi
if [ ! -e /var/lib/jwg/ips.lst ]; then
    echo "Downloading default preset IP list (ips.lst)..."
    curl -fSL https://raw.githubusercontent.com/Jipok/dnsr/master/ips.lst -o "$TMP_DIR/ips.lst"
    test -s "$TMP_DIR/ips.lst"
    install -m 600 "$TMP_DIR/ips.lst" /var/lib/jwg/ips.lst
fi
if [ ! -e /var/lib/jwg/RU_IPv4.txt ]; then
    echo "Downloading RU IPv4 blocklist (RU_IPv4.txt)..."
    curl -fSL https://country-ip-blocks.hackinggate.com/RU_IPv4.txt -o "$TMP_DIR/RU_IPv4.txt"
    sed -i '/^178\.248\.23/d' "$TMP_DIR/RU_IPv4.txt"
    test -s "$TMP_DIR/RU_IPv4.txt"
    install -m 600 "$TMP_DIR/RU_IPv4.txt" /var/lib/jwg/RU_IPv4.txt
fi

# 5. Check init system. Respect non-systemd distros (Void, Alpine, etc.)
if ! command -v systemctl >/dev/null 2>&1; then
    echo "Notice: systemd is not detected on this system."
    echo "You need to manually configure your init system (runit, OpenRC, etc.) to run:"
    echo "  1. $BIN_DIR/amneziawg-go -f wg0"
    echo "  2. $BIN_DIR/jwg --db /var/lib/jwg/jwg.db"
    echo "  3. $BIN_DIR/jwg --db /var/lib/jwg/jwg.db serve (separate supervised service for split DNS)"
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
WorkingDirectory=/var/lib/jwg
TimeoutStartSec=30

# Restart the VPN daemon automatically if it crashes
Restart=on-failure
RestartSec=3

# Make sure the directory for the database exists
ExecStartPre=/bin/mkdir -p /var/lib/jwg

# Clean up generic tun interfaces gracefully if they were left after a hard crash
ExecStartPre=-/sbin/ip link del wg0

# Start the userspace daemon in the foreground (-f)
# This creates the wg0 interface and keeps the tunnel alive
ExecStart=/usr/local/bin/amneziawg-go -f wg0

# Wait for the wg0 interface to actually appear in the kernel before running jwg.
# Then run jwg to assign IPs, routes, NAT, and rules.
ExecStartPost=/bin/sh -c 'until /sbin/ip link show wg0 >/dev/null 2>&1; do sleep 0.1; done; exec /usr/local/bin/jwg --db /var/lib/jwg/jwg.db'

# Clean up routing/interface on stop
ExecStopPost=-/sbin/ip link del wg0

[Install]
WantedBy=multi-user.target
EOF

# DNS has its own process: restarting it must not interrupt VPN sessions.
cat << 'EOF' > /etc/systemd/system/jwg-dns.service
[Unit]
Description=JWG split-tunnel DNS and traffic statistics
After=network-online.target jwg.service
Wants=network-online.target jwg.service
PartOf=jwg.service

[Service]
Type=notify
TimeoutStartSec=15
WorkingDirectory=/var/lib/jwg
ExecStart=/usr/local/bin/jwg --db /var/lib/jwg/jwg.db serve
Restart=on-failure
RestartSec=3
UMask=0077

[Install]
WantedBy=multi-user.target
EOF

# 7. Enable and restart so upgrades actually use the newly installed binary.
echo "Reloading systemd daemon and enabling jwg.service & jwg-dns.service..."
systemctl daemon-reload
systemctl enable jwg.service jwg-dns.service
systemctl restart jwg.service
systemctl restart jwg-dns.service

# 8. Final success message
echo -e "${GREEN}====================================================${NC}"
echo -e "${GREEN}JWG has been successfully installed and started!${NC}"
echo -e "${GREEN}====================================================${NC}"
echo ""
echo "You can now add your first user by running:"
echo "  jwg add MyPhone           # Full tunnel"
echo "  jwg add MyPhone --split   # Split tunnel (FakeIP DNS)"
echo ""

