# JWG

**The lightweight CLI manager for WireGuard and AmneziaWG.**

Most WireGuard tools fall into two extremes: manual config editing or heavy web UIs that require Docker, PostgreSQL, and a browser.

`jwg` is a single-binary CLI that handles the entire lifecycle of your VPN server: networking, keys, firewall rules, and peer management automatically. It doesn't need a database server or a web panel—it just works.

Crucially, it is compatible with **AmneziaWG-go**.

---

## ✨ Why jwg?

*   **👻 AmneziaWG Ready:** Designed to work seamlessly with `amneziawg-go` and `wireguard-go` interfaces, not just kernel modules.
*   **🎯 Server-Side Split Tunneling:** Route only blocked domains through the VPN (FakeIP + kernel `nftables` DNAT) while domestic traffic goes direct—works even on iOS and simple clients.
*   **🚫 No Web UI Needed:** Forget about `docker-compose`, databases, or opening HTTP ports.
*   **🔋 Battery Included:** Handles **NAT**, **Packet Forwarding**, Anti-Bufferbloat (Smart QoS), and **Firewall** (nftables & UFW) automatically. You don't need to be a Linux network engineer to set this up.
*   **📱 QR Codes in Terminal:** Generate configs and display QR codes directly in the console.
*   **📂 Embedded Database:** Stores configurations and peers in a single `jwg.db` file. Zero external dependencies.

---

## 🚀 Installation & Quick Start

### 1. Installation

**Recommended: Automatic Installation**  
Installs the required binaries, preset domain/IP lists (`proxy.lst`, `ips.lst`, `RU_IPv4.txt`), sets up systemd services for AmneziaWG and FakeIP DNS, and starts the VPN automatically.
```bash
curl -sL https://raw.githubusercontent.com/Jipok/jwg/master/install.sh | sudo bash
```

<details>
<summary><b>Alternative: Manual / Wireguard Setup</b> (Click to expand)</summary>

`jwg` creates a missing kernel interface automatically: `awg0` for AmneziaWG when its module is available, otherwise `wg0` for WireGuard. Install the module and headers matching your **running kernel** first.

For a **userspace** backend, start its daemon before running `jwg`:
```bash
wget https://raw.githubusercontent.com/Jipok/jwg/refs/heads/master/amneziawg-go
chmod +x amneziawg-go
./amneziawg-go wg0
```

**Initialize JWG Server:**
Run `jwg` for the first time. It will auto-detect your Public IP, auto-assign a random secure port, bring the interface up, and apply necessary firewall rules.
```bash
wget https://github.com/Jipok/jwg/releases/latest/download/jwg
chmod +x jwg
./jwg
```
</details>

### 2. Add a Client
Once installed and running, just add a new peer. `jwg` will find the next available IP, generate keys, and sync the interface on the fly.

```bash
jwg add phone           # Full tunnel (all traffic via VPN)
jwg add phone --split   # Split tunnel (only domains from proxy.lst + IPs from ips.lst)
```
*The output matches the standard client config format and includes a QR code right in your terminal.*

---

## 🎯 Server-Side Split Tunneling (FakeIP)

Standard WireGuard clients (especially on iOS) don't support domain-based routing. `jwg serve` solves this on the server side without Docker or userspace proxies:

1. The client uses the VPN server (`10.8.0.1`) as its DNS and routes only `198.18.0.0/15` + `ips.lst` into the tunnel.
2. Normal domains resolve to their **real IPs** and go directly through the ISP.
3. Domains matching `/var/lib/jwg/proxy.lst` (including via CNAME chains) resolve to a virtual IP from `198.18.0.0/15`, which the Linux kernel transparently DNATs back to the real IP inside `nftables`.

Full-tunnel and `--split` clients can coexist on the same interface.

```bash
# Update domain & IP lists manually
sudo wget -qO /var/lib/jwg/proxy.lst https://github.com/1andrevich/Re-filter-lists/raw/refs/heads/main/domains_all.lst
sudo wget -qO /var/lib/jwg/ips.lst https://github.com/Jipok/dnsr/raw/refs/heads/master/ips.lst

# Restart the FakeIP DNS & stats daemon to reload proxy.lst (systemd)
sudo systemctl restart jwg-dns.service

# Export a split-tunnel config for an existing peer
sudo jwg show phone --split
```

---

## 📖 Command Reference

### Commands

| Command | Description |
| :--- | :--- |
| `jwg add <name> [--split]` | Add a new peer (optional `--split` for FakeIP split-tunnel config). |
| `jwg del <name>` *(or `rm`)*| Delete an existing peer. |
| `jwg show <name> [--split]` | Display config and QR code for an existing peer. |
| `jwg serve` | Run the FakeIP DNS mapper (`198.18.0.0/15`, `/var/lib/jwg/proxy.lst`) and traffic stats daemon. |
| `jwg` | Show live server status, interface details, and list of connected peers. |

### Configuration Flags
Flags override default settings and **persist** in the database.

```bash
# Add a peer with a specific internal IP
jwg add phone --ip 10.8.0.5

# Change server listening port
jwg --port 51820

# Set custom DNS for generated client configs
jwg --dns "1.1.1.1, 8.8.8.8"

# Force a specific public endpoint (e.g. behind NAT/DDNS/Cloudflare)
jwg --endpoint "vpn.my-server.com:51820"

# Change internal subnet
jwg --subnet "192.168.100.1/24"
```

**Advanced flags:**
*   `--iface <name>`: Target a specific interface (default: `wg0`).
*   `--nat-iface <name>`: Manually specify the public interface for NAT (default: auto-detected).
*   `--client-allowed-ips <CIDR>`: Set specific `AllowedIPs` generated inside client configs (default: `0.0.0.0/0`).
*   `--db <path>`: Check/Store the database in a custom path (defaults to `./jwg.db`, then `/var/lib/jwg/jwg.db`).
*   `--awg-version <1.5|2.0|3.0|3.1>`: AmneziaWG obfuscation profile version to generate when initializing a new database (default: `2.0`).
*   `--blocklist <path>`: Path to a plain-text file with IPs/CIDRs to drop server-side via nftables.

💡 **Geo-blocking to prevent VPN detection**
```bash
sudo wget https://country-ip-blocks.hackinggate.com/RU_IPv4.txt -O /var/lib/jwg/RU_IPv4.txt
# Fix habr
sudo sed -i '/^178\.248\.23/d' /var/lib/jwg/RU_IPv4.txt
sudo jwg --blocklist /var/lib/jwg/RU_IPv4.txt
```
*(To disable the blocklist later, simply run `sudo jwg --blocklist ""`)*

---

## 🐧 Power User: The Ultimate Setup (Void Linux & Kernel Module)

By default, the auto-installer uses the userspace `amneziawg-go` daemon, which is great for compatibility. However, if you want **maximum performance**, you need the kernel module.

If you have a fresh/cheap VPS (Ubuntu/Debian) and want a completely bloat-free environment, you can use my [void-infect](https://github.com/Jipok/void-infect) script to replace the existing OS with **Void Linux** on the fly. 

My custom Void repository already contains the **AmneziaWG DKMS kernel module** and `jwg` with native `runit` services.

**1. Reinstall your VPS to Void Linux (takes ~2 mins):**
```bash
wget https://raw.githubusercontent.com/Jipok/void-infect/master/void-infect.sh
chmod +x void-infect.sh
./void-infect.sh YourGithubUsername
```
*(Server will automatically reboot into a fresh Void Linux system).*

**2. Install kernel AmneziaWG and JWG:**
```bash
xbps-install jwg

# Download split-tunnel lists and RU IPv4 blocklist
wget -qO /var/lib/jwg/proxy.lst https://github.com/1andrevich/Re-filter-lists/raw/refs/heads/main/domains_all.lst
wget -qO /var/lib/jwg/ips.lst https://github.com/Jipok/dnsr/raw/refs/heads/master/ips.lst
wget -qO /var/lib/jwg/RU_IPv4.txt https://country-ip-blocks.hackinggate.com/RU_IPv4.txt
sed -i '/^178\.248\.23/d' /var/lib/jwg/RU_IPv4.txt

# Run the setup wizard first; jwg creates awg0 and picks up RU_IPv4.txt automatically
jwg

# Enable the runit service (restores the tunnel and runs FakeIP DNS + stats)
ln -s /etc/sv/jwg-awg0 /var/service/
```

This gives you a pure, natively integrated WireGuard/AmneziaWG server running entirely in kernel space without systemd overhead. Just type `jwg add client` (or `jwg add client --split`) and you're good to go.
