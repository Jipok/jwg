# JWG

**The lightweight CLI manager for WireGuard and AmneziaWG.**

Most WireGuard tools fall into two extremes: manual config editing or heavy web UIs that require Docker, PostgreSQL, and a browser.

`jwg` is a single-binary CLI that handles the entire lifecycle of your VPN server: networking, keys, firewall rules, and peer management automatically. It doesn't need a database server or a web panel—it just works.

Crucially, it is compatible with **AmneziaWG-go**.

---

## ✨ Why jwg?

*   **👻 AmneziaWG Ready:** Designed to work seamlessly with `amneziawg-go` and `wireguard-go` interfaces, not just kernel modules.
*   **🚫 No Web UI Needed:** Forget about `docker-compose`, databases, or opening HTTP ports.
*   **🔋 Battery Included:** Handles **NAT**, **Packet Forwarding**, Anti-Bufferbloat (Smart QoS), and **Firewall** (nftables & UFW) automatically. You don't need to be a Linux network engineer to set this up.
*   **📱 QR Codes in Terminal:** Generate configs and display QR codes directly in the console.
*   **📂 Embedded Database:** Stores configurations and peers in a single `jwg.db` file. Zero external dependencies.

---

## 🚀 Installation & Quick Start

### 1. Installation

**Recommended: Automatic Installation**  
Installs the required binaries, sets up a systemd service for AmneziaWG, and starts the VPN automatically.
```bash
curl -sL https://raw.githubusercontent.com/Jipok/jwg/master/install.sh | sudo bash
```

<details>
<summary><b>Alternative: Manual / Wireguard Setup</b> (Click to expand)</summary>

`jwg` manages the *configuration logic*, but you need to run the interface process first.

**Start the Interface (choose one):**
```bash
# Option 1: AmneziaWG (Userspace Go daemon)
wget https://raw.githubusercontent.com/Jipok/jwg/refs/heads/master/amneziawg-go
chmod +x amneziawg-go
./amneziawg-go wg0

# Option 2: Standard Kernel WireGuard
ip link add dev wg0 type wireguard
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
jwg -add phone
```
*The output matches the standard client config format and includes a QR code right in your terminal.*

---

## 📖 Command Reference

### Commands

| Command | Description |
| :--- | :--- |
| `jwg add <name>` | Add a new peer. Auto-assigns the next available IP. |
| `jwg del <name>` *(or `rm`)*| Delete an existing peer. |
| `jwg show <name>` | Display config and QR code for an existing peer. |
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
*   `--blocklist <path>`: Path to a plain-text file with IPs/CIDRs to drop server-side via nftables.

💡 **Geo-blocking to prevent VPN detection**
```bash
sudo wget https://country-ip-blocks.hackinggate.com/RU_IPv4.txt -O /var/lib/jwg/RU_IPv4.txt
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
# Install kernel headers, the DKMS module, and jwg
xbps-install linux-lts-headers jwg

# Enable the runit service
ln -s /etc/sv/jwg-awg0 /var/service/
```

This gives you a pure, natively integrated WireGuard/AmneziaWG server running entirely in kernel space without systemd overhead. Just type `jwg add client` and you're good to go.
