# JWG

**The lightweight CLI manager for WireGuard and AmneziaWG.**

Most WireGuard tools fall into two extremes: manual config editing or heavy web UIs that require Docker, PostgreSQL, and a browser.

`jwg` is a single-binary CLI that handles the entire lifecycle of your VPN server: networking, keys, firewall rules, and peer management automatically. It doesn't need a database server or a web panel—it just works.

Crucially, it is compatible with **AmneziaWG-go**.

---

## ✨ Why jwg?

*   **👻 AmneziaWG Ready:** Designed to work seamlessly with `amneziawg-go` and `wireguard-go` interfaces, not just kernel modules.
*   **🚫 No Web UI Needed:** Forget about `docker-compose`, web servers, or opening HTTP ports. Manage your VPN entirely via SSH.
*   **🔋 Battery Included:** Handles **NAT**, **Packet Forwarding**, and **Firewall** (nftables & UFW) automatically. You don't need to be a Linux network engineer to set this up.
*   **📱 QR Codes in Terminal:** Generate configs and display QR codes directly in the console for instant mobile connection.
*   **📂 Embedded Database:** Stores peers in a `jwg.db` file. Zero external dependencies.

---

## 🚀 Quick Start

### 1. Start the Interface
`jwg` manages the *configuration logic*, but you need to keep the interface process running.

**Recommended: AmneziaWG**
```bash
wget https://raw.githubusercontent.com/Jipok/jwg/refs/heads/master/amneziawg-go
chmod +x amneziawg-go
./amneziawg-go wg0
```

**Or: Standard Kernel WireGuard**
```bash
ip link add dev wg0 type wireguard
```

### 2. Initialize Server
Run `jwg` for the first time. It will auto-detect your Public IP and apply necessary firewall rules.

```bash
wget https://github.com/Jipok/jwg/releases/latest/download/jwg
chmod +x jwg
./jwg
```

### 3. Add a Client
Add a new peer. `jwg` will find the next available IP, generate keys, and sync the interface.

```bash
./jwg -add phone
```
*The output matches the standard client config format and includes a QR code.*

---

## 📖 Command Reference

### Managing Peers

| Command | Description |
| :--- | :--- |
| `jwg -add <name>` | Add a new peer. Auto-assigns IP. |
| `jwg -add <name> -ip 10.8.0.5/32` | Add a peer with a specific internal IP. |
| `jwg -del <name>` | Delete a peer. |
| `jwg -show <name>` | Display config and QR code for an existing peer. |
| `jwg` | Show server status, used IPs, and connected peers. |

### Configuration & Storage
Flags override default settings and **persist** in the database.

**Database Location:**
`jwg` first checks for `./jwg.db`. If not found, it defaults to `/var/lib/jwg/jwg.db`. You can specify a custom path manually:

```bash
jwg -db /etc/wireguard/my_vpn.db
```

**Network Settings:**

```bash
# Set custom listen port
jwg -port 51820

# Set custom DNS for clients
jwg -dns "1.1.1.1, 8.8.8.8"

# Force a specific endpoint (e.g. behind NAT/Cloudflare)
jwg -endpoint "vpn.my-server.com:51820"

# Change internal subnet
jwg -subnet "192.168.100.1/24"
```

---

## 🔥 Firewall & Networking
`jwg` is opinionated about networking to save you time:
1.  **Forwarding:** It enables kernel IP forwarding.
2.  **NAT:** It creates a dedicated `jwg_nat` table in **nftables** to masquerade traffic (allow peers to access the internet).
3.  **UFW Support:** If UFW is active, `jwg` automatically adds generic allows and route rules to prevent silent packet drops.
