package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/Jipok/go-persist"
	"github.com/skip2/go-qrcode"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	defaultPort          = 31797
	defaultIface         = "wg0"
	defaultSubnet        = "10.8.0.1/24"
	defaultNatIface      = ""
	dbFileName           = "jwg.db"
	dbMapPeers           = "peers"
	dbMapKeyServerConfig = "config"
	defaultDNS           = "8.8.8.8, 1.1.1.1" // Default DNS for client configs
)

// --- ANSI Color Codes for formatted output ---
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"
	colorBold   = "\033[1m"
)

// --- Global variables ---
var (
	// Persistence and WireGuard clients
	store       *persist.Store
	config      ServerConfig
	peerDataMap *persist.PersistMap[PeerData]
	wgClient    *wgctrl.Client

	// Command-line flags mapped to variables
	argAddPeer  string // Name of the peer to add
	argDelPeer  string // Name of the peer to delete
	argShowPeer string // Name of the peer to show config and QR code for
	argPeerIP   string // Optional IP for the new peer
	argIface    string
	argPort     int
	argEndpoint string
	argSubnet   string
	argNatIface string
	argDNS      string = defaultDNS

	err error
)

// Persistent configuration
type ServerConfig struct {
	PrivateKey wgtypes.Key
	Endpoint   string
	Port       int
	Subnet     string
	NatIface   string
	DNS        string
	Interface  string
}

// PeerData holds all necessary information about a peer, including its
// private key which is needed for generating client configs but is not
// stored in the WireGuard device configuration itself.
type PeerData struct {
	// Name is the human-readable identifier for the peer, used as the key in the DB.
	Name string
	// Config is the configuration applied to the server's interface.
	Config wgtypes.PeerConfig
	// PrivateKey is the peer's own private key, used to generate its client config.
	PrivateKey wgtypes.Key
}

func main() {
	flag.StringVar(&argAddPeer, "add", "", "Name of the new peer to add (e.g., 'device1')")
	flag.StringVar(&argDelPeer, "del", "", "Name of the peer to delete (e.g., 'device2')")
	flag.StringVar(&argShowPeer, "show", "", "Name of an existing peer to show config and QR code for")
	flag.StringVar(&argPeerIP, "ip", "", "Optional: IP address for the new peer (e.g., '10.8.0.5/32'). If not set, it's assigned automatically.")
	flag.IntVar(&argPort, "port", defaultPort, "Port for WireGuard server to listen on")
	flag.StringVar(&argIface, "iface", defaultIface, "WireGuard interface name")
	flag.StringVar(&argEndpoint, "endpoint", "", "Public endpoint of the server (for 'add' action)")
	flag.StringVar(&argSubnet, "subnet", defaultSubnet, "Subnet for the server's wg interface (used for initial setup)")
	flag.StringVar(&argNatIface, "nat-iface", defaultNatIface, "Public-facing network interface for NAT (leave empty to auto-detect)")
	flag.StringVar(&argDNS, "dns", defaultDNS, "DNS servers for client configs")
	flag.Parse()

	if os.Geteuid() != 0 {
		log.Fatalf("%s[ERR]%s This program must be run as root (sudo) to manage network interfaces and firewall rules.", colorRed, colorReset)
	}

	// Verify nft is installed
	if _, err := exec.LookPath("nft"); err != nil {
		log.Fatalf("%s[ERR]%s 'nft' command not found. Please install nftables (e.g., apt install nftables).", colorRed, colorReset)
	}

	if argPeerIP != "" && argAddPeer == "" {
		log.Fatalf("The -ip flag can only be used when adding a new peer with the -add flag.")
	}

	// --- Persistence/Config ---
	store = persist.New()

	peerDataMap, err = persist.Map[PeerData](store, dbMapPeers)
	if err != nil {
		log.Fatalf("failed to create peers map: %v", err)
	}

	if err = store.Open(dbFileName); err != nil {
		log.Fatalf("failed to open persistence store: %v", err)
	}
	defer store.Close()

	if err = store.Shrink(); err != nil {
		log.Fatalf("failed to shrink store: %v", err)
	}

	config, err = persist.Get[ServerConfig](store, dbMapKeyServerConfig)
	if err != nil && err != persist.ErrKeyNotFound {
		log.Fatalf("failed to read server config map: %v", err)
	}

	// Flag to track if we need to save updates to the DB
	configDirty := false
	// Flag to track if we need to re-apply firewall rules (port or nat-iface changed)
	firewallDirty := false

	if err == persist.ErrKeyNotFound {
		fmt.Printf("%s[INFO]%s Server config not found. Generating a new one...\n", colorCyan, colorReset)
		privateKey, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			log.Fatalf("Failed to generate private key: %v", err)
		}
		config = ServerConfig{PrivateKey: privateKey}
		configDirty = true
	}

	// --- Configuration Normalization Logic ---
	// Apply defaults to the Config struct if fields are empty (fresh install)
	if config.Interface == "" {
		config.Interface = defaultIface
	}
	if config.Port == 0 {
		config.Port = defaultPort
	}
	if config.Subnet == "" {
		config.Subnet = defaultSubnet
	}
	if config.DNS == "" {
		config.DNS = defaultDNS
	}

	// Apply Command Line Flags overrides
	// We check if the flag was explicitly passed by the user, regardless of its value.
	// This allows users to revert settings to default values (e.g. -port 31797).
	if isFlagPassed("iface") {
		config.Interface = argIface
		configDirty = true
	}
	if isFlagPassed("port") {
		if config.Port != argPort {
			fmt.Printf("%s[WARN]%s Port changed from %d to %d. Existing clients will lose connection until their config is updated.\n", colorYellow, colorReset, config.Port, argPort)
			firewallDirty = true
		}
		config.Port = argPort
		configDirty = true

		// Update Endpoint string automatically if port changes
		if config.Endpoint != "" {
			host, _, err := net.SplitHostPort(config.Endpoint)
			if err == nil {
				newEndpoint := net.JoinHostPort(host, fmt.Sprintf("%d", argPort))
				if config.Endpoint != newEndpoint {
					config.Endpoint = newEndpoint
				}
			}
		}
	}
	if isFlagPassed("subnet") {
		config.Subnet = argSubnet
		configDirty = true
		firewallDirty = true
	}
	if isFlagPassed("nat-iface") {
		config.NatIface = argNatIface
		configDirty = true
		firewallDirty = true
	}
	if isFlagPassed("dns") {
		config.DNS = argDNS
		configDirty = true
	}
	if isFlagPassed("endpoint") {
		config.Endpoint = argEndpoint
		configDirty = true
		fmt.Printf("%s[OK]%s Manual endpoint set via flag: %s%s%s\n", colorGreen, colorReset, colorBold, config.Endpoint, colorReset)
	}

	// Sync "Global Args" with "Config State"
	argIface = config.Interface
	argPort = config.Port
	argSubnet = config.Subnet
	argNatIface = config.NatIface
	argDNS = config.DNS

	// Interface validation
	if _, err := net.InterfaceByName(argIface); err != nil {
		printMissingInterfaceHelp(argIface)
		os.Exit(1)
	}

	// WG Client Setup
	wgClient, err = wgctrl.New()
	if err != nil {
		log.Fatalf("failed to open wgctrl: %v", err)
	}
	defer wgClient.Close()

	// Ensure we have a valid NAT interface before configuring firewall
	if argNatIface == "" {
		detectedIface, err := detectDefaultInterface()
		if err == nil {
			argNatIface = detectedIface
		}
	}

	// Auto-detect Endpoint if still empty
	if config.Endpoint == "" {
		publicIP, err := detectPublicIP()
		if err != nil {
			log.Fatalf("Failed to auto-detect public IP and -endpoint flag not provided: %v", err)
		}
		config.Endpoint = fmt.Sprintf("%s:%d", publicIP, argPort)
		configDirty = true
		fmt.Printf("%s[OK]%s Detected and using new endpoint: %s%s%s\n", colorGreen, colorReset, colorBold, config.Endpoint, colorReset)
	}

	// Save config if any values changed
	if configDirty {
		if err := store.Set(dbMapKeyServerConfig, config); err != nil {
			log.Fatalf("Failed to save server config: %v", err)
		}
	}

	// --- Action Router ---
	if argShowPeer != "" {
		runShowPeer(argShowPeer)
		return
	}
	if argAddPeer != "" {
		runAddPeer(argAddPeer)
	}
	if argDelPeer != "" {
		runDelPeer(argDelPeer)
	}

	mutatingAction := argAddPeer != "" || argDelPeer != ""

	// Check environment and configure firewall/interfaces
	if !isInterfaceConfigured(argIface, argSubnet) {
		fmt.Printf("%s[WARN]%s Interface %s is not configured with IP %s. Running initial network setup...\n", colorYellow, colorReset, argIface, argSubnet)
		// This runs full setup: IP assignment + UP + Firewall
		runInitialNetworkSetup()
		mutatingAction = true
	} else if firewallDirty {
		// Interface is UP, but port or NAT settings configuration changed via flags.
		fmt.Printf("%s[CONF]%s Configuration changed (Port/Subnet/NAT). Updating firewall rules...\n", colorYellow, colorReset)

		if argNatIface == "" {
			log.Fatalf("NAT interface could not be auto-detected. Please use -nat-iface.")
		}

		// Re-apply firewall rules
		if err := applyNftablesRules(argSubnet, argIface, argNatIface); err != nil {
			log.Fatalf("Failed to apply nftables configuration: %v", err)
		}
		checkAndConfigureUFW(argPort, argIface, argNatIface)

		fmt.Printf("%s[OK]%s Firewall rules updated for port %d.\n", colorGreen, colorReset, argPort)
		mutatingAction = true // Force WG sync to bind to new port
	} else {
		fmt.Printf("%s[OK]%s Network configuration (IP & NAT) appears to be in place. Skipping setup.\n", colorGreen, colorReset)
	}

	// Safety check: even if user didn't ask to add/del peer, and IP is set,
	// checking if the running interface actually matches our desired config (Port/Keys).
	if !mutatingAction {
		if d, err := wgClient.Device(argIface); err == nil {
			if d.ListenPort != argPort {
				fmt.Printf("%s[CONF]%s Live listen port (%d) mismatches config (%d).\n", colorYellow, colorReset, d.ListenPort, argPort)
				mutatingAction = true
			} else if d.PrivateKey != config.PrivateKey {
				fmt.Printf("%s[CONF]%s Live private key mismatches database.\n", colorYellow, colorReset)
				mutatingAction = true
			} else if len(d.Peers) != peerDataMap.Size() {
				fmt.Printf("%s[CONF]%s Live peer count (%d) mismatches database (%d).\n", colorYellow, colorReset, len(d.Peers), peerDataMap.Size())
				mutatingAction = true
			}
		}
	}

	// --- Core Sync Logic ---
	if mutatingAction {
		fmt.Printf("\n%s[SYNC]%s Starting full sync for interface %s%s%s...\n", colorPurple, colorReset, colorBold, argIface, colorReset)

		// Load all peers from the database.
		allPeers := make([]wgtypes.PeerConfig, 0, peerDataMap.Size())
		peerDataMap.Range(func(key string, peer PeerData) bool {
			allPeers = append(allPeers, peer.Config)
			return true // Continue iterating
		})
		fmt.Printf("  %s[DB]%s Found %d peers in the database to apply.\n", colorCyan, colorReset, len(allPeers))

		// Create a complete configuration object and apply it.
		// This replaces all existing peers on the interface with the list from our database.
		configWg := wgtypes.Config{
			PrivateKey:   &config.PrivateKey,
			ListenPort:   &argPort,
			ReplacePeers: true, // This is key: it makes the configuration idempotent.
			Peers:        allPeers,
		}

		if err := wgClient.ConfigureDevice(argIface, configWg); err != nil {
			log.Fatalf("Failed to configure WireGuard device: %v", err)
		}
		fmt.Printf("  %s[OK]%s Synced interface %s with private key, listen port, and %d peers.\n", colorGreen, colorReset, argIface, len(allPeers))
	}

	// Only show final state if not just adding a peer
	if argAddPeer == "" && argDelPeer == "" {
		fmt.Printf("\n%s%s----------------- Live State ------------------%s\n", colorBlue, colorBold, colorReset)
		runShowInfo()
		fmt.Printf("\n%s[DONE]%s Sync complete.\n", colorGreen, colorReset)
	}
}

// detectDefaultInterface checks the routing table to find which interface
// is used to reach the public internet (specifically targeting "8.8.8.8").
func detectDefaultInterface() (string, error) {
	// We use "ip route get 8.8.8.8" to ask the kernel which interface
	// it would use to route a packet to Google DNS.
	// Output format looks like: "8.8.8.8 via 192.168.1.1 dev eth0 src 192.168.1.5 ..."
	out, err := exec.Command("ip", "route", "get", "8.8.8.8").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("command 'ip route get' failed: %w", err)
	}

	output := string(out)
	fields := strings.Fields(output)

	// Iterate through fields to find "dev" and return the next field
	for i, field := range fields {
		if field == "dev" && i+1 < len(fields) {
			return fields[i+1], nil
		}
	}

	return "", fmt.Errorf("could not parse interface name from output: %s", output)
}

func printMissingInterfaceHelp(ifaceName string) {
	fmt.Printf("\n%s[ERROR]%s Network interface '%s%s%s' not found.\n", colorRed, colorReset, colorBold, ifaceName, colorReset)
	fmt.Printf("This utility manages configuration, but the interface must be created first.\n\n")

	fmt.Printf("%sChoose your backend and start the interface:%s\n", colorBlue, colorReset)
	fmt.Println("---------------------------------------------------------------")

	fmt.Printf("%s1. AmneziaWG (Userspace)                         %s<- Recommended%s\n", colorGreen, colorBlue, colorReset)
	fmt.Printf("   If using the amneziawg-go version of wireguard-go:\n")
	fmt.Printf("   %s#%s%s ./amneziawg-go -f %s%s\n", colorGreen, colorReset, colorBold, ifaceName, colorReset)
	fmt.Println("   (This runs foreground. Keep it running or make a service)")
	fmt.Println()

	fmt.Printf("%s2. WireGuard-Go (Userspace)%s\n", colorGreen, colorReset)
	fmt.Printf("   Standard userspace implementation:\n")
	fmt.Printf("   %s#%s%s ./wireguard-go -f %s%s\n", colorGreen, colorReset, colorBold, ifaceName, colorReset)
	fmt.Println()

	fmt.Printf("%s3. Linux Kernel WireGuard%s\n", colorGreen, colorReset)
	fmt.Printf("   Best performance, standard on modern Linux:\n")
	fmt.Printf("   %s#%s%s ip link add dev %s type wireguard%s\n", colorGreen, colorReset, colorBold, ifaceName, colorReset)
	fmt.Println("---------------------------------------------------------------")

	fmt.Printf("\nOnce the interface is initialized, run this tool again to configure it.\n\n")
}

func isInterfaceConfigured(ifaceName, expectedAddr string) bool {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return false // Interface likely doesn't exist.
	}

	addrs, err := iface.Addrs()
	if err != nil {
		log.Printf("Warning: could not get addresses for interface %s: %v", ifaceName, err)
		return false // Can't get addresses, so assume not configured.
	}

	// The expected address includes the CIDR mask (e.g., "10.8.0.1/24").
	// The Addr.String() method for an IPNet returns this exact format.
	for _, addr := range addrs {
		if addr.String() == expectedAddr {
			return true
		}
	}

	return false
}

func runInitialNetworkSetup() {
	// Detect default interface
	if argNatIface == "" {
		fmt.Printf("%s[INFO]%s NAT interface not specified. Attempting auto-detection...\n", colorCyan, colorReset)
		detectedIface, err := detectDefaultInterface()
		if err != nil {
			fmt.Printf("%s[ERR]%s Failed to auto-detect default interface: %v.\n   %sSet it manually with -nat-iface%s\n", colorYellow, colorReset, err, colorBlue, colorReset)
			os.Exit(1)
		} else {
			argNatIface = detectedIface
			fmt.Printf("%s[OK]%s Auto-detected default interface: %s%s%s\n", colorGreen, colorReset, colorBold, argNatIface, colorReset)
		}
	}

	// Step 1: Assign IP address to the interface
	runCmd("ip", "addr", "flush", "dev", argIface)
	if err := runCmd("ip", "address", "add", argSubnet, "dev", argIface); err != nil {
		log.Fatalf("Failed to assign IP address %s to %s: %v", argSubnet, argIface, err)
	}
	fmt.Printf("  %s[OK]%s Assigned IP %s to interface %s.\n", colorGreen, colorReset, argSubnet, argIface)

	// Step 2: Bring the interface UP
	if err := runCmd("ip", "link", "set", "up", "dev", argIface); err != nil {
		log.Fatalf("Failed to bring up interface %s: %v", argIface, err)
	}
	fmt.Printf("  %s[OK]%s Interface %s is now UP.\n", colorGreen, colorReset, argIface)

	// Step 3: Enable IP forwarding in the kernel.
	fmt.Printf("  %s[SETUP]%s Enabling kernel IP forwarding...\n", colorCyan, colorReset)
	if err := runCmd("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		fmt.Printf("%s[WARN]%s Failed to enable IP forwarding via sysctl: %v\n", colorYellow, colorReset, err)
	} else {
		fmt.Printf("    %s[OK]%s IP forwarding enabled for the current session.\n", colorGreen, colorReset)
	}

	// Step 4: Firewall Configuration (NFTables)
	fmt.Printf("  %s[FIREWALL]%s Configuring nftables rules (NAT & Forwarding)...\n", colorYellow, colorReset)

	if err := applyNftablesRules(argSubnet, argIface, argNatIface); err != nil {
		log.Fatalf("Failed to apply nftables configuration: %v", err)
	}
	fmt.Printf("    %s[OK]%s Nftables rules applied to table 'jwg'.\n", colorGreen, colorReset)

	checkAndConfigureUFW(argPort, argIface, argNatIface)
}

// applyNftablesRules creates a dedicated table 'jwg' to handle WG traffic.
// Included hooks:
// 1. Filter Forward: Allows traffic in/out of WG interface.
// 2. NAT Postrouting: Masquerades traffic going out to the internet.
func applyNftablesRules(subnet, wgIface, natIface string) error {
	// We use a priority of -5 for filter to try and run before standard firewalls (often 0),
	// although strictly speaking, an explicit DROP in another table will still win in Netfilter.
	// But this setup is cleaner and idempotent.

	nftScript := fmt.Sprintf(`
# Define table for filtering (IPv4/IPv6)
add table inet jwg_filter
delete table inet jwg_filter

add table inet jwg_filter
add chain inet jwg_filter forward { type filter hook forward priority -5; policy accept; }

# Allow traffic from WG to Internet
add rule inet jwg_filter forward iifname "%s" oifname "%s" counter accept

# Allow return traffic (established/related)
add rule inet jwg_filter forward iifname "%s" oifname "%s" ct state related,established counter accept


# Define table for NAT (IPv4 only usually needed for masquerade here)
add table ip jwg_nat
delete table ip jwg_nat

add table ip jwg_nat
add chain ip jwg_nat postrouting { type nat hook postrouting priority 100; policy accept; }

# Masquerade traffic from WG subnet going out via NAT interface
add rule ip jwg_nat postrouting oifname "%s" ip saddr %s counter masquerade
`, wgIface, natIface, natIface, wgIface, natIface, subnet)

	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = bytes.NewBufferString(nftScript)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft execution failed: %v\nOutput: %s", err, string(output))
	}

	return nil
}

// checkAndConfigureUFW ensures UFW allows both the listening port
// and the forwarding of traffic from WireGuard to the internet.
func checkAndConfigureUFW(port int, wgIface, natIface string) {
	path, err := exec.LookPath("ufw")
	if err != nil || path == "" {
		return // UFW is not installed
	}

	// Check if UFW is active
	cmd := exec.Command("ufw", "status")
	output, err := cmd.CombinedOutput()

	// If UFW is not active, do nothing (firewall is likely disabled)
	if err != nil || !strings.Contains(string(output), "Status: active") {
		return
	}

	fmt.Printf("  %s[FIREWALL]%s UFW is active. Applying compatibility rules...\n", colorPurple, colorReset)

	// 1. Open the UDP port (Input)
	portRule := fmt.Sprintf("%d/udp", port)
	allowCmd := exec.Command("ufw", "allow", portRule)
	if out, err := allowCmd.CombinedOutput(); err != nil {
		fmt.Printf("    %s[WARN]%s Failed to start allowance for port %s: %s\n", colorYellow, colorReset, portRule, string(out))
	} else {
		fmt.Printf("    - Rule ensured: allow %s\n", portRule)
	}

	// 2. Allow Forwarding (Routing)
	// Essential! Without this, connected clients have no internet access because
	// UFW's default "routed" policy is usually DROP.
	// Command: ufw route allow in on <wg0> out on <eth0>
	routeCmd := exec.Command("ufw", "route", "allow", "in", "on", wgIface, "out", "on", natIface)
	if out, err := routeCmd.CombinedOutput(); err != nil {
		fmt.Printf("    %s[WARN]%s Failed to add UFW route rule (internet might be blocked): %s\n", colorYellow, colorReset, string(out))
	} else {
		fmt.Printf("    - Rule ensured: route allow in on %s out on %s\n", wgIface, natIface)
	}
}

// runCmd is a helper to execute shell commands and log their output.
func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("command '%s %s' failed: %w\nSTDOUT:\n%s\nSTDERR:\n%s",
			name, strings.Join(args, " "), err, stdout.String(), stderr.String())
	}
	return nil
}

// detectPublicIP finds the server's public IP address using an external service.
func detectPublicIP() (string, error) {
	// A list of services to try.
	services := []string{
		"https://ifconfig.co",
		"https://ifconfig.me/ip",
		"https://icanhazip.com",
	}

	fmt.Printf("%s[INFO]%s Detecting public IP by querying external services...\n", colorCyan, colorReset)

	// Iterate over the services.
	for _, service := range services {
		// Create an HTTP client with a reasonable timeout for each attempt.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

		req, err := http.NewRequestWithContext(ctx, "GET", service, nil)
		if err != nil {
			cancel()
			// Log error and try the next service.
			fmt.Printf("    - error creating request for %s: %v\n", service, err)
			continue
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			cancel()
			fmt.Printf("    - failed to get public IP from %s: %v\n", service, err)
			continue
		}

		// Check status code.
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			cancel()
			fmt.Printf("    - bad status code from %s: %d\n", service, resp.StatusCode)
			continue
		}

		// Read the response body.
		ipBytes, err := io.ReadAll(resp.Body)
		resp.Body.Close() // Close body right after reading.
		if err != nil {
			cancel()
			fmt.Printf("    - failed to read response body from %s: %v\n", service, err)
			continue
		}

		cancel() // We are done with this context.
		// If we got here, we have a valid IP.
		return strings.TrimSpace(string(ipBytes)), nil
	}

	// If the loop completes, all services have failed.
	return "", fmt.Errorf("all public IP detection services failed")
}

// Collects all IPs currently in use by peers and the server
func getUsedIPs() (map[string]struct{}, error) {
	usedIPs := make(map[string]struct{})
	serverIP, err := netip.ParseAddr(strings.Split(argSubnet, "/")[0])
	if err != nil {
		return nil, fmt.Errorf("could not parse server IP from '%s': %w", argSubnet, err)
	}
	usedIPs[serverIP.String()] = struct{}{}

	peerDataMap.Range(func(key string, peer PeerData) bool {
		for _, ipNet := range peer.Config.AllowedIPs {
			// Convert net.IP to netip.Addr for easier comparison.
			// Unmap the address to ensure that IPv4-mapped IPv6 addresses
			// are treated as plain IPv4, matching how we iterate the subnet.
			addr, _ := netip.AddrFromSlice(ipNet.IP)
			addr = addr.Unmap()
			usedIPs[addr.String()] = struct{}{}
		}
		return true // continue iteration
	})
	return usedIPs, nil
}

// findNextAvailableIP searches the server's subnet for an unused IP address.
func findNextAvailableIP() (string, error) {
	// 1. Parse the server's subnet to get the valid range.
	prefix, err := netip.ParsePrefix(argSubnet)
	if err != nil {
		return "", fmt.Errorf("could not parse server subnet '%s': %w", argSubnet, err)
	}
	// Normalize to discard host bits (e.g. 10.8.0.1/24 -> 10.8.0.0/24)
	prefix = prefix.Masked()

	// 2. Collect all IPs currently in use.
	usedIPs, err := getUsedIPs()
	if err != nil {
		return "", fmt.Errorf("could not get list of used IPs: %w", err)
	}

	serverIP, _ := netip.ParseAddr(strings.Split(argSubnet, "/")[0])

	// 3. Iterate through all IPs in the subnet and return the first one not in our set.
	// We start from the server's IP and check the next one.
	for ip := serverIP.Next(); prefix.Contains(ip); ip = ip.Next() {
		if _, isUsed := usedIPs[ip.String()]; !isUsed {
			// Found an available IP. Return it in CIDR format for a single host.
			return ip.String() + "/32", nil
		}
	}

	return "", fmt.Errorf("no available IP addresses found in subnet %s", argSubnet)
}

// Adds new peer to DB and returns the config for runtime application.
// It uses a user-specified IP if provided, otherwise finds the next available one.
func runAddPeer(peerName string) {
	// --- Step 0: Pre-flight checks & data gathering ---

	// Check if a peer with this name already exists. Our map key is the peer name.
	if _, exists := peerDataMap.Get(peerName); exists {
		log.Fatalf("Peer with name '%s' already exists. Please choose a unique name.", peerName)
	}

	var peerIP string
	var err error

	// If user provides an IP, validate and use it. Otherwise, find one.
	if argPeerIP != "" {
		fmt.Printf("%s[INFO]%s Using user-provided IP for new peer '%s'...\n", colorCyan, colorReset, peerName)
		// Validate that the provided IP is a valid single-host CIDR.
		ipPrefix, err := netip.ParsePrefix(argPeerIP)
		if err != nil {
			log.Fatalf("Invalid format for -ip flag '%s': %v. Must be like '10.8.0.5/32'.", argPeerIP, err)
		}
		if !ipPrefix.IsSingleIP() {
			log.Fatalf("IP address '%s' must be a single host address (e.g., with a /32 mask for IPv4).", argPeerIP)
		}
		peerIP = argPeerIP
		userIP := ipPrefix.Addr()

		// Check if this IP is already in use.
		usedIPs, err := getUsedIPs()
		if err != nil {
			log.Fatalf("Could not verify if IP is in use: %v", err)
		}
		if _, isUsed := usedIPs[userIP.String()]; isUsed {
			log.Fatalf("The provided IP address '%s' is already in use.", userIP)
		}
		fmt.Printf("  %s[OK]%s Using validated IP: %s%s%s\n", colorGreen, colorReset, colorBold, peerIP, colorReset)
	} else {
		fmt.Printf("%s[INFO]%s Finding next available IP for new peer '%s'...\n", colorCyan, colorReset, peerName)
		peerIP, err = findNextAvailableIP()
		if err != nil {
			log.Fatalf("Failed to find an available IP: %v", err)
		}
		fmt.Printf("  %s[OK]%s Assigned next available IP: %s%s%s\n", colorGreen, colorReset, colorBold, peerIP, colorReset)
	}

	// --- 1. Get Server's Public Key for client config ---
	serverDevice, err := wgClient.Device(argIface)
	if err != nil {
		log.Fatalf("failed to get device '%s' to retrieve server public key: %v. Is the interface up?", argIface, err)
	}
	serverPublicKey := serverDevice.PublicKey

	// --- 2. Generate keys for the new peer ---
	peerPrivateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		log.Fatalf("failed to generate peer private key: %v", err)
	}
	psk, err := wgtypes.GenerateKey()
	if err != nil {
		log.Fatalf("failed to generate preshared key: %v", err)
	}
	peerPublicKey := peerPrivateKey.PublicKey()

	// --- 3. Create peer configuration objects ---
	_, parsedIPNet, err := net.ParseCIDR(peerIP) // Use the auto-found IP
	if err != nil {
		log.Fatalf("invalid peer IP address format: %v", err)
	}

	peerSrvCfg := wgtypes.PeerConfig{
		PublicKey:         peerPublicKey,
		PresharedKey:      &psk,
		AllowedIPs:        []net.IPNet{*parsedIPNet},
		ReplaceAllowedIPs: true,
	}
	newPeerData := PeerData{
		Name:       peerName,
		Config:     peerSrvCfg,
		PrivateKey: peerPrivateKey,
	}

	// --- 4. Persist the new peer ---
	// The key for the map is the peer's name, ensuring uniqueness.
	if err := peerDataMap.SetFSync(peerName, newPeerData); err != nil {
		log.Fatalf("Failed to save new peer '%s' to persistent store: %v", peerName, err)
	}
	fmt.Printf("%s[DB]%s Peer '%s' (%s) saved. It will be applied on this run.\n", colorCyan, colorReset, peerName, peerPublicKey.String())

	// --- 5. Generate and show the client's configuration file ---
	printClientConfig(peerName, newPeerData, serverPublicKey)
}

// runShowPeer generates and displays the client config and QR code for an existing peer.
// This is a read-only operation.
func runShowPeer(peerName string) {
	// 1. Fetch peer data from the database.
	peerData, exists := peerDataMap.Get(peerName)
	if !exists {
		log.Fatalf("Peer with name '%s' not found in the database.", peerName)
	}

	// 2. Get the server's public key from the live interface.
	serverDevice, err := wgClient.Device(argIface)
	if err != nil {
		log.Fatalf("Failed to get device '%s' to retrieve server public key: %v. Is the interface up?", argIface, err)
	}
	serverPublicKey := serverDevice.PublicKey

	printClientConfig(peerName, peerData, serverPublicKey)
}

// printClientConfig generates and displays a client configuration file and a QR code.
// It's used both when adding a new peer and when showing an existing one.
func printClientConfig(peerName string, peerData PeerData, serverPublicKey wgtypes.Key) {
	if len(peerData.Config.AllowedIPs) == 0 {
		log.Fatalf("Cannot generate config for peer '%s': no AllowedIPs found in its data.", peerName)
	}
	peerIP := peerData.Config.AllowedIPs[0].String()

	if peerData.Config.PresharedKey == nil {
		log.Fatalf("Cannot generate config for peer '%s': no PresharedKey found in its data.", peerName)
	}
	psk := peerData.Config.PresharedKey.String()

	clientConfig := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s
DNS = %s

[Peer]
PublicKey = %s
PresharedKey = %s
Endpoint = %s
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`,
		peerData.PrivateKey.String(),
		peerIP,
		config.DNS,
		serverPublicKey.String(),
		psk,
		config.Endpoint,
	)

	fmt.Printf("\n%s%s---------- Client Configuration for '%s' -----------%s\n", colorBlue, colorBold, peerName, colorReset)
	fmt.Println(clientConfig)
	fmt.Printf("%s%s----------------------------------------------------%s\n", colorBlue, colorBold, colorReset)
	fmt.Printf("\n%s%s--------- QR Code (for Mobile) ----------%s\n", colorBlue, colorBold, colorReset)

	qr, err := qrcode.New(clientConfig, qrcode.Medium)
	if err != nil {
		log.Printf("Warning: failed to generate QR code: %v", err)
	} else {
		fmt.Println(qr.ToSmallString(false))
	}
}

// runShowInfo displays detailed information about the live device and persisted peers.
func runShowInfo() {
	// ---- Build a map from PublicKey -> Name for easy lookup ----
	publicKeyToName := make(map[wgtypes.Key]string)
	peerDataMap.Range(func(name string, peer PeerData) bool {
		// The key of the map is the peer name, so we use peer.Config.PublicKey
		publicKeyToName[peer.Config.PublicKey] = name
		return true
	})

	// ---- Live Device Info ----
	fmt.Println("🔎 Live Configuration (from wgctrl)")
	fmt.Println("====================================")
	// We query for the specific device from the flag, not all devices.
	d, err := wgClient.Device(argIface)
	if err != nil {
		// This might happen if the interface doesn't exist yet. It's not a fatal error here.
		fmt.Printf("%sCould not get live info for device '%s': %v%s\n", colorRed, argIface, err, colorReset)
	} else {
		printDeviceDetails(d)

		if len(d.Peers) == 0 {
			fmt.Printf("  %sPeers%s: (none)\n", colorBold, colorReset)
		} else {
			// Sort peers by Name alphabetically
			sort.Slice(d.Peers, func(i, j int) bool {
				nameI, okI := publicKeyToName[d.Peers[i].PublicKey]
				nameJ, okJ := publicKeyToName[d.Peers[j].PublicKey]

				// If name not found (unmanaged peer), push to the end
				if !okI && okJ {
					return false
				}
				if okI && !okJ {
					return true
				}
				if !okI && !okJ {
					// Both unknown, sort by public key
					return d.Peers[i].PublicKey.String() < d.Peers[j].PublicKey.String()
				}

				// Standard alphabet sort
				return nameI < nameJ
			})

			fmt.Printf("  %sPeers (%d):%s\n", colorBold, len(d.Peers), colorReset)
			for _, p := range d.Peers {
				// Pass the lookup map to the print function
				printPeerDetails(p, publicKeyToName)
			}
		}
	}
}

// runDelPeer handles the logic for removing a peer FROM THE DATABASE.
// The main sync logic will then remove it from the live interface.
func runDelPeer(peerName string) {
	// First, check if the peer actually exists in our database.
	if _, exists := peerDataMap.Get(peerName); !exists {
		log.Fatalf("Peer with name '%s' not found in the database. Nothing to delete.", peerName)
	}

	// Attempt to delete the peer from the persistent map.
	if err := peerDataMap.DeleteFSync(peerName); err != nil {
		log.Fatalf("Failed to delete peer '%s' from the persistent store: %v", peerName, err)
	}

	// Provide feedback to the user.
	fmt.Printf("%s[DB]%s Peer '%s' deleted from the database. The change will be synced to the live interface on this run.\n", colorGreen, colorReset, peerName)
}

// printDeviceDetails prints all available fields for a wgtypes.Device.
func printDeviceDetails(d *wgtypes.Device) {
	fmt.Printf("%sInterface:%s %s%s (%s)%s\n", colorBold, colorReset, colorGreen, d.Name, d.Type.String(), colorReset)

	// Helper for formatted key-value printing
	printInfo := func(key, value string) {
		fmt.Printf("  %-14s: %s%s%s\n", key, colorBold, value, colorReset)
	}

	printInfo("Public Key", d.PublicKey.String())
	printInfo("Listen Port", fmt.Sprintf("%d", d.ListenPort))
	if d.FirewallMark > 0 {
		printInfo("Firewall Mark", fmt.Sprintf("%d", d.FirewallMark))
	}
}

// printPeerDetails prints all available fields for a wgtypes.Peer.
func printPeerDetails(p wgtypes.Peer, publicKeyToName map[wgtypes.Key]string) {
	// Look up the friendly name from the map.
	peerName, ok := publicKeyToName[p.PublicKey]
	if !ok {
		peerName = "(unmanaged)"
	}

	// Peer header with public key and our friendly name
	fmt.Printf("  - %sPeer%s: %s%s%s %s[%s]%s\n", colorBold, colorReset, colorYellow, p.PublicKey.String(), colorReset, colorCyan, peerName, colorReset)

	// Helper for indented key-value printing
	printInfo := func(key, value string) {
		fmt.Printf("    %-20s: %s%s%s\n", key, colorBold, value, colorReset)
	}

	var endpointStr string
	if p.Endpoint != nil {
		endpointStr = p.Endpoint.String()
	} else {
		endpointStr = "(none)"
	}
	printInfo("Endpoint", endpointStr)

	var allowedIPs []string
	for _, ipnet := range p.AllowedIPs {
		allowedIPs = append(allowedIPs, ipnet.String())
	}
	printInfo("Allowed IPs", strings.Join(allowedIPs, ", "))

	var handshakeStr string
	if p.LastHandshakeTime.IsZero() {
		handshakeStr = "never"
	} else {
		// More readable time diff
		handshakeStr = fmt.Sprintf("%s ago", time.Since(p.LastHandshakeTime).Round(time.Second))
	}
	printInfo("Last Handshake", handshakeStr)

	printInfo("Transfer", fmt.Sprintf("%s received, %s sent", formatBytes(p.ReceiveBytes), formatBytes(p.TransmitBytes)))

	if p.PersistentKeepaliveInterval > 0 {
		printInfo("Persistent Keepalive", p.PersistentKeepaliveInterval.String())
	}
}

// formatBytes is a helper function to convert byte counts into a human-readable string.
func formatBytes(b int64) string {
	if b < 1024 {
		return fmt.Sprintf("%d B", b)
	}
	const unit = 1024
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

// Helper function to check if a specific flag was passed in the command line arguments
func isFlagPassed(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}
