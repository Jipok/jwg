package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/Jipok/wgctrl-go"
	"github.com/Jipok/wgctrl-go/wgtypes"
)

const (
	backendAmneziaWG = "amneziawg"
	backendWireGuard = "wireguard"
	backendUserspace = "userspace"
)

func kernelModuleAvailable(name string) bool {
	if _, err := os.Stat("/sys/module/" + name); err == nil {
		return true
	}
	return exec.Command("modprobe", "-n", "-q", name).Run() == nil
}

// detectExistingTunnelInterface checks whether a WireGuard/AmneziaWG interface is already present.
func detectExistingTunnelInterface() (name string, isUserspace bool, isAmnezia bool) {
	client, err := wgctrl.New()
	if err == nil {
		defer client.Close()
		for _, candidate := range []string{defaultIface, "awg0"} {
			if d, err := client.Device(candidate); err == nil {
				return d.Name, d.Type == wgtypes.Userspace, d.IsAmnezia
			}
		}
		if devs, err := client.Devices(); err == nil && len(devs) > 0 {
			d := devs[0]
			return d.Name, d.Type == wgtypes.Userspace, d.IsAmnezia
		}
	}
	for _, candidate := range []string{defaultIface, "awg0"} {
		if _, err := net.InterfaceByName(candidate); err == nil {
			return candidate, false, strings.HasPrefix(candidate, "awg")
		}
	}
	return "", false, false
}

func defaultTunnelInterface() string {
	if name, _, _ := detectExistingTunnelInterface(); name != "" {
		return name
	}
	if _, err := os.Stat("/etc/sv/jwg-awg0/run"); err == nil || kernelModuleAvailable(backendAmneziaWG) {
		return "awg0"
	}
	return defaultIface
}

// inferLegacyBackend fills Backend and AutoCreateIface for databases created before 3.0.0
// or non-interactive runs with explicit CLI flags.
func inferLegacyBackend(cfg *ServerConfig) (changed bool) {
	if cfg.Backend != "" {
		return false
	}
	if client, err := wgctrl.New(); err == nil {
		defer client.Close()
		if d, err := client.Device(cfg.Interface); err == nil {
			if d.Type == wgtypes.Userspace {
				cfg.Backend = backendUserspace
				cfg.AutoCreateIface = false
				return true
			}
			if d.IsAmnezia {
				cfg.Backend = backendAmneziaWG
			} else {
				cfg.Backend = backendWireGuard
			}
			cfg.AutoCreateIface = true
			return true
		}
	}
	if cfg.AmnezJc != 0 || cfg.AmnezH1 != "" || strings.HasPrefix(cfg.Interface, "awg") {
		cfg.Backend = backendAmneziaWG
		cfg.AutoCreateIface = true
		return true
	}
	cfg.Backend = backendWireGuard
	cfg.AutoCreateIface = true
	return true
}

func createKernelInterface(name, backend string) (created bool, err error) {
	if _, err := net.InterfaceByName(name); err == nil {
		return false, nil
	}
	if name == "" || len(name) > 15 || strings.ContainsAny(name, "/: \t\r\n") {
		return false, fmt.Errorf("invalid tunnel interface name %q", name)
	}
	if backend != backendAmneziaWG && backend != backendWireGuard {
		return false, fmt.Errorf("unsupported kernel backend %q", backend)
	}
	out, err := exec.Command("ip", "link", "add", "dev", name, "type", backend).CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("create %s (%s): %w: %s; install the %s module for the running kernel or start its userspace daemon", name, backend, err, strings.TrimSpace(string(out)), backend)
	}
	fmt.Printf("%s[OK]%s Created kernel %s interface %s.\n", colorGreen, colorReset, backend, name)
	return true, nil
}

func ensureConfigInterface(cfg *ServerConfig) error {
	if _, err := net.InterfaceByName(cfg.Interface); err == nil {
		return nil
	}
	if !cfg.AutoCreateIface || cfg.Backend == backendUserspace {
		return fmt.Errorf("interface %q is not running (expected existing/userspace interface)", cfg.Interface)
	}
	backend := cfg.Backend
	if backend == "" {
		if cfg.AmnezJc != 0 || cfg.AmnezH1 != "" || strings.HasPrefix(cfg.Interface, "awg") {
			backend = backendAmneziaWG
		} else {
			backend = backendWireGuard
		}
	}
	_, err := createKernelInterface(cfg.Interface, backend)
	return err
}

func ensureTunnelInterface(name string, amnezia bool) error {
	backend := backendWireGuard
	if amnezia || strings.HasPrefix(name, "awg") {
		backend = backendAmneziaWG
	}
	_, err := createKernelInterface(name, backend)
	return err
}
