package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureTunnelInterface(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "commands")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$JWG_TEST_IP_LOG\"\nif [ \"$JWG_TEST_IP_FAIL\" = 1 ]; then echo 'module unavailable' >&2; exit 1; fi\n"
	if err := os.WriteFile(filepath.Join(dir, "ip"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("JWG_TEST_IP_LOG", log)
	t.Setenv("JWG_TEST_IP_FAIL", "0")
	if err := ensureTunnelInterface("lo", true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(log); !os.IsNotExist(err) {
		t.Fatal("existing interface modified")
	}
	for _, tc := range []struct {
		name    string
		amnezia bool
		backend string
	}{
		{"jwgwgtest0", false, "wireguard"},
		{"awgtest0", false, "amneziawg"},
		{"jwgawgtest0", true, "amneziawg"},
	} {
		if err := ensureTunnelInterface(tc.name, tc.amnezia); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(log)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), "link add dev "+tc.name+" type "+tc.backend+"\n") {
			t.Fatalf("unexpected command: %s", data)
		}
	}
	before, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"", "bad name", "a/b", "toolonginterfacename"} {
		if err := ensureTunnelInterface(name, false); err == nil {
			t.Fatalf("accepted %q", name)
		}
	}
	after, _ := os.ReadFile(log)
	if string(before) != string(after) {
		t.Fatal("invalid name invoked ip")
	}
	t.Setenv("JWG_TEST_IP_FAIL", "1")
	if err := ensureTunnelInterface("awgtest1", true); err == nil || !strings.Contains(err.Error(), "module unavailable") {
		t.Fatalf("missing actionable failure: %v", err)
	}
	data, _ := os.ReadFile(log)
	if strings.Contains(string(data), "awgtest1 type wireguard") {
		t.Fatal("AWG failure silently downgraded to WG")
	}

	// Userspace / user-managed interfaces (AutoCreateIface=false) must never be auto-created as kernel wireguard.
	t.Setenv("JWG_TEST_IP_FAIL", "0")
	_ = os.Remove(log)
	userspaceCfg := ServerConfig{Interface: "wgtest_user0", Backend: backendUserspace, AutoCreateIface: false}
	if err := ensureConfigInterface(&userspaceCfg); err == nil {
		t.Fatal("expected error when userspace interface is not running")
	}
	if _, err := os.Stat(log); !os.IsNotExist(err) {
		t.Fatal("userspace config must not invoke ip link add")
	}

	// Self-created kernel interfaces (AutoCreateIface=true) must use the stored Backend regardless of interface name.
	customAWG := ServerConfig{Interface: "wg_custom0", Backend: backendAmneziaWG, AutoCreateIface: true}
	if err := ensureConfigInterface(&customAWG); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(log)
	if !strings.Contains(string(data), "link add dev wg_custom0 type amneziawg\n") {
		t.Fatalf("expected amneziawg creation for custom interface name, got: %s", data)
	}
}
