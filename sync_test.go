package main

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/Jipok/wgctrl-go/wgtypes"
)

func TestNonInteractiveStdin(t *testing.T) {
	old := os.Stdin
	defer func() { os.Stdin = old }()
	f, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	os.Stdin = f
	if isInteractiveTerminal() {
		t.Fatal("/dev/null is not a terminal")
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	os.Stdin = r
	if isInteractiveTerminal() {
		t.Fatal("a pipe is not a terminal")
	}
}

func TestPeerConfigChanges(t *testing.T) {
	var k1, k2, k3, psk wgtypes.Key
	k1[0], k2[0], k3[0], psk[0] = 1, 2, 3, 4
	_, ip1, _ := net.ParseCIDR("10.8.0.2/32")
	_, ip2, _ := net.ParseCIDR("10.8.0.3/32")
	live := []wgtypes.Peer{{PublicKey: k1, PresharedKey: psk, AllowedIPs: []net.IPNet{*ip1}, Endpoint: &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1234}, ReceiveBytes: 100, LastHandshakeTime: time.Now()}}
	first := wgtypes.PeerConfig{PublicKey: k1, PresharedKey: &psk, AllowedIPs: []net.IPNet{*ip1}, ReplaceAllowedIPs: true}
	second := wgtypes.PeerConfig{PublicKey: k2, PresharedKey: &psk, AllowedIPs: []net.IPNet{*ip2}, ReplaceAllowedIPs: true}
	if changes := peerConfigChanges([]wgtypes.PeerConfig{first}, live); len(changes) != 0 {
		t.Fatalf("unchanged peer updated: %+v", changes)
	}
	changes := peerConfigChanges([]wgtypes.PeerConfig{first, second}, live)
	if len(changes) != 1 || changes[0].PublicKey != k2 || changes[0].Remove {
		t.Fatalf("add touched another peer: %+v", changes)
	}
	changes = peerConfigChanges(nil, live)
	if len(changes) != 1 || changes[0].PublicKey != k1 || !changes[0].Remove {
		t.Fatalf("incorrect removal: %+v", changes)
	}
	first.AllowedIPs = []net.IPNet{*ip2}
	changes = peerConfigChanges([]wgtypes.PeerConfig{first}, live)
	if len(changes) != 1 || !changes[0].ReplaceAllowedIPs {
		t.Fatalf("allowed IP change not reconciled: %+v", changes)
	}
	first.PublicKey = k3
	changes = peerConfigChanges([]wgtypes.PeerConfig{first}, live)
	if len(changes) != 2 {
		t.Fatalf("same-count drift not reconciled: %+v", changes)
	}
}
