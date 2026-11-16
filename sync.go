package main

import (
	"net"
	"slices"
	"sort"
	"time"

	"github.com/Jipok/wgctrl-go/wgtypes"
)

// peerConfigChanges leaves unchanged peers (including discovered endpoints and counters) alone.
func peerConfigChanges(desired []wgtypes.PeerConfig, live []wgtypes.Peer) []wgtypes.PeerConfig {
	current := make(map[wgtypes.Key]wgtypes.Peer, len(live))
	for _, p := range live {
		current[p.PublicKey] = p
	}
	var changes []wgtypes.PeerConfig
	for _, p := range desired {
		old, exists := current[p.PublicKey]
		delete(current, p.PublicKey)
		var psk wgtypes.Key
		if p.PresharedKey != nil {
			psk = *p.PresharedKey
		}
		var keepalive time.Duration
		if p.PersistentKeepaliveInterval != nil {
			keepalive = *p.PersistentKeepaliveInterval
		}
		if exists && old.PresharedKey == psk && old.PersistentKeepaliveInterval == keepalive && slices.Equal(ipNetStrings(old.AllowedIPs), ipNetStrings(p.AllowedIPs)) {
			continue
		}
		p.ReplaceAllowedIPs = true
		changes = append(changes, p)
	}
	for key := range current {
		changes = append(changes, wgtypes.PeerConfig{PublicKey: key, Remove: true})
	}
	return changes
}

func ipNetStrings(ips []net.IPNet) []string {
	out := make([]string, len(ips))
	for i, ip := range ips {
		out[i] = ip.String()
	}
	sort.Strings(out)
	return out
}
