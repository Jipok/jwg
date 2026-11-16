package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Jipok/wgctrl-go"
	"github.com/Jipok/wgctrl-go/wgtypes"
)

type DailyTraffic struct {
	Rx int64 `json:"rx"`
	Tx int64 `json:"tx"`
}

type PeerTrafficStats struct {
	LastKernelRx int64                   `json:"last_kernel_rx"`
	LastKernelTx int64                   `json:"last_kernel_tx"`
	TotalRx      int64                   `json:"total_rx"`
	TotalTx      int64                   `json:"total_tx"`
	UpdatedAt    int64                   `json:"updated_at"`
	Daily        map[string]DailyTraffic `json:"daily,omitempty"`
}

type StatsFile struct {
	Interface string                      `json:"interface"`
	UpdatedAt int64                       `json:"updated_at"`
	Peers     map[string]PeerTrafficStats `json:"peers"`
}

func statsFilePath(stateDir, iface string) string {
	return filepath.Join(stateDir, fmt.Sprintf("stats_%s.json", iface))
}

func LoadStatsFile(stateDir, iface string) (*StatsFile, error) {
	sf := &StatsFile{Interface: iface, Peers: make(map[string]PeerTrafficStats)}
	data, err := os.ReadFile(statsFilePath(stateDir, iface))
	if err != nil {
		if os.IsNotExist(err) {
			return sf, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(data, sf); err != nil {
		return nil, err
	}
	if sf.Peers == nil {
		sf.Peers = make(map[string]PeerTrafficStats)
	}
	return sf, nil
}

func SaveStatsFile(stateDir, iface string, sf *StatsFile) error {
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return err
	}
	sf.Interface, sf.UpdatedAt = iface, time.Now().Unix()
	data, err := json.MarshalIndent(sf, "", "  ")
	if err != nil {
		return err
	}
	path := statsFilePath(stateDir, iface)
	if err := os.WriteFile(path+".tmp", data, 0600); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}

// UpdatePeerStatsSnapshot applies live kernel counters to the accumulated StatsFile.
func UpdatePeerStatsSnapshot(sf *StatsFile, peers []wgtypes.Peer, now time.Time) {
	if sf.Peers == nil {
		sf.Peers = make(map[string]PeerTrafficStats)
	}
	dayKey := now.UTC().Format("2006-01-02")
	cutoffDay := now.UTC().AddDate(0, 0, -60).Format("2006-01-02")

	for _, p := range peers {
		pub := p.PublicKey.String()
		st := sf.Peers[pub]
		if st.Daily == nil {
			st.Daily = make(map[string]DailyTraffic)
		}

		deltaRx, deltaTx := p.ReceiveBytes, p.TransmitBytes
		if p.ReceiveBytes >= st.LastKernelRx {
			deltaRx = p.ReceiveBytes - st.LastKernelRx
		}
		if p.TransmitBytes >= st.LastKernelTx {
			deltaTx = p.TransmitBytes - st.LastKernelTx
		}

		st.LastKernelRx, st.LastKernelTx = p.ReceiveBytes, p.TransmitBytes
		st.TotalRx += deltaRx
		st.TotalTx += deltaTx
		st.UpdatedAt = now.Unix()

		if deltaRx > 0 || deltaTx > 0 {
			d := st.Daily[dayKey]
			d.Rx += deltaRx
			d.Tx += deltaTx
			st.Daily[dayKey] = d
		}
		for k := range st.Daily {
			if k < cutoffDay {
				delete(st.Daily, k)
			}
		}
		sf.Peers[pub] = st
	}
}

var statsMu sync.Mutex

func CollectAndSavePeerStats(stateDir, iface string) error {
	statsMu.Lock()
	defer statsMu.Unlock()

	client, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer client.Close()
	dev, err := client.Device(iface)
	if err != nil {
		return err
	}
	sf, err := LoadStatsFile(stateDir, iface)
	if err != nil {
		return err
	}
	UpdatePeerStatsSnapshot(sf, dev.Peers, time.Now())
	return SaveStatsFile(stateDir, iface, sf)
}
