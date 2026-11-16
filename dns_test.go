package main

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Jipok/wgctrl-go/wgtypes"
	"golang.org/x/net/dns/dnsmessage"
)

type mockNft struct {
	mu      sync.Mutex
	scripts []string
	fail    bool
}

func (m *mockNft) run(script string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return fmt.Errorf("simulated nft failure")
	}
	m.scripts = append(m.scripts, script)
	return nil
}

func TestDomainMatcher(t *testing.T) {
	dir := t.TempDir()
	listFile := filepath.Join(dir, "proxy.lst")
	content := `# Comment
youtube.com
gemini.google.com
*.cdn-*.instagram.com
`
	if err := os.WriteFile(listFile, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	dm := NewDomainMatcher(listFile)
	if dm.Count() != 3 {
		t.Fatalf("expected 3 rules, got %d", dm.Count())
	}

	cases := []struct {
		domain string
		want   bool
	}{
		{"youtube.com", true},
		{"www.youtube.com.", true},
		{"m.youtube.com", true},
		{"notyoutube.com", false},
		{"gemini.google.com", true},
		{"sub.gemini.google.com", true},
		{"mail.google.com", false},
		{"google.com", false},
		{"edge.cdn-eu.instagram.com", true},
		{"ozon.ru", false},
	}

	for _, tc := range cases {
		if got := dm.Match(tc.domain); got != tc.want {
			t.Errorf("Match(%q) = %v, want %v", tc.domain, got, tc.want)
		}
	}
}

func TestFakeIPPoolPersistenceAndEviction(t *testing.T) {
	nft := &mockNft{}

	// /30 has 4 addresses -> 2 usable host IPs (198.18.0.1, 198.18.0.2)
	pool, err := NewFakeIPPool("awg0", "198.18.0.0/30", nft.run, nil)
	if err != nil {
		t.Fatal(err)
	}

	r1 := netip.MustParseAddr("142.250.74.14")
	r2 := netip.MustParseAddr("142.250.74.46")
	rLoop := netip.MustParseAddr("127.0.0.1")
	rCGNAT := netip.MustParseAddr("100.64.0.1")
	mapped, err := pool.MapRealIPs([]netip.Addr{r1, r2, rLoop, rCGNAT})
	if err != nil {
		t.Fatal(err)
	}
	if _, hasLoop := mapped[rLoop]; hasLoop {
		t.Fatalf("loopback IP must not be mapped: %v", mapped)
	}
	if _, hasCGNAT := mapped[rCGNAT]; hasCGNAT {
		t.Fatalf("CGNAT IP must not be mapped: %v", mapped)
	}
	if mapped[r1] != netip.MustParseAddr("198.18.0.1") || mapped[r2] != netip.MustParseAddr("198.18.0.2") {
		t.Fatalf("unexpected mapping: %v", mapped)
	}

	// Verify nft failure during eviction does NOT corrupt in-memory state
	nft.fail = true
	rFail := netip.MustParseAddr("1.2.3.4")
	if _, err := pool.MapRealIPs([]netip.Addr{rFail}); err == nil {
		t.Fatalf("expected error when nft fails")
	}
	if pool.real2fake[r1] != netip.MustParseAddr("198.18.0.1") || pool.real2fake[r2] != netip.MustParseAddr("198.18.0.2") {
		t.Fatalf("in-memory maps corrupted after failed nft transaction: %v", pool.real2fake)
	}
	nft.fail = false

	// Eviction with new IP first and existing IP second in same batch ([r3, r1] in 2-IP pool must keep r1->198.18.0.1 and evict r2->198.18.0.2)
	r3 := netip.MustParseAddr("8.8.4.4")
	mappedBatch, err := pool.MapRealIPs([]netip.Addr{r3, r1})
	if err != nil {
		t.Fatal(err)
	}
	if mappedBatch[r1] != netip.MustParseAddr("198.18.0.1") || mappedBatch[r3] != netip.MustParseAddr("198.18.0.2") {
		t.Fatalf("unexpected batch eviction result: %v", mappedBatch)
	}

	// Reload from kernel liveMap into a fresh pool instance
	pool2, err := NewFakeIPPool("awg0", "198.18.0.0/30", nft.run, pool.fake2real)
	if err != nil {
		t.Fatal(err)
	}
	mapped2, err := pool2.MapRealIPs([]netip.Addr{r1, r3})
	if err != nil {
		t.Fatal(err)
	}
	if mapped2[r1] != mappedBatch[r1] || mapped2[r3] != mappedBatch[r3] {
		t.Fatalf("reloaded mapping mismatch: got %v, want %v", mapped2, mappedBatch)
	}
}

func makeDNSQuery(id uint16, name string, qtype dnsmessage.Type) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName(name),
		Type:  qtype,
		Class: dnsmessage.ClassINET,
	})
	msg, _ := b.Finish()
	return msg
}

func TestFakeDNSServerEndToEnd(t *testing.T) {
	// Start mock upstream UDP DNS server
	upConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upConn.Close()

	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := upConn.ReadFrom(buf)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			hdr, err := p.Start(buf[:n])
			if err != nil {
				continue
			}
			q, err := p.Question()
			if err != nil {
				continue
			}

			b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
				ID:                 hdr.ID,
				Response:           true,
				RecursionDesired:   hdr.RecursionDesired,
				RecursionAvailable: true,
				RCode:              dnsmessage.RCodeSuccess,
			})
			_ = b.StartQuestions()
			_ = b.Question(q)
			_ = b.StartAnswers()

			qname := normalizeDomain(q.Name.String())
			if qname == "www.youtube.com" && q.Type == dnsmessage.TypeA {
				// Return CNAME + 2 A records
				_ = b.CNAMEResource(
					dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 300},
					dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("yt.l.google.com.")},
				)
				_ = b.AResource(
					dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("yt.l.google.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 300},
					dnsmessage.AResource{A: [4]byte{142, 250, 74, 14}},
				)
				_ = b.AResource(
					dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("yt.l.google.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 300},
					dnsmessage.AResource{A: [4]byte{142, 250, 74, 46}},
				)
			} else if qname == "ozon.ru" && q.Type == dnsmessage.TypeA {
				_ = b.AResource(
					dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 120},
					dnsmessage.AResource{A: [4]byte{185, 71, 67, 10}},
				)
			} else if qname == "alias.example.org" {
				// CNAME to proxied youtube.com in Answer, target A in Additional + unrelated NS glue in Additional
				_ = b.CNAMEResource(
					dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 300},
					dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("edge.youtube.com.")},
				)
				if q.Type == dnsmessage.TypeA {
					_ = b.StartAdditionals()
					_ = b.AResource(
						dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("edge.youtube.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 300},
						dnsmessage.AResource{A: [4]byte{142, 250, 74, 99}},
					)
					_ = b.AResource(
						dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("ns1.gtld-servers.net."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 300},
						dnsmessage.AResource{A: [4]byte{192, 5, 6, 30}},
					)
				}
			}
			resp, _ := b.Finish()
			_, _ = upConn.WriteTo(resp, addr)
		}
	}()

	dir := t.TempDir()
	listFile := filepath.Join(dir, "proxy.lst")
	_ = os.WriteFile(listFile, []byte("youtube.com\n"), 0600)

	nft := &mockNft{}
	pool, err := NewFakeIPPool("awg0", "198.18.0.0/15", nft.run, nil)
	if err != nil {
		t.Fatal(err)
	}

	srv := &FakeDNSServer{
		UpstreamDNS: upConn.LocalAddr().String(),
		Matcher:     NewDomainMatcher(listFile),
		Pool:        pool,
		TTL:         60,
		Timeout:     2 * time.Second,
	}

	// 1. Non-proxied domain (ozon.ru) must return real IP 185.71.67.10
	respOzon, err := srv.HandlePacket(makeDNSQuery(101, "ozon.ru.", dnsmessage.TypeA), false)
	if err != nil {
		t.Fatal(err)
	}
	_, _, ozonIPs, err := extractResolvedIPv4s(respOzon)
	if err != nil || len(ozonIPs) != 1 || ozonIPs[0] != netip.MustParseAddr("185.71.67.10") {
		t.Fatalf("expected ozon.ru real IP 185.71.67.10, got %v (err=%v)", ozonIPs, err)
	}

	// 2. Proxied domain (www.youtube.com) A query must resolve CNAME chain, install nft DNAT, and return 198.18.0.1 & 198.18.0.2
	respYT, err := srv.HandlePacket(makeDNSQuery(102, "www.youtube.com.", dnsmessage.TypeA), false)
	if err != nil {
		t.Fatal(err)
	}
	_, _, ytIPs, err := extractResolvedIPv4s(respYT)
	if err != nil || len(ytIPs) != 2 {
		t.Fatalf("expected 2 fake IPs for www.youtube.com, got %v (err=%v)", ytIPs, err)
	}
	if ytIPs[0] != netip.MustParseAddr("198.18.0.1") || ytIPs[1] != netip.MustParseAddr("198.18.0.2") {
		t.Fatalf("unexpected fake IPs: %v", ytIPs)
	}
	if pool.fake2real[netip.MustParseAddr("198.18.0.1")] != netip.MustParseAddr("142.250.74.14") {
		t.Fatalf("pool map missing 198.18.0.1 -> 142.250.74.14: %v", pool.fake2real)
	}

	// 3. Non-proxied domain with CNAME to proxied youtube.com and A in Additional (ignoring NS glue)
	respAlias, err := srv.HandlePacket(makeDNSQuery(104, "alias.example.org.", dnsmessage.TypeA), false)
	if err != nil {
		t.Fatal(err)
	}
	_, _, aliasIPs, err := extractResolvedIPv4s(respAlias)
	if err != nil || len(aliasIPs) != 1 || aliasIPs[0] != netip.MustParseAddr("198.18.0.3") {
		t.Fatalf("expected 1 fake IP 198.18.0.3 for alias.example.org, got %v (err=%v)", aliasIPs, err)
	}
	if pool.fake2real[netip.MustParseAddr("198.18.0.3")] != netip.MustParseAddr("142.250.74.99") {
		t.Fatalf("pool map missing 198.18.0.3 -> 142.250.74.99: %v", pool.fake2real)
	}

	// 4. Both direct proxied domain and CNAME-aliased domain must return empty NOERROR on AAAA and HTTPS (Type 65)
	for _, dom := range []string{"www.youtube.com.", "alias.example.org."} {
		for _, qt := range []dnsmessage.Type{dnsmessage.TypeAAAA, dnsTypeHTTPS} {
			respSuppress, err := srv.HandlePacket(makeDNSQuery(103, dom, qt), false)
			if err != nil {
				t.Fatal(err)
			}
			var p dnsmessage.Parser
			hdr, err := p.Start(respSuppress)
			if err != nil || hdr.RCode != dnsmessage.RCodeSuccess {
				t.Fatalf("expected NOERROR on %s type %v, got hdr=%+v err=%v", dom, qt, hdr, err)
			}
			_ = p.SkipAllQuestions()
			if _, err := p.Answer(); err != dnsmessage.ErrSectionDone {
				t.Fatalf("expected 0 answers for suppressed %s type %v, got err=%v", dom, qt, err)
			}
		}
	}
}

func TestPeerTrafficStatsAccumulation(t *testing.T) {
	key, _ := wgtypes.GeneratePrivateKey()
	pub := key.PublicKey()

	sf := &StatsFile{Interface: "awg0", Peers: make(map[string]PeerTrafficStats)}
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

	// Snapshot 1: 100 MB Rx, 200 MB Tx
	UpdatePeerStatsSnapshot(sf, []wgtypes.Peer{{PublicKey: pub, ReceiveBytes: 100, TransmitBytes: 200}}, now)
	// Snapshot 2: 150 MB Rx, 350 MB Tx (+50, +150)
	UpdatePeerStatsSnapshot(sf, []wgtypes.Peer{{PublicKey: pub, ReceiveBytes: 150, TransmitBytes: 350}}, now.Add(time.Minute))
	// Snapshot 3: kernel reset (interface recreated) -> counters drop to 30, 70 (+30, +70)
	UpdatePeerStatsSnapshot(sf, []wgtypes.Peer{{PublicKey: pub, ReceiveBytes: 30, TransmitBytes: 70}}, now.Add(2*time.Minute))

	st := sf.Peers[pub.String()]
	if st.TotalRx != 180 || st.TotalTx != 420 {
		t.Fatalf("expected TotalRx=180 TotalTx=420, got Rx=%d Tx=%d", st.TotalRx, st.TotalTx)
	}
	day := st.Daily["2026-11-09"]
	if day.Rx != 180 || day.Tx != 420 {
		t.Fatalf("unexpected daily stats: %+v", day)
	}
}
