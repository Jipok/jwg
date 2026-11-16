package main

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestUDPReplyLimits(t *testing.T) {
	q := dnsmessage.Question{Name: dnsmessage.MustNewName("large.example."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	for _, tc := range []struct {
		name      string
		edns      uint16
		count     int
		truncated bool
	}{
		{"legacy-small", 0, 2, false}, {"legacy-large", 0, 40, true},
		{"edns-512", 512, 40, true}, {"edns-too-small", 128, 40, true},
		{"edns-1232", 1232, 40, false}, {"edns-client-limit", 600, 40, true},
		{"edns-large-capped", 4096, 100, true}, {"edns-1232-large", 1232, 100, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 42, RecursionDesired: true})
			_ = b.StartQuestions()
			_ = b.Question(q)
			if tc.edns != 0 {
				_ = b.StartAdditionals()
				_ = b.OPTResource(dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("."), Type: dnsmessage.TypeOPT, Class: dnsmessage.Class(tc.edns)}, dnsmessage.OPTResource{})
			}
			query, err := b.Finish()
			if err != nil {
				t.Fatal(err)
			}
			var ips []netip.Addr
			for ip := netip.MustParseAddr("198.18.0.1"); len(ips) < tc.count; ip = ip.Next() {
				ips = append(ips, ip)
			}
			response, err := buildDNSReply(dnsmessage.Header{ID: 42, RecursionDesired: true}, q, dnsmessage.RCodeSuccess, ips, 60)
			if err != nil {
				t.Fatal(err)
			}
			limited, err := limitUDPReply(query, response)
			if err != nil {
				t.Fatal(err)
			}
			var p dnsmessage.Parser
			h, err := p.Start(limited)
			if err != nil {
				t.Fatal(err)
			}
			if h.Truncated != tc.truncated || h.ID != 42 || !h.Response {
				t.Fatalf("bad header: %+v", h)
			}
			questions, err := p.AllQuestions()
			if err != nil || len(questions) != 1 || questions[0] != q {
				t.Fatalf("bad questions: %v %v", questions, err)
			}
			answers, err := p.AllAnswers()
			if err != nil {
				t.Fatal(err)
			}
			if tc.truncated {
				if len(limited) > 512 || len(answers) != 0 {
					t.Fatalf("bad truncated reply: %d bytes, %d answers", len(limited), len(answers))
				}
			} else if len(answers) != tc.count {
				t.Fatalf("lost answers: %d", len(answers))
			}
		})
	}
}

func TestDNSUDPTruncationAndTCPRetry(t *testing.T) {
	// A TCP-only upstream forces the forwarder to fall back from UDP to TCP.
	up, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	go func() {
		for {
			c, err := up.Accept()
			if err != nil {
				return
			}
			func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(time.Second))
				q, err := readTCPDNS(c)
				if err != nil {
					return
				}
				var p dnsmessage.Parser
				h, err := p.Start(q)
				if err != nil {
					return
				}
				question, err := p.Question()
				if err != nil {
					return
				}
				var ips []netip.Addr
				for ip := netip.MustParseAddr("8.8.8.1"); len(ips) < 100; ip = ip.Next() {
					ips = append(ips, ip)
				}
				r, err := buildDNSReply(h, question, dnsmessage.RCodeSuccess, ips, 60)
				if err == nil {
					_ = writeTCPDNS(c, r)
				}
			}()
		}
	}()
	s := &FakeDNSServer{UpstreamDNS: up.Addr().String(), Timeout: time.Second}
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	tcp, err := net.Listen("tcp", udp.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	go func() { _ = s.ServeUDP(udp) }()
	go func() { _ = s.ServeTCP(tcp) }()
	query := makeDNSQuery(99, "large.example.", dnsmessage.TypeA)
	c, err := net.DialTimeout("udp", udp.LocalAddr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err = c.Write(query); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	var p dnsmessage.Parser
	h, err := p.Start(buf[:n])
	if err != nil || !h.Truncated || n > 512 {
		t.Fatalf("expected short TC reply: %d %+v %v", n, h, err)
	}
	conn, err := net.DialTimeout("tcp", tcp.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	if err = writeTCPDNS(conn, query); err != nil {
		t.Fatal(err)
	}
	resp, err := readTCPDNS(conn)
	if err != nil {
		t.Fatal(err)
	}
	h, err = p.Start(resp)
	if err != nil || h.Truncated || len(resp) <= 1232 {
		t.Fatalf("expected complete TCP reply: %d %+v %v", len(resp), h, err)
	}
	if err = p.SkipAllQuestions(); err != nil {
		t.Fatal(err)
	}
	answers, err := p.AllAnswers()
	if err != nil || len(answers) != 100 {
		t.Fatalf("TCP retry lost answers: %d %v", len(answers), err)
	}
}

func TestDNSHealthWithoutUpstream(t *testing.T) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 23})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName("health.jwg."), Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassCHAOS})
	q, _ := b.Finish()
	s := &FakeDNSServer{}
	for _, tcp := range []bool{false, true} {
		r, err := s.HandlePacket(q, tcp)
		if err != nil {
			t.Fatal(err)
		}
		var p dnsmessage.Parser
		h, err := p.Start(r)
		if err != nil || !h.Response || h.ID != 23 || h.RCode != dnsmessage.RCodeSuccess {
			t.Fatalf("health failed: %+v %v", h, err)
		}
	}
}
