package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	defaultFakeCIDR    = "198.18.0.0/15"
	defaultUpstreamDNS = "1.1.1.1:53"
	defaultFakeDNSTTL  = 60
	dnsTypeHTTPS       = dnsmessage.Type(65)
	dnsTypeSVCB        = dnsmessage.Type(64)
)

var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

// DomainMatcher holds suffix rules and wildcard (*) patterns loaded once at startup from proxy.lst.
type DomainMatcher struct {
	suffixes map[string]struct{}
	patterns []string
}

func NewDomainMatcher(sources string) *DomainMatcher {
	dm := &DomainMatcher{suffixes: make(map[string]struct{})}
	for _, src := range strings.Split(sources, ",") {
		src = strings.TrimSpace(src)
		if src == "" {
			continue
		}
		data, err := os.ReadFile(src)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			if idx := strings.IndexByte(line, '#'); idx != -1 {
				line = line[:idx]
			}
			if line = normalizeDomain(line); line == "" {
				continue
			}
			if strings.Contains(line, "*") {
				dm.patterns = append(dm.patterns, line)
			} else if line = strings.TrimPrefix(line, "."); line != "" {
				dm.suffixes[line] = struct{}{}
			}
		}
	}
	return dm
}

func normalizeDomain(d string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
}

func (dm *DomainMatcher) Match(domain string) bool {
	domain = normalizeDomain(domain)
	if domain == "" {
		return false
	}
	for cur := domain; ; {
		if _, ok := dm.suffixes[cur]; ok {
			return true
		}
		idx := strings.IndexByte(cur, '.')
		if idx == -1 {
			break
		}
		cur = cur[idx+1:]
	}
	for _, pat := range dm.patterns {
		if ok, _ := path.Match(pat, domain); ok {
			return true
		}
	}
	return false
}

func (dm *DomainMatcher) Count() int {
	return len(dm.suffixes) + len(dm.patterns)
}

var nftPairRegex = regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)\s*:\s*(\d+\.\d+\.\d+\.\d+)`)

func execNftScript(script string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft failed: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func listNftFakeIPMap(iface string) (map[netip.Addr]netip.Addr, error) {
	out, err := exec.Command("nft", "list", "map", "ip", "jwg_dns_"+iface, "fakeip_dnat").Output()
	if err != nil {
		return nil, err
	}
	res := make(map[netip.Addr]netip.Addr)
	for _, m := range nftPairRegex.FindAllStringSubmatch(string(out), -1) {
		fIP, err1 := netip.ParseAddr(m[1])
		rIP, err2 := netip.ParseAddr(m[2])
		if err1 == nil && err2 == nil {
			res[fIP] = rIP
		}
	}
	return res, nil
}

func ipToU32(ip netip.Addr) uint32 {
	b := ip.As4()
	return binary.BigEndian.Uint32(b[:])
}

func u32ToIP(v uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}

func isPublicIPv4(ip netip.Addr) bool {
	if !ip.IsValid() || !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsPrivate() || cgnatPrefix.Contains(ip) {
		return false
	}
	b := ip.As4()
	return b[0] < 240 // exclude 240.0.0.0/4 (Class E / broadcast)
}

// FakeIPPool manages the 1-to-1 bijection real_ip <-> fake_ip in the kernel nftables map.
type FakeIPPool struct {
	mu        sync.Mutex
	iface     string
	prefix    netip.Prefix
	firstIP   uint32
	lastIP    uint32
	cursor    uint32
	real2fake map[netip.Addr]netip.Addr
	fake2real map[netip.Addr]netip.Addr
	lastUsed  map[netip.Addr]int64
	runNft    func(script string) error
}

func NewFakeIPPool(iface, fakeCIDR string, runNft func(string) error, liveMap map[netip.Addr]netip.Addr) (*FakeIPPool, error) {
	prefix, err := netip.ParsePrefix(fakeCIDR)
	if err != nil || !prefix.Addr().Is4() {
		return nil, fmt.Errorf("invalid fake CIDR %q: %v", fakeCIDR, err)
	}
	prefix = prefix.Masked()
	bits := prefix.Bits()
	base := ipToU32(prefix.Addr())
	total := uint32(1) << (32 - bits)
	if total <= 2 {
		return nil, fmt.Errorf("fake CIDR %q too small", fakeCIDR)
	}

	p := &FakeIPPool{
		iface:     iface,
		prefix:    prefix,
		firstIP:   base + 1,
		lastIP:    base + total - 2,
		cursor:    base + 1,
		real2fake: make(map[netip.Addr]netip.Addr),
		fake2real: make(map[netip.Addr]netip.Addr),
		lastUsed:  make(map[netip.Addr]int64),
		runNft:    runNft,
	}

	now := time.Now().Unix()
	for fIP, rIP := range liveMap {
		if fIP.IsValid() && fIP.Is4() && isPublicIPv4(rIP) && !prefix.Contains(rIP) {
			if u := ipToU32(fIP); u >= p.firstIP && u <= p.lastIP {
				p.bindLocked(rIP, fIP, now)
			}
		}
	}

	if runNft != nil {
		table := "jwg_dns_" + iface
		var elemLine string
		if len(p.fake2real) > 0 {
			elems := make([]string, 0, len(p.fake2real))
			for fIP, rIP := range p.fake2real {
				elems = append(elems, fmt.Sprintf("%s : %s", fIP, rIP))
			}
			sort.Strings(elems)
			elemLine = fmt.Sprintf("add element ip %s fakeip_dnat { %s }\n", table, strings.Join(elems, ", "))
		}
		script := fmt.Sprintf(`add table ip %[1]s
delete table ip %[1]s
add table ip %[1]s
add map ip %[1]s fakeip_dnat { type ipv4_addr : ipv4_addr; size %[5]d; }
%[4]sadd chain ip %[1]s prerouting { type nat hook prerouting priority -50; policy accept; }
add rule ip %[1]s prerouting iifname "%[2]s" ip daddr %[3]s dnat to ip daddr map @fakeip_dnat
add chain ip %[1]s forward { type filter hook forward priority -10; policy accept; }
add rule ip %[1]s forward iifname "%[2]s" ip daddr %[3]s counter reject with icmp type host-unreachable
`, table, iface, prefix, elemLine, total)
		if err := runNft(script); err != nil {
			return nil, err
		}
	}

	return p, nil
}

func (p *FakeIPPool) bindLocked(realIP, fakeIP netip.Addr, ts int64) {
	if _, used := p.fake2real[fakeIP]; !used {
		if _, mapped := p.real2fake[realIP]; !mapped {
			p.real2fake[realIP] = fakeIP
			p.fake2real[fakeIP] = realIP
			p.lastUsed[fakeIP] = ts
		}
	}
}

func (p *FakeIPPool) Count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.fake2real)
}

// MapRealIPs maps real IPv4 addresses to fake IPs, installing new rules into nftables BEFORE mutating pool state.
func (p *FakeIPPool) MapRealIPs(realIPs []netip.Addr) (map[netip.Addr]netip.Addr, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now().Unix()
	result := make(map[netip.Addr]netip.Addr, len(realIPs))
	newPairs := make(map[netip.Addr]netip.Addr)
	reserved := make(map[netip.Addr]struct{}, len(realIPs))
	evictedMap := make(map[netip.Addr]netip.Addr) // fakeIP -> oldRealIP
	nextCursor := p.cursor

	// Pass 1: reserve all already-mapped fake IPs for the input batch so Pass 2 cannot evict them.
	for _, rIP := range realIPs {
		if !isPublicIPv4(rIP) || p.prefix.Contains(rIP) {
			continue
		}
		if fIP, ok := p.real2fake[rIP]; ok {
			result[rIP] = fIP
			reserved[fIP] = struct{}{}
		}
	}

	// Pass 2: allocate new fake IPs for unmapped real IPs.
	for _, rIP := range realIPs {
		if !isPublicIPv4(rIP) || p.prefix.Contains(rIP) {
			continue
		}
		if _, ok := result[rIP]; ok {
			continue
		}

		fIP, wasEvicted, oldReal, newCur := p.planNextLocked(nextCursor, reserved)
		if !fIP.IsValid() {
			return nil, fmt.Errorf("no fake IP available in pool %s", p.prefix)
		}
		nextCursor = newCur
		reserved[fIP] = struct{}{}
		if wasEvicted {
			evictedMap[fIP] = oldReal
		}
		newPairs[fIP] = rIP
		result[rIP] = fIP
	}

	if len(newPairs) > 0 && p.runNft != nil {
		table := "jwg_dns_" + p.iface
		var sb strings.Builder
		if len(evictedMap) > 0 {
			evicted := make([]string, 0, len(evictedMap))
			for fIP := range evictedMap {
				evicted = append(evicted, fIP.String())
			}
			sb.WriteString(fmt.Sprintf("delete element ip %s fakeip_dnat { %s }\n", table, strings.Join(evicted, ", ")))
		}
		elems := make([]string, 0, len(newPairs))
		for fIP, rIP := range newPairs {
			elems = append(elems, fmt.Sprintf("%s : %s", fIP, rIP))
		}
		sb.WriteString(fmt.Sprintf("add element ip %s fakeip_dnat { %s }\n", table, strings.Join(elems, ", ")))
		if err := p.runNft(sb.String()); err != nil {
			return nil, err
		}
	}

	p.cursor = nextCursor
	for fIP, oldReal := range evictedMap {
		delete(p.real2fake, oldReal)
		delete(p.fake2real, fIP)
		delete(p.lastUsed, fIP)
	}
	for _, fIP := range result {
		p.lastUsed[fIP] = now
	}
	for fIP, rIP := range newPairs {
		p.real2fake[rIP] = fIP
		p.fake2real[fIP] = rIP
	}

	return result, nil
}

func (p *FakeIPPool) planNextLocked(cursor uint32, reserved map[netip.Addr]struct{}) (fakeIP netip.Addr, evicted bool, oldReal netip.Addr, nextCursor uint32) {
	span := p.lastIP - p.firstIP + 1
	for i := uint32(0); i < span; i++ {
		ipInt := p.firstIP + ((cursor - p.firstIP + i) % span)
		cand := u32ToIP(ipInt)
		if _, inUse := p.fake2real[cand]; !inUse {
			if _, inBatch := reserved[cand]; !inBatch {
				nextCursor = p.firstIP + ((ipInt - p.firstIP + 1) % span)
				return cand, false, netip.Addr{}, nextCursor
			}
		}
	}

	var oldestFake netip.Addr
	var oldestTS int64 = 1<<62 - 1
	for fIP, rIP := range p.fake2real {
		if _, inBatch := reserved[fIP]; !inBatch {
			if ts := p.lastUsed[fIP]; !oldestFake.IsValid() || ts < oldestTS {
				oldestFake, oldestTS, oldReal = fIP, ts, rIP
			}
		}
	}
	return oldestFake, oldestFake.IsValid(), oldReal, cursor
}

// --- DNS Parsing & Rewriting (using golang.org/x/net/dns/dnsmessage) ---

// extractResolvedIPv4s parses a DNS response (Answer + Authority + Additional),
// resolves the CNAME chain starting from the queried name (like dnsr/dns-parse.go
// so A records in Additional for CNAMEs are found without grabbing unrelated NS glue),
// and returns the header, all domain names in the CNAME chain, and deduplicated public IPv4s.
func extractResolvedIPv4s(dnsPayload []byte) (dnsmessage.Header, []string, []netip.Addr, error) {
	var p dnsmessage.Parser
	hdr, err := p.Start(dnsPayload)
	if err != nil {
		return hdr, nil, nil, err
	}
	questions, err := p.AllQuestions()
	if err != nil && err != dnsmessage.ErrSectionDone {
		p.Start(dnsPayload)
		if err := p.SkipAllQuestions(); err != nil {
			return hdr, nil, nil, err
		}
	}

	var requestedName string
	if len(questions) > 0 {
		requestedName = normalizeDomain(questions[0].Name.String())
	}

	cnameMap := make(map[string]string)
	ipMap := make(map[string][]netip.Addr)
	var answerIPs []netip.Addr

	processRR := func(rr dnsmessage.Resource, inAnswer bool) {
		name := normalizeDomain(rr.Header.Name.String())
		switch rr.Header.Type {
		case dnsmessage.TypeCNAME:
			if body, ok := rr.Body.(*dnsmessage.CNAMEResource); ok {
				cnameMap[name] = normalizeDomain(body.CNAME.String())
			}
		case dnsmessage.TypeA:
			if body, ok := rr.Body.(*dnsmessage.AResource); ok {
				ip := netip.AddrFrom4(body.A)
				if isPublicIPv4(ip) {
					ipMap[name] = append(ipMap[name], ip)
					if inAnswer {
						answerIPs = append(answerIPs, ip)
					}
				}
			}
		}
	}

	for {
		rr, err := p.Answer()
		if err != nil {
			break
		}
		processRR(rr, true)
	}
	for {
		rr, err := p.Authority()
		if err != nil {
			break
		}
		processRR(rr, false)
	}
	for {
		rr, err := p.Additional()
		if err != nil {
			break
		}
		processRR(rr, false)
	}

	seen := make(map[netip.Addr]struct{})
	var out []netip.Addr
	addIP := func(ip netip.Addr) {
		if _, ok := seen[ip]; !ok {
			seen[ip] = struct{}{}
			out = append(out, ip)
		}
	}

	var chainNames []string
	visited := make(map[string]struct{})
	for cur := requestedName; cur != "" && len(visited) < 10; {
		if _, dup := visited[cur]; dup {
			break
		}
		visited[cur] = struct{}{}
		chainNames = append(chainNames, cur)
		for _, ip := range ipMap[cur] {
			addIP(ip)
		}
		cur = cnameMap[cur]
	}

	// Fallback: if Answer had A records not linked via requestedName, don't drop them.
	// (NS glue records only live in Additional, never in Answer.)
	if len(out) == 0 {
		for _, ip := range answerIPs {
			addIP(ip)
		}
	}

	return hdr, chainNames, out, nil
}

func buildDNSReply(reqHdr dnsmessage.Header, q dnsmessage.Question, rcode dnsmessage.RCode, fakeIPs []netip.Addr, ttl uint32) ([]byte, error) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:                 reqHdr.ID,
		Response:           true,
		OpCode:             reqHdr.OpCode,
		RecursionDesired:   reqHdr.RecursionDesired,
		RecursionAvailable: true,
		RCode:              rcode,
	})
	b.EnableCompression()
	_ = b.StartQuestions()
	_ = b.Question(q)
	if len(fakeIPs) > 0 {
		_ = b.StartAnswers()
		for _, ip := range fakeIPs {
			_ = b.AResource(
				dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: ttl},
				dnsmessage.AResource{A: ip.As4()},
			)
		}
	}
	return b.Finish()
}

// FakeDNSServer handles UDP and TCP DNS requests for a WireGuard tunnel.
type FakeDNSServer struct {
	ListenAddr  string
	UpstreamDNS string
	Matcher     *DomainMatcher
	Pool        *FakeIPPool
	TTL         uint32
	Timeout     time.Duration
}

func (s *FakeDNSServer) HandlePacket(rawQuery []byte, forceTCP bool) (resp []byte, err error) {
	if !forceTCP {
		defer func() {
			if err == nil {
				resp, err = limitUDPReply(rawQuery, resp)
			}
		}()
	}
	var p dnsmessage.Parser
	reqHdr, err := p.Start(rawQuery)
	if err != nil {
		return nil, err
	}
	q, err := p.Question()
	if err != nil {
		return s.queryUpstream(rawQuery, forceTCP)
	}

	qName := normalizeDomain(q.Name.String())
	if qName == "health.jwg" && q.Class == dnsmessage.ClassCHAOS && q.Type == dnsmessage.TypeTXT {
		return buildDNSReply(reqHdr, q, dnsmessage.RCodeSuccess, nil, 0)
	}
	isProxied := s.Matcher != nil && s.Matcher.Match(qName)

	ttl := s.TTL
	if ttl == 0 {
		ttl = defaultFakeDNSTTL
	}
	isSuppressType := q.Type == dnsmessage.TypeAAAA || q.Type == dnsTypeHTTPS || q.Type == dnsTypeSVCB
	if isProxied && isSuppressType {
		return buildDNSReply(reqHdr, q, dnsmessage.RCodeSuccess, nil, ttl)
	}
	if (q.Type != dnsmessage.TypeA && !isSuppressType) || s.Matcher == nil {
		return s.queryUpstream(rawQuery, forceTCP)
	}

	upResp, err := s.queryUpstream(rawQuery, forceTCP)
	if err != nil {
		if isProxied {
			return buildDNSReply(reqHdr, q, dnsmessage.RCodeServerFailure, nil, ttl)
		}
		return nil, err
	}
	upHdr, chainNames, realIPs, err := extractResolvedIPv4s(upResp)
	if err != nil {
		if isProxied {
			return buildDNSReply(reqHdr, q, dnsmessage.RCodeServerFailure, nil, ttl)
		}
		return upResp, nil
	}
	if !isProxied {
		for _, name := range chainNames {
			if s.Matcher.Match(name) {
				isProxied = true
				break
			}
		}
	}
	if !isProxied {
		return upResp, nil
	}
	if isSuppressType {
		return buildDNSReply(reqHdr, q, dnsmessage.RCodeSuccess, nil, ttl)
	}
	if upHdr.RCode != dnsmessage.RCodeSuccess || len(realIPs) == 0 {
		return upResp, nil
	}

	mapped, err := s.Pool.MapRealIPs(realIPs)
	if err != nil {
		log.Printf("[DNS] Failed to map IPs for %s: %v", qName, err)
		return buildDNSReply(reqHdr, q, dnsmessage.RCodeServerFailure, nil, ttl)
	}

	fakeIPs := make([]netip.Addr, 0, len(realIPs))
	for _, rIP := range realIPs {
		fIP, ok := mapped[rIP]
		if !ok || !fIP.IsValid() {
			return buildDNSReply(reqHdr, q, dnsmessage.RCodeServerFailure, nil, ttl)
		}
		fakeIPs = append(fakeIPs, fIP)
	}
	return buildDNSReply(reqHdr, q, dnsmessage.RCodeSuccess, fakeIPs, ttl)
}

func (s *FakeDNSServer) queryUpstream(rawQuery []byte, useTCP bool) ([]byte, error) {
	timeout := s.Timeout
	if timeout == 0 {
		timeout = 4 * time.Second
	}
	var reqID uint16
	if len(rawQuery) >= 2 {
		reqID = binary.BigEndian.Uint16(rawQuery[:2])
	}
	var lastErr error
	for _, up := range strings.Split(s.UpstreamDNS, ",") {
		if up = strings.TrimSpace(up); up == "" {
			continue
		}
		if !strings.Contains(up, ":") {
			up += ":53"
		}
		if !useTCP {
			if c, err := net.DialTimeout("udp", up, timeout); err == nil {
				_ = c.SetDeadline(time.Now().Add(timeout))
				_, err = c.Write(rawQuery)
				buf := make([]byte, 4096)
				n, rerr := c.Read(buf)
				c.Close()
				if err == nil && rerr == nil {
					var p dnsmessage.Parser
					if hdr, perr := p.Start(buf[:n]); perr == nil && hdr.Response && hdr.ID == reqID {
						if !hdr.Truncated {
							return buf[:n], nil
						}
					} else if perr != nil {
						lastErr = perr
					}
				} else if rerr != nil {
					lastErr = rerr
				} else {
					lastErr = err
				}
			} else {
				lastErr = err
			}
		}
		c, err := net.DialTimeout("tcp", up, timeout)
		if err != nil {
			lastErr = err
			continue
		}
		_ = c.SetDeadline(time.Now().Add(timeout))
		err = writeTCPDNS(c, rawQuery)
		var resp []byte
		if err == nil {
			resp, err = readTCPDNS(c)
		}
		c.Close()
		if err == nil {
			var p dnsmessage.Parser
			if hdr, perr := p.Start(resp); perr == nil && hdr.Response && hdr.ID == reqID {
				return resp, nil
			} else if perr != nil {
				err = perr
			} else {
				err = fmt.Errorf("unexpected TCP DNS response header")
			}
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no upstream DNS servers configured")
	}
	return nil, lastErr
}

func readTCPDNS(r io.Reader) ([]byte, error) {
	var msgLen uint16
	if err := binary.Read(r, binary.BigEndian, &msgLen); err != nil {
		return nil, err
	}
	if msgLen == 0 {
		return nil, io.ErrUnexpectedEOF
	}
	buf := make([]byte, msgLen)
	_, err := io.ReadFull(r, buf)
	return buf, err
}

func writeTCPDNS(w io.Writer, msg []byte) error {
	if len(msg) > 65535 {
		return fmt.Errorf("dns message too large: %d", len(msg))
	}
	buf := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(msg)))
	copy(buf[2:], msg)
	_, err := w.Write(buf)
	return err
}

// limitUDPReply honors the client's EDNS limit, capped at 1232 to avoid fragmentation.
// A short TC reply keeps DNS compression pointers valid and lets the client retry over TCP.
func limitUDPReply(query, response []byte) ([]byte, error) {
	limit := 512
	var p dnsmessage.Parser
	if _, err := p.Start(query); err != nil {
		return nil, err
	}
	questions, err := p.AllQuestions()
	if err != nil {
		return nil, err
	}
	if err := p.SkipAllAnswers(); err != nil {
		return nil, err
	}
	if err := p.SkipAllAuthorities(); err != nil {
		return nil, err
	}
	for {
		h, err := p.AdditionalHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return nil, err
		}
		if h.Type == dnsmessage.TypeOPT {
			limit = max(512, min(int(h.Class), 1232))
		}
		if err := p.SkipAdditional(); err != nil {
			return nil, err
		}
	}
	if len(response) <= limit {
		return response, nil
	}
	hdr, err := p.Start(response)
	if err != nil {
		return nil, err
	}
	hdr.Truncated = true
	b := dnsmessage.NewBuilder(nil, hdr)
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	for _, q := range questions {
		if err := b.Question(q); err != nil {
			return nil, err
		}
	}
	return b.Finish()
}

func tunnelDNSResponding(iface, subnet string) bool {
	q := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x4a57})
	_ = q.StartQuestions()
	_ = q.Question(dnsmessage.Question{Name: dnsmessage.MustNewName("health.jwg."), Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassCHAOS})
	query, _ := q.Finish()
	conn, err := net.DialTimeout("udp", net.JoinHostPort(detectInterfaceIPv4(iface, subnet), "53"), 300*time.Millisecond)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := conn.Write(query); err != nil {
		return false
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return false
	}
	var p dnsmessage.Parser
	h, err := p.Start(buf[:n])
	return err == nil && h.Response && h.ID == 0x4a57 && h.RCode == dnsmessage.RCodeSuccess
}

func (s *FakeDNSServer) ServeUDP(pc net.PacketConn) error {
	buf := make([]byte, 4096)
	for {
		n, clientAddr, err := pc.ReadFrom(buf)
		if err != nil {
			return err
		}
		query := bytes.Clone(buf[:n])
		go func() {
			defer func() { _ = recover() }()
			if resp, err := s.HandlePacket(query, false); err == nil && len(resp) > 0 {
				_, _ = pc.WriteTo(resp, clientAddr)
			}
		}()
	}
}

func (s *FakeDNSServer) ServeTCP(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go func(c net.Conn) {
			defer func() { _ = recover() }()
			defer c.Close()
			for {
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				q, err := readTCPDNS(c)
				if err != nil {
					return
				}
				resp, err := s.HandlePacket(q, true)
				if err != nil || len(resp) == 0 || writeTCPDNS(c, resp) != nil {
					return
				}
			}
		}(conn)
	}
}

func detectInterfaceIPv4(ifaceName, fallbackSubnet string) string {
	if iface, err := net.InterfaceByName(ifaceName); err == nil {
		if addrs, err := iface.Addrs(); err == nil {
			for _, a := range addrs {
				if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.To4() != nil {
					return ipnet.IP.To4().String()
				}
			}
		}
	}
	if pfx, err := netip.ParsePrefix(fallbackSubnet); err == nil && pfx.Addr().Is4() {
		return pfx.Addr().String()
	}
	return "10.8.0.1"
}

func stateDirPath(dbFlagPath string) string {
	return filepath.Dir(resolveDBPath(dbFlagPath))
}

func ensureUFWTunnelDNS(wgIface string) {
	if path, err := exec.LookPath("ufw"); err == nil && path != "" {
		cmd := exec.Command("ufw", "status")
		cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
		if out, err := cmd.CombinedOutput(); err == nil && strings.Contains(string(out), "Status: active") {
			_ = exec.Command("ufw", "allow", "in", "on", wgIface, "to", "any", "port", "53").Run()
		}
	}
}

func runServeDaemon(iface, listenAddr, fakeCIDR, upstreamDNS, proxyList string) {
	if fakeCIDR == "" {
		fakeCIDR = defaultFakeCIDR
	}
	if upstreamDNS == "" {
		upstreamDNS = defaultUpstreamDNS
	}
	if listenAddr == "" {
		listenAddr = net.JoinHostPort(detectInterfaceIPv4(iface, argSubnet), "53")
	} else if !strings.Contains(listenAddr, ":") {
		listenAddr = net.JoinHostPort(listenAddr, "53")
	}

	stateDir := stateDirPath(argDBPath)
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		log.Fatalf("[ERR] Failed to create state directory %s: %v", stateDir, err)
	}
	if proxyList == "" {
		proxyList = filepath.Join(stateDir, "proxy.lst")
	} else if _, err := os.Stat(proxyList); err != nil {
		log.Fatalf("[ERR] Proxy domain list %q cannot be read: %v", proxyList, err)
	}

	matcher := NewDomainMatcher(proxyList)
	if matcher.Count() == 0 {
		log.Printf("[WARN] Proxy domain list %q has 0 rules (or file does not exist)", proxyList)
	}

	// Bind UDP and TCP sockets BEFORE modifying nftables so a duplicate daemon exits harmlessly.
	udpConn, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		log.Fatalf("[ERR] Failed to listen on UDP %s: %v", listenAddr, err)
	}
	defer udpConn.Close()

	tcpLn, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("[ERR] Failed to listen on TCP %s: %v", listenAddr, err)
	}
	defer tcpLn.Close()

	liveMap, _ := listNftFakeIPMap(iface)
	pool, err := NewFakeIPPool(iface, fakeCIDR, execNftScript, liveMap)
	if err != nil {
		log.Fatalf("[ERR] Failed to initialize FakeIP pool: %v", err)
	}
	ensureUFWTunnelDNS(iface)

	srv := &FakeDNSServer{
		ListenAddr:  listenAddr,
		UpstreamDNS: upstreamDNS,
		Matcher:     matcher,
		Pool:        pool,
		TTL:         defaultFakeDNSTTL,
		Timeout:     4 * time.Second,
	}

	fmt.Printf("%s[OK]%s FakeIP DNS daemon listening on %s (iface=%s, pool=%s, mapped=%d, rules=%d, upstream=%s)\n",
		colorGreen, colorReset, listenAddr, iface, fakeCIDR, pool.Count(), matcher.Count(), upstreamDNS)

	if err := CollectAndSavePeerStats(stateDir, iface); err != nil {
		log.Printf("[WARN] Stats snapshot failed: %v", err)
	}

	stopCh := make(chan struct{})
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := CollectAndSavePeerStats(stateDir, iface); err != nil {
					log.Printf("[WARN] Stats snapshot failed: %v", err)
				}
			case <-stopCh:
				return
			}
		}
	}()

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	errCh := make(chan error, 2)
	go func() { errCh <- srv.ServeUDP(udpConn) }()
	go func() { errCh <- srv.ServeTCP(tcpLn) }()
	if socket := os.Getenv("NOTIFY_SOCKET"); socket != "" {
		conn, err := net.Dial("unixgram", socket)
		if err != nil {
			log.Fatalf("[ERR] systemd readiness notification: %v", err)
		}
		_, err = conn.Write([]byte("READY=1"))
		_ = conn.Close()
		if err != nil {
			log.Fatalf("[ERR] systemd readiness notification: %v", err)
		}
	}
	select {
	case <-sigCh:
		close(stopCh)
		if err := CollectAndSavePeerStats(stateDir, iface); err != nil {
			log.Printf("[WARN] Final stats snapshot failed: %v", err)
		}
	case err := <-errCh:
		log.Fatalf("[ERR] DNS server exited: %v", err)
	}
}
