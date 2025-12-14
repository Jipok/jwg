package wguser

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// configureDevice configures a device specified by its path.
func (c *Client) configureDevice(device string, cfg wgtypes.Config) error {
	conn, err := c.dial(device)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Start with set command.
	var buf bytes.Buffer
	buf.WriteString("set=1\n")

	// Add any necessary configuration from cfg, then finish with an empty line.
	writeConfig(&buf, cfg)
	buf.WriteString("\n")

	// Apply configuration for the device and then check the error number.
	if _, err := io.Copy(conn, &buf); err != nil {
		return err
	}

	res := make([]byte, 32)
	n, err := conn.Read(res)
	if err != nil {
		return err
	}

	// errno=0 indicates success, anything else returns an error number that
	// matches definitions from errno.h.
	str := strings.TrimSpace(string(res[:n]))
	if str != "errno=0" {
		// TODO(mdlayher): return actual errno on Linux?
		return os.NewSyscallError("read", fmt.Errorf("wguser: %s", str))
	}

	return nil
}

// writeConfig writes textual configuration to w as specified by cfg.
func writeConfig(w io.Writer, cfg wgtypes.Config) {
	if cfg.PrivateKey != nil {
		fmt.Fprintf(w, "private_key=%s\n", hexKey(*cfg.PrivateKey))
	}

	if cfg.ListenPort != nil {
		fmt.Fprintf(w, "listen_port=%d\n", *cfg.ListenPort)
	}

	if cfg.FirewallMark != nil {
		fmt.Fprintf(w, "fwmark=%d\n", *cfg.FirewallMark)
	}

	// --- AmneziaWG Parameters Start ---

	// Junk Packets
	if cfg.JunkPacketCount != nil {
		fmt.Fprintf(w, "jc=%d\n", *cfg.JunkPacketCount)
	}
	if cfg.JunkPacketMinSize != nil {
		fmt.Fprintf(w, "jmin=%d\n", *cfg.JunkPacketMinSize)
	}
	if cfg.JunkPacketMaxSize != nil {
		fmt.Fprintf(w, "jmax=%d\n", *cfg.JunkPacketMaxSize)
	}

	// Padding
	if cfg.InitPadding != nil {
		fmt.Fprintf(w, "s1=%d\n", *cfg.InitPadding)
	}
	if cfg.ResponsePadding != nil {
		fmt.Fprintf(w, "s2=%d\n", *cfg.ResponsePadding)
	}
	if cfg.CookiePadding != nil {
		fmt.Fprintf(w, "s3=%d\n", *cfg.CookiePadding)
	}
	if cfg.TransportPadding != nil {
		fmt.Fprintf(w, "s4=%d\n", *cfg.TransportPadding)
	}

	// Headers (passed as strings because they can be ranges "123-456")
	if cfg.InitHeader != nil {
		fmt.Fprintf(w, "h1=%s\n", *cfg.InitHeader) // h1 -> Init
	}
	if cfg.ResponseHeader != nil {
		fmt.Fprintf(w, "h2=%s\n", *cfg.ResponseHeader) // h2 -> Response
	}
	if cfg.CookieHeader != nil {
		fmt.Fprintf(w, "h3=%s\n", *cfg.CookieHeader) // h3 -> Cookie
	}
	if cfg.TransportHeader != nil {
		fmt.Fprintf(w, "h4=%s\n", *cfg.TransportHeader) // h4 -> Transport
	}

	// Init Custom Packets ("Custom signature packets")
	if cfg.InitPacket1 != nil {
		fmt.Fprintf(w, "i1=%s\n", *cfg.InitPacket1)
	}
	if cfg.InitPacket2 != nil {
		fmt.Fprintf(w, "i2=%s\n", *cfg.InitPacket2)
	}
	if cfg.InitPacket3 != nil {
		fmt.Fprintf(w, "i3=%s\n", *cfg.InitPacket3)
	}
	if cfg.InitPacket4 != nil {
		fmt.Fprintf(w, "i4=%s\n", *cfg.InitPacket4)
	}
	if cfg.InitPacket5 != nil {
		fmt.Fprintf(w, "i5=%s\n", *cfg.InitPacket5)
	}

	// --- AmneziaWG Parameters End ---

	if cfg.ReplacePeers {
		fmt.Fprintln(w, "replace_peers=true")
	}

	for _, p := range cfg.Peers {
		fmt.Fprintf(w, "public_key=%s\n", hexKey(p.PublicKey))

		if p.Remove {
			fmt.Fprintln(w, "remove=true")
		}

		if p.UpdateOnly {
			fmt.Fprintln(w, "update_only=true")
		}

		if p.PresharedKey != nil {
			fmt.Fprintf(w, "preshared_key=%s\n", hexKey(*p.PresharedKey))
		}

		if p.Endpoint != nil {
			fmt.Fprintf(w, "endpoint=%s\n", p.Endpoint.String())
		}

		if p.PersistentKeepaliveInterval != nil {
			fmt.Fprintf(w, "persistent_keepalive_interval=%d\n", int(p.PersistentKeepaliveInterval.Seconds()))
		}

		if p.ReplaceAllowedIPs {
			fmt.Fprintln(w, "replace_allowed_ips=true")
		}

		for _, ip := range p.AllowedIPs {
			fmt.Fprintf(w, "allowed_ip=%s\n", ip.String())
		}
	}
}

// hexKey encodes a wgtypes.Key into a hexadecimal string.
func hexKey(k wgtypes.Key) string {
	return hex.EncodeToString(k[:])
}
