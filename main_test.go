package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplyNftablesRulesBlocklist(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "nft.log")
	// Record every invocation without changing the host's firewall.
	if err := os.WriteFile(filepath.Join(dir, "nft"), []byte("#!/bin/sh\nprintf 'invoked\\n' >> \"$JWG_TEST_NFT_LOG\"\ncat >> \"$JWG_TEST_NFT_LOG\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("JWG_TEST_NFT_LOG", logPath)

	blockFile := filepath.Join(dir, "blocked.lst")
	if err := os.WriteFile(blockFile, []byte("# test\n185.71.67.0/24\n8.8.8.8\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := applyNftablesRules("10.8.0.1/24", "awg0", "eth0", blockFile); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"185.71.67.0/24, 8.8.8.8/32",
		`iifname "awg0" ip daddr @blocked_ips counter drop`,
	} {
		if !strings.Contains(string(before), want) {
			t.Fatalf("missing blocklist rule %q", want)
		}
	}

	for _, tc := range []struct {
		name    string
		content string
	}{
		{name: "missing"},
		{name: "directory"},
		{name: "empty"},
		{name: "comments", content: "# no entries\n\n"},
		{name: "invalid", content: "not-a-subnet\n"},
		{name: "ipv6-only", content: "2001:db8::/32\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name)
			switch tc.name {
			case "missing":
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			default:
				if err := os.WriteFile(path, []byte(tc.content), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := applyNftablesRules("10.8.0.1/24", "awg0", "eth0", path); err == nil {
				t.Fatal("expected an error for an unusable blocklist")
			}
			after, err := os.ReadFile(logPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("nft invoked despite an unusable blocklist")
			}
		})
	}

	t.Run("explicit-disable", func(t *testing.T) {
		if err := applyNftablesRules("10.8.0.1/24", "awg0", "eth0", ""); err != nil {
			t.Fatal(err)
		}
		after, err := os.ReadFile(logPath)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.HasPrefix(after, before) || len(after) <= len(before) {
			t.Fatal("explicit disable did not invoke nft")
		}
		if bytes.Contains(after[len(before):], []byte("blocked_ips")) {
			t.Fatal("explicit disable still installs a blocklist")
		}
	})
}
