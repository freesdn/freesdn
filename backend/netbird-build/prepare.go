//go:build ignore

// Apply the reviewed FreeSDN transport changes only to a private vendor tree.
package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
)

func main() {
	if err := prepare(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func prepare() error {
	const target = "vendor/github.com/netbirdio/netbird/client/internal/relay/"
	modules, err := os.ReadFile("vendor/modules.txt")
	if err != nil {
		return err
	}
	if !bytes.Contains(modules, []byte("# github.com/netbirdio/netbird v0.79.0\n")) || bytes.Contains(modules, []byte("github.com/netbirdio/netbird =>")) {
		return fmt.Errorf("review the transport changes before updating the released NetBird source")
	}
	data, err := os.ReadFile(target + "relay.go")
	if err != nil {
		return err
	}
	if fmt.Sprintf("%x", sha256.Sum256(data)) != "cefe41cf1d00b15103d93cabe3e2139ef89eb9c09af83b0259aacb191f0fc4fe" {
		return fmt.Errorf("NetBird relay source differs from the reviewed release; refusing to patch")
	}
	start := bytes.Index(data, []byte("func (p *StunTurnProbe) probeSTUN"))
	end := bytes.Index(data, []byte("// ProbeTURN"))
	if start < 0 || end <= start || bytes.Count(data, []byte("github.com/pion/turn/v3")) != 1 {
		return fmt.Errorf("unexpected NetBird relay source layout")
	}
	probe, err := os.ReadFile("patches/probe_stun.go.txt")
	if err != nil {
		return err
	}
	updated := append(append(bytes.Clone(data[:start]), append(probe, '\n')...), data[end:]...)
	updated = bytes.ReplaceAll(updated, []byte("github.com/pion/turn/v3"), []byte("github.com/pion/turn/v4"))
	if err := os.WriteFile(target+"relay.go", updated, 0644); err != nil {
		return err
	}
	for _, file := range []string{"probe_net.go", "freesdn_transport_test.go"} {
		data, err := os.ReadFile("patches/" + file + ".txt")
		if err != nil {
			return err
		}
		if err := os.WriteFile(target+file, data, 0644); err != nil {
			return err
		}
	}
	return nil
}
