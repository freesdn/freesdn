//go:build ignore

// Apply FreeSDN's Caddy 2.11.4 / CEL 0.30 compatibility change to a private
// vendor tree, after go mod download, go mod verify and go mod vendor.
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
	const source = "vendor/github.com/caddyserver/caddy/v2/modules/caddyhttp/celmatcher.go"
	modules, err := os.ReadFile("vendor/modules.txt")
	if err != nil {
		return err
	}
	if !bytes.Contains(modules, []byte("# github.com/caddyserver/caddy/v2 v2.11.4\n")) || bytes.Contains(modules, []byte("github.com/caddyserver/caddy/v2 =>")) {
		return fmt.Errorf("review the CEL patch before changing the released Caddy source")
	}
	data, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	if fmt.Sprintf("%x", sha256.Sum256(data)) != "e0fb48fde80ea23f7810e0e7f3fb2998032a6bea052deedaaeb02881d6c8cc6b" {
		return fmt.Errorf("Caddy CEL source differs from the reviewed release; refusing to patch")
	}
	old := []byte("[]interpreter.Interpretable{reqAttr}")
	if bytes.Count(data, old) != 2 {
		return fmt.Errorf("expected exactly two CEL call argument conversions")
	}
	// InterpretableAttribute embeds InterpretableV2 in CEL 0.30. Only the
	// argument slice type changes; evaluation and error handling stay intact.
	data = bytes.ReplaceAll(data, old, []byte("[]interpreter.InterpretableV2{reqAttr}"))
	return os.WriteFile(source, data, 0644)
}
