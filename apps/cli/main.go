// kekkai — the CLI (ADR 0015): `keygen` and `pubkey` run locally, `status --json` is a thin
// gRPC client of the node's control socket.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/scorsi/kekkai/cli/internal/genproto/kekkai/control/v1"
	"github.com/scorsi/kekkai/cli/internal/keys"
	"github.com/scorsi/kekkai/cli/internal/version"
)

// Keeps the generated client in the build so `go vet` covers it.
var _ controlv1.ControlServiceClient

const usage = `usage:
  kekkai keygen [FILE]   write a new private key to stdout, or to FILE in mode 0400
  kekkai pubkey          read a private key on stdin, print its public key
  kekkai --version`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "kekkai:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("missing command\n%s", usage)
	}
	switch {
	case args[0] == "--version":
		fmt.Println(version.Version)
		return nil
	case args[0] == "keygen" && len(args) <= 2:
		return keygen(args[1:])
	case args[0] == "pubkey" && len(args) == 1:
		return pubkey()
	}
	return fmt.Errorf("unknown command %q\n%s", args[0], usage)
}

func keygen(args []string) error {
	k, err := keys.Generate()
	if err != nil {
		return err
	}
	line := keys.Encode(k) + "\n"
	if len(args) == 0 {
		_, err = io.WriteString(os.Stdout, line)
		return err
	}
	// O_EXCL: never overwrite an existing key.
	f, err := os.OpenFile(args[0], os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(f, line); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func pubkey() error {
	text, err := io.ReadAll(io.LimitReader(os.Stdin, 4096))
	if err != nil {
		return err
	}
	k, err := keys.Decode(string(text))
	if err != nil {
		return err
	}
	p, err := keys.Public(k)
	if err != nil {
		return err
	}
	fmt.Println(keys.Encode(p))
	return nil
}
