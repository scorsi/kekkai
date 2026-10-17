// kekkai — the CLI, a thin gRPC client of the node's control API (0015). Empty shell until v0.2.
package main

import (
	"fmt"
	"os"

	"github.com/scorsi/kekkai/cli/internal/genproto/kekkai/control/v1"
	"github.com/scorsi/kekkai/cli/internal/version"
)

// Keeps the generated client in the build so `go vet` covers it.
var _ controlv1.ControlServiceClient

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Println(version.Version)
	}
}
