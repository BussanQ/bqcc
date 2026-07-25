package main

import (
	"fmt"
	"os"

	"github.com/example/decentid/internal/cli"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

// decentid is the unified single-binary entrypoint. "web" starts the localhost
// operation console; every other subcommand is the original node CLI.
func main() {
	if len(os.Args) < 2 {
		cli.Usage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "web":
		cli.RunWeb(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Printf("decentid %s\n", version)
	case "-h", "--help", "help":
		cli.Usage()
	default:
		cli.RunNode(os.Args[1:])
	}
}
