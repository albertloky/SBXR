//go:build linux

// Command sbxr is the root-only V3 numbered menu.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	githubadapter "github.com/albertloky/SBXR/internal/softwarelifecycle/adapter/github"
)

func main() {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "SBXR requires root authority.\nRun: sudo sbxr")
		os.Exit(1)
	}
	lifecycle := softwarelifecycle.NewInstalled(githubadapter.New())
	os.Exit(run(context.Background(), os.Args[1:], os.Stdin, os.Stdout, os.Stderr, lifecycle))
}
