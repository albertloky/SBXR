//go:build linux

// Command sbxr is the root-only Installer-Updater numbered menu.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	githubadapter "github.com/albertloky/SBXR/internal/softwarelifecycle/adapter/github"
	"github.com/albertloky/SBXR/internal/softwarelifecycle/adapter/terminal"
)

func main() {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "SBXR requires root authority.\nRun: sudo sbxr")
		os.Exit(1)
	}
	lifecycle := softwarelifecycle.NewInstalled(githubadapter.New())
	_, status := terminal.Run(context.Background(), os.Args[1:], os.Stdin, os.Stdout, os.Stderr, os.Environ(), lifecycle)
	os.Exit(status)
}
