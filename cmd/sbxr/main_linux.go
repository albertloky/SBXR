//go:build linux

// Command sbxr is the root-only V3 numbered menu.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/albertloky/SBXR/internal/proxyinstallation"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	githubadapter "github.com/albertloky/SBXR/internal/softwarelifecycle/adapter/github"
)

func main() {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "SBXR requires root authority.\nRun: sudo sbxr")
		os.Exit(1)
	}
	lifecycle := softwarelifecycle.NewInstalledWithUpdateAdmission(githubadapter.New(), proxyinstallation.AdmitSoftwareUpdate)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	go func() {
		<-ctx.Done()
		_ = os.Stdin.Close()
	}()
	os.Exit(run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr, lifecycle))
}
