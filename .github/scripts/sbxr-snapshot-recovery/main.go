//go:build linux && amd64 && sbxr_snapshot_recovery

// This one-time helper is built separately and is never installed as sbxr.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/albertloky/SBXR/internal/proxyinstallation"
)

func main() {
	if len(os.Args) != 3 || os.Args[1] != "check" && os.Args[1] != "apply" {
		fmt.Fprintln(os.Stderr, "usage: sbxr-snapshot-recovery check|apply /absolute/protected/plan.json")
		os.Exit(2)
	}
	if len(os.Args[2]) == 0 || os.Args[2][0] != '/' {
		os.Exit(2)
	}
	os.Clearenv()
	os.Setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	result, err := proxyinstallation.RecoverCertificateSnapshot(ctx, os.Args[2], os.Args[1] == "apply")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(result)
}
