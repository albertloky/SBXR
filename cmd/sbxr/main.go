// Command sbxr is the startup and Module-wiring entry point.
package main

import (
	"context"
	"os"

	"github.com/albertloky/SBXR/internal/healthdiagnostics"
	healthfilesystem "github.com/albertloky/SBXR/internal/healthdiagnostics/adapter/filesystem"
	"github.com/albertloky/SBXR/internal/networkpolicy"
	"github.com/albertloky/SBXR/internal/networkpolicy/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/ownerconsole"
	"github.com/albertloky/SBXR/internal/state/adapter/filesystem"
	"github.com/albertloky/SBXR/internal/subscriptionserving"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "version" {
		if writeVersion(os.Stdout, false) != nil {
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 3 && os.Args[1] == "version" && os.Args[2] == "--json" {
		if writeVersion(os.Stdout, true) != nil {
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 3 && os.Args[1] == "private" && os.Args[2] == "health-check" {
		history := healthdiagnostics.NewEventHistory(healthfilesystem.NewEventStorage(), nil)
		if runScheduledHealthCheck(context.Background(), history) != nil {
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "__subscription-serve" {
		if subscriptionserving.Run(context.Background()) != nil {
			os.Exit(1)
		}
		return
	}
	_ = filesystem.New()
	_ = networkpolicy.New(ubuntu.New())
	if runOwnerConsole(context.Background(), os.Stdin, os.Stdout, os.Environ()) != nil {
		os.Exit(1)
	}
}

func runOwnerConsole(ctx context.Context, input, output *os.File, environment []string) error {
	capabilities := ownerconsole.DetectTerminal(input, output, environment)
	return ownerconsole.Run(ctx, ownerconsole.Session{Input: input, Output: output, Environment: environment, Capabilities: &capabilities, Authenticator: systemAuthenticator{}})
}
