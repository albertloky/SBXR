package main

import (
	"context"
	"io"

	"github.com/albertloky/SBXR/internal/proxyinstallation"
	hostadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/host"
	"github.com/albertloky/SBXR/internal/proxyinstallation/adapter/terminal"
	"github.com/albertloky/SBXR/internal/proxyinstallation/subscriptionserving"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

func run(ctx context.Context, arguments []string, input io.Reader, output, errorOutput io.Writer, lifecycle softwarelifecycle.Interface) int {
	if len(arguments) == 1 && arguments[0] == hostadapter.ServingRole {
		if proxyinstallation.ServeSubscription(ctx, lifecycle) == subscriptionserving.Stopped {
			return 0
		}
		return 1
	}
	return terminal.Run(ctx, arguments, input, output, errorOutput, proxyinstallation.NewInstalled(lifecycle))
}
