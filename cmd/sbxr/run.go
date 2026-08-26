package main

import (
	"context"
	"io"

	"github.com/albertloky/SBXR/internal/proxyinstallation"
	"github.com/albertloky/SBXR/internal/proxyinstallation/adapter/terminal"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

func run(ctx context.Context, arguments []string, input io.Reader, output, errorOutput io.Writer, lifecycle softwarelifecycle.Interface) int {
	return terminal.Run(ctx, arguments, input, output, errorOutput, proxyinstallation.NewInstalled(lifecycle))
}
