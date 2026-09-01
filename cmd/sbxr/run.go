package main

import (
	"context"
	"io"
	"os"

	"github.com/albertloky/SBXR/internal/proxyinstallation"
	hostadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/host"
	"github.com/albertloky/SBXR/internal/proxyinstallation/adapter/terminal"
	"github.com/albertloky/SBXR/internal/proxyinstallation/subscriptionserving"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

func run(ctx context.Context, arguments []string, input io.Reader, output, errorOutput io.Writer, lifecycle softwarelifecycle.Interface) int {
	if len(arguments) == 1 && arguments[0] == hostadapter.RenewalRecorderRole {
		return proxyinstallation.RecordRenewal(ctx, lifecycle)
	}
	if len(arguments) == 1 && (arguments[0] == hostadapter.RenewalDeployRole || arguments[0] == hostadapter.RenewalPostRole) {
		environment := map[string]string{}
		for _, name := range []string{"SBXR_RENEWAL_ATTEMPT_ID", "RENEWED_LINEAGE", "RENEWED_DOMAINS", "FAILED_DOMAINS"} {
			environment[name] = os.Getenv(name)
		}
		if proxyinstallation.RecordRenewalHook(ctx, lifecycle, arguments[0], environment) {
			return 0
		}
		return 1
	}
	if len(arguments) == 1 && arguments[0] == hostadapter.ServingRole {
		if proxyinstallation.ServeSubscription(ctx, lifecycle) == subscriptionserving.Stopped {
			return 0
		}
		return 1
	}
	if len(arguments) == 1 && arguments[0] == hostadapter.ProxyStartRole {
		if proxyinstallation.AuthorizeProxyStart(ctx, lifecycle) {
			return 0
		}
		return 1
	}
	return terminal.Run(ctx, arguments, input, output, errorOutput, proxyinstallation.NewInstalled(lifecycle))
}
