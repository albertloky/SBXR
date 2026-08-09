// Package contract contains the dependency-safe contribution handed to the
// Software Lifecycle fresh-install coordinator by each owning Module.
package contract

import "github.com/albertloky/SBXR/internal/systemchanges"

type InstallContribution struct {
	Name, Identity, SHA256, StableSHA256 string
	Owner                                systemchanges.Module
	ChangeSet, DesiredStateSHA256        string
	Steps                                []systemchanges.Step
	Checks                               []systemchanges.Check
	Ports, Details                       []string
	Firewall                             string
	Privileged                           bool
}

type UpdateContribution = InstallContribution
