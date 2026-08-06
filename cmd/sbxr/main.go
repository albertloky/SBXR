// Command sbxr is the startup and Module-wiring entry point.
package main

import (
	"github.com/albertloky/SBXR/internal/networkpolicy"
	"github.com/albertloky/SBXR/internal/networkpolicy/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/state/adapter/filesystem"
)

func main() {
	_ = filesystem.New()
	_ = networkpolicy.New(ubuntu.New())
}
