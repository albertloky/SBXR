// Command sbxr is the startup and Module-wiring entry point.
package main

import (
	"github.com/albertloky/SBXR/internal/state/adapter/filesystem"
)

func main() {
	_ = filesystem.New()
}
