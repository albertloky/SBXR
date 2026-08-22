//go:build !linux

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "SBXR supports only Ubuntu Server 24.04 on amd64 or arm64.")
	os.Exit(1)
}
