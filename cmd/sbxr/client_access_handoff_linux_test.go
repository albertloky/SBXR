//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRootOwnerConsoleStartsManagedWorkWithoutASecondSudo(t *testing.T) {
	name := filepath.Join(t.TempDir(), "sbxr")
	if err := os.WriteFile(name, []byte("#!/bin/sh\n[ \"$*\" = \"private client-access\" ]\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer executable.Close()
	socket, wait, err := startClientAccessProcess(t.Context(), executable)
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	if err := wait(); err != nil {
		t.Fatalf("root managed process = %v", err)
	}
}
