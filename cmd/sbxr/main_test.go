package main

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"
)

func TestDefaultRunRefusesRedirectedTerminal(t *testing.T) {
	input, writeInput, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	defer writeInput.Close()
	readOutput, output, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer readOutput.Close()
	if err := runOwnerConsole(context.Background(), input, output, []string{"TERM=xterm-256color", "LANG=C.UTF-8"}); err == nil {
		t.Fatal("redirected default Run was admitted")
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
	refusal, err := io.ReadAll(readOutput)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(refusal); !strings.Contains(got, "interactive input") || strings.Contains(got, "CLIENT-ACCESS-MARKER") {
		t.Fatalf("refusal = %q", got)
	}
}
