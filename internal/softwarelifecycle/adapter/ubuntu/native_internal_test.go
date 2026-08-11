package ubuntu

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRunNativeCapturesBoundedStderr(t *testing.T) {
	command := filepath.Join(t.TempDir(), "certbot")
	if err := os.WriteFile(command, []byte("#!/bin/sh\nprintf 'certbot 5.4.0\\n' >&2\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	output, err := runNative(t.Context(), command, []string{"--version"}, 64)
	if err != nil || string(output) != "certbot 5.4.0\n" {
		t.Fatalf("stderr output = %q, %v", output, err)
	}
}
