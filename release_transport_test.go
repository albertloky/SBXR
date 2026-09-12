package architecture_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestQualificationGatewayReadinessIsBoundedAndObservable(t *testing.T) {
	script, err := filepath.Abs(".github/scripts/qualification-gateway-readiness.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, child, curl, timeout, want string
		wantSuccess                      bool
	}{
		{name: "delayed healthy gateway", child: "sleep 10", curl: "sleep .2\nexit 0", timeout: "5", wantSuccess: true},
		{name: "exited gateway", child: "exit 23", curl: "while test \"$#\" -gt 0; do if test \"$1\" = --max-time; then shift; sleep \"$1\"; exit 1; fi; shift; done\nexit 1", timeout: "30", want: "qualification gateway exited before readiness\nlistener-fact"},
		{name: "live gateway timeout", child: "sleep 10", curl: "exit 1", timeout: "1", want: "qualification gateway readiness timed out\nlistener-fact"},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			bin := filepath.Join(directory, "bin")
			if err := os.Mkdir(bin, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(bin, "curl"), []byte("#!/bin/sh\n"+test.curl+"\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(bin, "ss"), []byte("#!/bin/sh\nprintf 'listener-fact\\n'\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			log := filepath.Join(directory, "gateway.log")
			pidFile := filepath.Join(directory, "gateway.pid")
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, "bash", script, "https://gateway.test/ready", log, pidFile, test.timeout, "sh", "-c", test.child)
			command.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"))
			output, runErr := command.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("readiness exceeded its test deadline: %v\n%s", ctx.Err(), output)
			}
			if pid, readErr := os.ReadFile(pidFile); readErr == nil {
				if value, parseErr := strconv.Atoi(strings.TrimSpace(string(pid))); parseErr == nil {
					_ = exec.Command("kill", strconv.Itoa(value)).Run()
				}
			}
			if (runErr == nil) != test.wantSuccess {
				t.Fatalf("readiness error = %v, output = %s", runErr, output)
			}
			if !strings.Contains(string(output), test.want) {
				t.Fatalf("readiness output = %q, want %q", output, test.want)
			}
		})
	}
}

func TestSubscriptionQualificationHasIsolatedRebootSafeTransport(t *testing.T) {
	workflow, err := os.ReadFile(".github/workflows/candidate.yml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(workflow), "v3-qualification-transport.sh") {
		t.Fatal("version-3 transport is missing")
	}
	script, err := os.ReadFile(".github/scripts/v3-qualification-transport.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"127.0.0.1:9443", "127.0.0.2", "--to-ports 9443", "ExecStartPre=", "ExecStopPost=", "WantedBy=multi-user.target", "systemctl enable", "systemctl disable", "cmp -s", "route-down", "update-ca-certificates", "transport-owned"} {
		if !strings.Contains(string(script), required) {
			t.Fatalf("missing transport lifecycle %q", required)
		}
	}
	collector, err := os.ReadFile(".github/scripts/v3-recurring-evidence.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(collector), "/root/sbxr-qualification-evidence") || strings.Contains(string(collector), "/run/sbxr-qualification/v3-evidence") {
		t.Fatal("scenario clock handoff cannot survive reboot")
	}
	if output, err := exec.Command("bash", "-n", ".github/scripts/v3-qualification-transport.sh").CombinedOutput(); err != nil {
		t.Fatalf("syntax: %v %s", err, output)
	}
}

func TestQualificationRoutingInspectionFailsClosed(t *testing.T) {
	script, err := filepath.Abs(".github/scripts/v3-qualification-transport.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range []int{0, 1, 4} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "iptables"), []byte(fmt.Sprintf("#!/bin/sh\nexit %d\n", status)), 0700); err != nil {
				t.Fatal(err)
			}
			command := exec.Command("bash", "-c", `source "$1"; if has_redirect; then echo present; else echo absent; fi`, "routing-check", script)
			command.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"))
			output, err := command.CombinedOutput()
			if status == 4 {
				if err == nil || len(output) != 0 {
					t.Fatalf("inspection error accepted: %v %s", err, output)
				}
				return
			}
			wanted := "present\n"
			if status == 1 {
				wanted = "absent\n"
			}
			if err != nil || string(output) != wanted {
				t.Fatalf("routing result: %v %s", err, output)
			}
		})
	}
}

func TestQualificationHostsRestorationPreservesOriginalAndUnrelatedEdits(t *testing.T) {
	script, err := filepath.Abs(".github/scripts/v3-qualification-transport.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, changed := range []bool{false, true} {
		t.Run(strconv.FormatBool(changed), func(t *testing.T) {
			dir := t.TempDir()
			before := "127.0.0.1 localhost"
			after := before + "\n127.0.0.2 api.github.com github.com # sbxr-qualification-v3\n"
			current, wanted := after, before
			if changed {
				current += "192.0.2.1 unrelated\n"
				wanted = before + "\n192.0.2.1 unrelated\n"
			}
			for name, body := range map[string]string{"hosts.before": before, "hosts.after": after, "hosts": current, "iptables": "#!/bin/sh\nexit 1\n", "update-ca-certificates": "#!/bin/sh\ntouch \"$SBXR_TEST_ROOT/refreshed\"\n"} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0700); err != nil {
					t.Fatal(err)
				}
			}
			command := exec.Command("bash", "-c", `source "$1"; root="$2"; hosts="$root/hosts"; ca="$root/absent-ca"; route_down`, "hosts-check", script, dir)
			command.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "SBXR_TEST_ROOT="+dir)
			// The production runner uses GNU sed; macOS requires its empty suffix.
			if changed {
				if output, err := exec.Command("uname", "-s").Output(); err == nil && strings.TrimSpace(string(output)) == "Darwin" {
					wrapper := "#!/bin/sh\nif test \"$1\" = -i; then shift; exec /usr/bin/sed -i '' \"$@\"; fi\nexec /usr/bin/sed \"$@\"\n"
					if err := os.WriteFile(filepath.Join(dir, "sed"), []byte(wrapper), 0700); err != nil {
						t.Fatal(err)
					}
				}
			}
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("restore: %v %s", err, output)
			}
			if _, err := os.Stat(filepath.Join(dir, "refreshed")); err != nil {
				t.Fatal("absent CA source skipped trust-store refresh", err)
			}
			got, err := os.ReadFile(filepath.Join(dir, "hosts"))
			if err != nil || string(got) != wanted {
				t.Fatalf("hosts restore = %q, %v", got, err)
			}
		})
	}
}

func TestQualificationTransportRefusesExistingUnit(t *testing.T) {
	script, err := filepath.Abs(".github/scripts/v3-qualification-transport.sh")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	unit := filepath.Join(dir, "existing-unit")
	if err := os.WriteFile(unit, []byte("unrelated unit"), 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("bash", "-c", `source "$1"; root="$2"; unit_path="$root/existing-unit"; ca="$root/absent-ca"; check_start; echo incorrectly-admitted`, "admission-check", script, dir)
	if output, err := command.CombinedOutput(); err == nil || len(output) != 0 {
		t.Fatalf("existing unit admitted: %v %s", err, output)
	}
	got, err := os.ReadFile(unit)
	if err != nil || string(got) != "unrelated unit" {
		t.Fatal("existing unit changed")
	}
}
