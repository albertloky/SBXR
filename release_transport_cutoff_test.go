package architecture_test

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

const cutoffFixtureNow int64 = 2_000_000_000

type transportCutoffFixture struct {
	t                *testing.T
	directory, stage string
	script, bin      string
}

func newTransportCutoffFixture(t *testing.T) *transportCutoffFixture {
	t.Helper()
	directory := t.TempDir()
	fixture := &transportCutoffFixture{t: t, directory: directory, stage: filepath.Join(directory, "stage"), script: filepath.Join(directory, "transport.sh"), bin: filepath.Join(directory, "bin")}
	for _, path := range []string{fixture.stage, fixture.bin} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	body, err := os.ReadFile(".github/scripts/v3-qualification-transport.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(body)
	for old, replacement := range map[string]string{
		"root=/root/sbxr-qualification-v3":                              "root=" + shellCutoffQuote(fixture.stage),
		"unit_path=/etc/systemd/system/$unit":                           "unit_path=" + shellCutoffQuote(filepath.Join(directory, "service")),
		"unit_link=/etc/systemd/system/multi-user.target.wants/$unit":   "unit_link=" + shellCutoffQuote(filepath.Join(directory, "service-link")),
		"ca=/usr/local/share/ca-certificates/sbxr-qualification-v3.crt": "ca=" + shellCutoffQuote(filepath.Join(directory, "ca")),
		"hosts=/etc/hosts": "hosts=" + shellCutoffQuote(filepath.Join(directory, "hosts")),
	} {
		if strings.HasPrefix(old, "unit_link=") && !strings.Contains(script, old) {
			continue // The pre-cutoff script has no explicit enablement-link path.
		}
		if strings.Count(script, old) != 1 {
			t.Fatalf("transport fixture cannot isolate %q", old)
		}
		script = strings.Replace(script, old, replacement, 1)
	}
	if runtime.GOOS != "linux" {
		// Darwin's /dev/fd stat differs from procfs; retain a real open-inode check.
		script = strings.ReplaceAll(script, `test "$root/transport-owned" -ef /proc/self/fd/9`, `python3 -c 'import os,sys; assert os.path.samestat(os.stat(sys.argv[1]),os.fstat(9))' "$root/transport-owned"`)
	}
	fixture.write("transport.sh", script)
	fixture.write("stage/v3-qualification-transport.sh", script)
	fixture.write("hosts", "127.0.0.1 localhost\n")
	fixture.write("stage/ca.crt", "fixture CA\n")
	for _, name := range []string{"date", "id", "iptables", "update-ca-certificates", "systemctl", "flock", "timeout", "curl", "ss"} {
		if err := os.WriteFile(filepath.Join(fixture.bin, name), []byte(transportCutoffCommandFixture), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if runtime.GOOS == "darwin" {
		sed := "#!/bin/sh\nif test \"$1\" = -i; then shift; exec /usr/bin/sed -i '' \"$@\"; fi\nexec /usr/bin/sed \"$@\"\n"
		if err := os.WriteFile(filepath.Join(fixture.bin, "sed"), []byte(sed), 0700); err != nil {
			t.Fatal(err)
		}
	}
	return fixture
}

func shellCutoffQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func (fixture *transportCutoffFixture) write(path, body string) {
	fixture.t.Helper()
	if err := os.WriteFile(filepath.Join(fixture.directory, path), []byte(body), 0600); err != nil {
		fixture.t.Fatal(err)
	}
}

func (fixture *transportCutoffFixture) read(path string) string {
	fixture.t.Helper()
	body, err := os.ReadFile(filepath.Join(fixture.directory, path))
	if err != nil {
		fixture.t.Fatal(err)
	}
	return string(body)
}

func (fixture *transportCutoffFixture) run(now int64, source bool, args ...string) ([]byte, error) {
	fixture.t.Helper()
	commandArgs := []string{fixture.script}
	if source {
		commandArgs = []string{"-c", `source "$1"; shift; cutoff_deadline "$@"`, "cutoff", fixture.script}
	}
	commandArgs = append(commandArgs, args...)
	ctx, cancel := context.WithTimeout(fixture.t.Context(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "bash", commandArgs...)
	command.Env = append(os.Environ(), "PATH="+fixture.bin+string(os.PathListSeparator)+os.Getenv("PATH"), "SBXR_CUTOFF_FIXTURE="+fixture.directory, "SBXR_CUTOFF_NOW="+strconv.FormatInt(now, 10))
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		fixture.t.Fatalf("cutoff fixture exceeded deadline: %v %s", ctx.Err(), output)
	}
	return output, err
}

func (fixture *transportCutoffFixture) attendance(finish any) {
	fixture.t.Helper()
	body, err := json.Marshal(map[string]any{"v3_attempt": map[string]any{"attended_finish_by": finish}})
	if err != nil {
		fixture.t.Fatal(err)
	}
	fixture.write("stage/qualification-manifest.json", string(body))
}

func TestQualificationTransportCutoffBoundaries(t *testing.T) {
	iso := func(offset int64) string { return time.Unix(cutoffFixtureNow+offset, 0).UTC().Format(time.RFC3339) }
	for _, test := range []struct {
		name, manifest, explicit string
		finish                   any
		want                     int64
	}{
		{name: "signed finish plus cleanup", finish: iso(3600), want: cutoffFixtureNow + 5400},
		{name: "six hour ceiling", finish: iso(25000), want: cutoffFixtureNow + 21600},
		{name: "earlier explicit cutoff", finish: iso(3600), explicit: strconv.FormatInt(cutoffFixtureNow+1200, 10), want: cutoffFixtureNow + 1200},
		{name: "explicit extends signed bound", finish: iso(3600), explicit: strconv.FormatInt(cutoffFixtureNow+5401, 10)},
		{name: "explicit extends ceiling", finish: iso(25000), explicit: strconv.FormatInt(cutoffFixtureNow+21601, 10)},
		{name: "malformed explicit", finish: iso(3600), explicit: "tomorrow"},
		{name: "past explicit", finish: iso(3600), explicit: strconv.FormatInt(cutoffFixtureNow-1, 10)},
		{name: "cleanup reserve only", finish: iso(3600), explicit: strconv.FormatInt(cutoffFixtureNow+60, 10)},
		{name: "expired signed bound", finish: iso(-1801)},
		{name: "signed cleanup reserve only", finish: iso(-1740)},
		{name: "invalid finish", finish: "not-a-time"},
		{name: "legacy text is not absent attendance", finish: "legacy"},
		{name: "empty finish", finish: ""},
		{name: "null finish", manifest: `{"v3_attempt":{"attended_finish_by":null}}`},
		{name: "missing manifest"},
		{name: "malformed manifest", manifest: "{"},
		{name: "legacy no attendance", manifest: "{}", want: cutoffFixtureNow + 21600},
		{name: "legacy attempt no attendance", manifest: `{"v3_attempt":{}}`, want: cutoffFixtureNow + 21600},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTransportCutoffFixture(t)
			if test.finish != nil {
				fixture.attendance(test.finish)
			} else if test.manifest != "" {
				fixture.write("stage/qualification-manifest.json", test.manifest)
			}
			var args []string
			if test.explicit != "" {
				args = append(args, test.explicit)
			}
			output, err := fixture.run(cutoffFixtureNow, true, args...)
			if test.want == 0 {
				if err == nil {
					t.Fatalf("unsafe deadline accepted: %s", output)
				}
				if _, err := os.Stat(filepath.Join(fixture.stage, "transport-owned")); !os.IsNotExist(err) {
					t.Fatal("deadline refusal created transport authority")
				}
				if output, err := fixture.run(cutoffFixtureNow, false, append([]string{"up"}, args...)...); err == nil {
					t.Fatalf("up accepted unsafe deadline: %s", output)
				}
				if _, err := os.Stat(filepath.Join(fixture.stage, "transport-owned")); !os.IsNotExist(err) || fixture.read("hosts") != "127.0.0.1 localhost\n" {
					t.Fatal("up changed authority or routing before deadline admission")
				}
				return
			}
			if err != nil || string(output) != strconv.FormatInt(test.want, 10)+"\n" {
				t.Fatalf("cutoff = %s, %v; want %d", output, err, test.want)
			}
		})
	}
}

func TestQualificationTransportCutoffPersistsAndRestartCannotExtendIt(t *testing.T) {
	fixture := newTransportCutoffFixture(t)
	fixture.attendance(time.Unix(cutoffFixtureNow+3600, 0).UTC().Format(time.RFC3339))
	final := cutoffFixtureNow + 1200
	if output, err := fixture.run(cutoffFixtureNow, false, "up", strconv.FormatInt(final, 10)); err != nil {
		t.Fatalf("up: %v %s", err, output)
	}
	for path, want := range map[string]int64{"stage/deadline": final, "stage/runtime-deadline": final - 60} {
		if fixture.read(path) != strconv.FormatInt(want, 10)+"\n" {
			t.Fatalf("incorrect persisted %s", path)
		}
	}
	unit := fixture.read("stage/unit")
	for _, required := range []string{"KillMode=control-group", "TimeoutStopSec=30", "ExecStopPost=/usr/bin/timeout --signal=TERM --kill-after=5 25 /usr/bin/bash "} {
		if !strings.Contains(unit, required) {
			t.Fatalf("generated service omits bounded lifecycle %q", required)
		}
	}
	if output, err := fixture.run(cutoffFixtureNow+100, false, "serve"); err != nil {
		t.Fatalf("restart serve: %v %s", err, output)
	}
	if output, err := fixture.run(cutoffFixtureNow+100, false, "route-up"); err != nil {
		t.Fatalf("restart routing: %v %s", err, output)
	}
	if output, err := fixture.run(cutoffFixtureNow+100, false, "up", strconv.FormatInt(final+100, 10)); err == nil {
		t.Fatalf("up extended existing transport authority: %s", output)
	}
	var timeoutArgs []string
	if err := json.Unmarshal([]byte(fixture.read("timeout.json")), &timeoutArgs); err != nil {
		t.Fatal(err)
	}
	if len(timeoutArgs) < 4 || strings.Join(timeoutArgs[:3], " ") != "--signal=TERM --kill-after=5 1040" {
		t.Fatalf("serve reset or exceeded runtime deadline: %v", timeoutArgs)
	}
	if fixture.read("stage/deadline") != strconv.FormatInt(final, 10)+"\n" || fixture.read("stage/runtime-deadline") != strconv.FormatInt(final-60, 10)+"\n" {
		t.Fatal("restart changed persisted cutoff")
	}
	if output, err := fixture.run(final, false, "route-up"); err == nil {
		t.Fatalf("expired route-up accepted: %s", output)
	}
}

func TestQualificationTransportServeRefusesInvalidOrExpiredCutoff(t *testing.T) {
	for _, runtimeDeadline := range []string{"", "not-an-epoch\n", strconv.FormatInt(cutoffFixtureNow-1, 10) + "\n"} {
		t.Run(strings.TrimSpace(runtimeDeadline), func(t *testing.T) {
			fixture := newTransportCutoffFixture(t)
			fixture.routedState(cutoffFixtureNow + 1200)
			if runtimeDeadline == "" {
				if err := os.Remove(filepath.Join(fixture.stage, "runtime-deadline")); err != nil {
					t.Fatal(err)
				}
			} else {
				fixture.write("stage/runtime-deadline", runtimeDeadline)
			}
			if output, err := fixture.run(cutoffFixtureNow, false, "serve"); err == nil {
				t.Fatalf("unsafe serve deadline accepted: %s", output)
			}
			if _, err := os.Stat(filepath.Join(fixture.directory, "timeout.json")); !os.IsNotExist(err) {
				t.Fatal("unsafe serve invoked gateway timeout")
			}
		})
	}
}

func (fixture *transportCutoffFixture) routedState(final int64) {
	fixture.t.Helper()
	fixture.write("stage/transport-owned", "fixture ownership\n")
	fixture.write("stage/qualification-manifest.json", `{"releases":[]}`)
	fixture.write("stage/deadline", strconv.FormatInt(final, 10)+"\n")
	fixture.write("stage/runtime-deadline", strconv.FormatInt(final-60, 10)+"\n")
	fixture.write("stage/ca.crt", "fixture CA\n")
	fixture.write("ca", "fixture CA\n")
	fixture.write("stage/gateway.key", "private fixture key\n")
	fixture.write("stage/unit", "fixture unit\n")
	fixture.write("service", "fixture unit\n")
	if err := os.Symlink(filepath.Join(fixture.directory, "service"), filepath.Join(fixture.directory, "service-link")); err != nil {
		fixture.t.Fatal(err)
	}
	fixture.write("stage/hosts.before", "127.0.0.1 localhost\n")
	fixture.write("stage/hosts.after", "127.0.0.1 localhost\n127.0.0.2 api.github.com github.com # sbxr-qualification-v3\n")
	fixture.write("hosts", fixture.read("stage/hosts.after")+"192.0.2.1 unrelated\n")
	fixture.write("rule", "exact owned NAT rule\n")
}

func TestQualificationTransportAutomaticCutoffCleanupRetriesWithoutDeletingStaging(t *testing.T) {
	fixture := newTransportCutoffFixture(t)
	final := cutoffFixtureNow - 1
	fixture.routedState(final)
	fixture.write("fail-delete", "refuse\n")
	if output, err := fixture.run(cutoffFixtureNow, false, "route-down"); err == nil {
		t.Fatalf("failed NAT cleanup reported success: %s", output)
	}
	if fixture.read("stage/deadline") != strconv.FormatInt(final, 10)+"\n" || fixture.read("ca") != "fixture CA\n" {
		t.Fatal("failed cleanup reset deadline or removed unproved trust")
	}
	if err := os.Remove(filepath.Join(fixture.directory, "fail-delete")); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if output, err := fixture.run(cutoffFixtureNow+100, false, "route-down"); err != nil {
			t.Fatalf("cleanup retry %d: %v %s", attempt, err, output)
		}
	}
	for _, path := range []string{"rule", "ca"} {
		if _, err := os.Lstat(filepath.Join(fixture.directory, path)); !os.IsNotExist(err) {
			t.Fatalf("owned route residue remains: %s", path)
		}
	}
	if fixture.read("hosts") != "127.0.0.1 localhost\n192.0.2.1 unrelated\n" || fixture.read("stage/gateway.key") != "private fixture key\n" || fixture.read("service") != "fixture unit\n" {
		t.Fatal("automatic cutoff changed unrelated hosts, staging or service")
	}
	if target, err := os.Readlink(filepath.Join(fixture.directory, "service-link")); err != nil || target != filepath.Join(fixture.directory, "service") {
		t.Fatal("automatic cutoff changed retained enablement link")
	}
	if strings.Contains(fixture.read("commands"), "systemctl stop") {
		t.Fatal("automatic callback stopped its own service")
	}
}

func TestQualificationTransportRollbackReportsSubshellFailureAndFreshRetry(t *testing.T) {
	for _, failure := range []string{"foreign-ca", "iptables-delete"} {
		t.Run(failure, func(t *testing.T) {
			fixture := newTransportCutoffFixture(t)
			fixture.routedState(cutoffFixtureNow - 1)
			wantStatus, wantCA := 1, "foreign CA bytes\n"
			if failure == "foreign-ca" {
				fixture.write("ca", wantCA)
			} else {
				wantStatus, wantCA = 4, "fixture CA\n"
				fixture.write("fail-delete", "refuse\n")
			}
			output, err := fixture.run(cutoffFixtureNow, false, "route-down")
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != wantStatus || string(output) != "SBXR-TRANSPORT-ROLLBACK-FAILED\n" {
				t.Fatalf("failed subshell status/diagnostic = %v %q; want status %d and fixed failure code", err, output, wantStatus)
			}
			if fixture.read("ca") != wantCA || fixture.read("stage/gateway.key") != "private fixture key\n" {
				t.Fatal("failed rollback changed foreign CA or private staging")
			}
			if failure == "foreign-ca" {
				fixture.write("ca", "fixture CA\n")
			} else if err := os.Remove(filepath.Join(fixture.directory, "fail-delete")); err != nil {
				t.Fatal(err)
			}
			output, err = fixture.run(cutoffFixtureNow+5, false, "route-down")
			if err != nil || string(output) != "SBXR-TRANSPORT-ROUTES-RESTORED\n" {
				t.Fatalf("fresh rollback retry = %v %q", err, output)
			}
			for _, path := range []string{"rule", "ca"} {
				if _, err := os.Lstat(filepath.Join(fixture.directory, path)); !os.IsNotExist(err) {
					t.Fatalf("successful rollback retained %s", path)
				}
			}
			if fixture.read("hosts") != "127.0.0.1 localhost\n192.0.2.1 unrelated\n" || fixture.read("stage/gateway.key") != "private fixture key\n" || fixture.read("service") != "fixture unit\n" {
				t.Fatal("rollback retry changed unrelated hosts, staging or service")
			}
		})
	}
}

func TestQualificationTransportRollbackStatusSurvivesClosedDiagnosticStderr(t *testing.T) {
	for _, failure := range []string{"none", "foreign-ca", "iptables-delete"} {
		t.Run(failure, func(t *testing.T) {
			fixture := newTransportCutoffFixture(t)
			fixture.routedState(cutoffFixtureNow - 1)
			fixture.write("closed-stderr.sh", "exec 2>&-\nexec bash "+shellCutoffQuote(fixture.script)+" \"$@\"\n")
			fixture.script = filepath.Join(fixture.directory, "closed-stderr.sh")
			wantStatus := 0
			if failure == "foreign-ca" {
				wantStatus = 1
				fixture.write("ca", "foreign CA bytes\n")
			} else if failure == "iptables-delete" {
				wantStatus = 4
				fixture.write("fail-delete", "refuse\n")
			}
			output, err := fixture.run(cutoffFixtureNow, false, "route-down")
			status := 0
			if err != nil {
				exit, ok := err.(*exec.ExitError)
				if !ok {
					t.Fatalf("callback did not complete normally: %v", err)
				}
				status = exit.ExitCode()
			}
			if status != wantStatus || len(output) != 0 {
				t.Fatalf("closed-stderr cleanup status/output = %d %q; want %d and no diagnostic", status, output, wantStatus)
			}
			if failure == "none" {
				for _, path := range []string{"rule", "ca"} {
					if _, err := os.Lstat(filepath.Join(fixture.directory, path)); !os.IsNotExist(err) {
						t.Fatalf("successful cleanup retained %s", path)
					}
				}
				if fixture.read("hosts") != "127.0.0.1 localhost\n192.0.2.1 unrelated\n" {
					t.Fatal("successful cleanup changed unrelated hosts")
				}
			} else if failure == "foreign-ca" && fixture.read("ca") != "foreign CA bytes\n" {
				t.Fatal("failed cleanup removed foreign CA")
			} else if failure == "iptables-delete" && fixture.read("rule") != "exact owned NAT rule\n" {
				t.Fatal("failed routing cleanup fabricated rule absence")
			}
			if fixture.read("stage/gateway.key") != "private fixture key\n" || fixture.read("service") != "fixture unit\n" {
				t.Fatal("diagnostic failure changed retained staging or service")
			}
		})
	}
}

func TestQualificationTransportManualDownWaitsForStopBeforeRouteCleanup(t *testing.T) {
	fixture := newTransportCutoffFixture(t)
	fixture.routedState(cutoffFixtureNow + 1200)
	fixture.write("fail-stop", "refuse\n")
	if output, err := fixture.run(cutoffFixtureNow, false, "down"); err == nil {
		t.Fatalf("failed stop reported cleanup: %s", output)
	}
	if fixture.read("rule") != "exact owned NAT rule\n" || fixture.read("ca") != "fixture CA\n" {
		t.Fatal("route cleanup ran before confirmed stop")
	}
	if err := os.Remove(filepath.Join(fixture.directory, "fail-stop")); err != nil {
		t.Fatal(err)
	}
	fixture.write("commands", "")
	if output, err := fixture.run(cutoffFixtureNow, false, "down"); err != nil {
		t.Fatalf("manual retry: %v %s", err, output)
	}
	commands := fixture.read("commands")
	stop, lock, cleanup := strings.Index(commands, "systemctl stop"), strings.Index(commands, "flock "), strings.Index(commands, "-D OUTPUT")
	if stop < 0 || lock < stop || cleanup < lock {
		t.Fatalf("manual down does not wait for stop before locked route cleanup: %s", commands)
	}
}

func TestQualificationTransportCutoffRejectsReplacedOwnershipAfterLockWait(t *testing.T) {
	fixture := newTransportCutoffFixture(t)
	fixture.routedState(cutoffFixtureNow - 1)
	fixture.write("replace-owner-on-lock", "replace\n")
	if output, err := fixture.run(cutoffFixtureNow, false, "route-down"); err == nil {
		t.Fatalf("old waiter cleaned a replacement owner: %s", output)
	}
	if fixture.read("rule") != "exact owned NAT rule\n" || fixture.read("ca") != "fixture CA\n" || fixture.read("stage/transport-owned") != "replacement owner\n" {
		t.Fatal("old waiter changed replacement authority or routes")
	}
}

func TestQualificationTransportManualDownKeepsOriginalOwnerAcrossStop(t *testing.T) {
	fixture := newTransportCutoffFixture(t)
	fixture.routedState(cutoffFixtureNow + 1200)
	fixture.write("replace-owner-on-stop", "replace\n")
	if output, err := fixture.run(cutoffFixtureNow, false, "down"); err == nil {
		t.Fatalf("old stop cleaned replacement transport authority: %s", output)
	}
	if fixture.read("rule") != "exact owned NAT rule\n" || fixture.read("ca") != "fixture CA\n" || fixture.read("stage/transport-owned") != "replacement owner\n" || fixture.read("stage/gateway.key") != "private fixture key\n" || fixture.read("service") != "fixture unit\n" {
		t.Fatal("old stop changed replacement authority, routes, staging or service")
	}
	if !strings.Contains(fixture.read("commands"), "systemctl stop") {
		t.Fatal("ownership replacement was not exercised during stop")
	}
}

func TestQualificationTransportRefusesEmptyFailedUnitQueries(t *testing.T) {
	for _, operation := range []string{"up", "down"} {
		for _, property := range []string{"FragmentPath", "DropInPaths", "KillMode", "MainPID", "ControlPID", "ActiveState"} {
			if operation == "up" && (property == "MainPID" || property == "ControlPID" || property == "ActiveState") {
				continue
			}
			t.Run(operation+"/"+property, func(t *testing.T) {
				fixture := newTransportCutoffFixture(t)
				fixture.write("fail-show", property)
				args := []string{operation}
				if operation == "up" {
					fixture.attendance(time.Unix(cutoffFixtureNow+3600, 0).UTC().Format(time.RFC3339))
					args = append(args, strconv.FormatInt(cutoffFixtureNow+1200, 10))
				} else {
					fixture.routedState(cutoffFixtureNow + 1200)
				}
				if output, err := fixture.run(cutoffFixtureNow, false, args...); err == nil {
					t.Fatalf("empty failed %s query accepted: %s", property, output)
				}
				commands := fixture.read("commands")
				if strings.Contains(commands, "-D OUTPUT") || strings.Contains(commands, "-A OUTPUT") || strings.Contains(commands, "systemctl enable") || strings.Contains(commands, "systemctl start") {
					t.Fatal("failed unit query reached routing or service activation")
				}
				if operation == "up" {
					if fixture.read("hosts") != "127.0.0.1 localhost\n" {
						t.Fatal("failed admission changed hosts")
					}
				} else {
					if fixture.read("rule") != "exact owned NAT rule\n" || fixture.read("ca") != "fixture CA\n" || fixture.read("stage/transport-owned") != "fixture ownership\n" {
						t.Fatal("failed query changed transport authority or routes")
					}
					if (property == "FragmentPath" || property == "DropInPaths" || property == "KillMode") && strings.Contains(commands, "systemctl stop") {
						t.Fatal("unproved unit route reached stop")
					}
				}
			})
		}
	}
}

const transportCutoffCommandFixture = `#!/usr/bin/env python3
import datetime, json, os, pathlib, subprocess, sys
root = pathlib.Path(os.environ["SBXR_CUTOFF_FIXTURE"])
name, args = pathlib.Path(sys.argv[0]).name, sys.argv[1:]
with (root / "commands").open("a") as stream:
    stream.write(name + " " + " ".join(args) + "\n")
if name == "date":
    if args == ["+%s"]:
        print(os.environ["SBXR_CUTOFF_NOW"])
    elif "-d" in args:
        try:
            value = args[args.index("-d") + 1]
            print(int(datetime.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()))
        except Exception:
            sys.exit(1)
    else:
        sys.exit(80)
elif name == "id":
    print("0")
elif name == "iptables":
    rule = root / "rule"
    if "-C" in args:
        sys.exit(0 if rule.exists() else 1)
    if "-D" in args:
        if (root / "fail-delete").exists():
            sys.exit(4)
        rule.unlink()
    elif "-A" in args:
        rule.write_text("exact owned NAT rule\n")
    else:
        sys.exit(80)
elif name == "systemctl":
    if args and args[0] == "stop" and (root / "fail-stop").exists():
        sys.exit(1)
    if args and args[0] == "stop" and (root / "replace-owner-on-stop").exists():
        marker = root / "stage/transport-owned"
        marker.rename(root / "old-owner")
        marker.write_text("replacement owner\n")
    if args and args[0] == "show":
        values = {"FragmentPath":str(root / "service"), "DropInPaths":"", "KillMode":"control-group", "ActiveState":"inactive", "MainPID":"0", "ControlPID":"0"}
        fields = [arg.removeprefix("--property=") for arg in args if arg.startswith("--property=")]
        if len(fields) != 1 or fields[0] not in values:
            sys.exit(80)
        if (root / "fail-show").exists() and (root / "fail-show").read_text() == fields[0]:
            sys.exit(1)
        print(values[fields[0]])
elif name == "timeout":
    (root / "timeout.json").write_text(json.dumps(args))
    if args[-1:] == ["route-down"]:
        command = args[3:]
        if len(command) != 3 or command[0] not in ("/usr/bin/bash", "bash") or pathlib.Path(command[1]).resolve() not in ((root / "transport.sh").resolve(), (root / "stage/v3-qualification-transport.sh").resolve()):
            sys.exit(80)
        sys.exit(subprocess.run(["bash", *command[1:]], check=False).returncode)
elif name == "flock":
    if (root / "fail-lock").exists():
        sys.exit(1)
    if (root / "replace-owner-on-lock").exists():
        marker = root / "stage/transport-owned"
        marker.rename(root / "stage/old-owner")
        marker.write_text("replacement owner\n")
elif name == "update-ca-certificates":
    if (root / "fail-refresh").exists():
        sys.exit(1)
elif name not in ("curl", "ss"):
    sys.exit(80)
`
