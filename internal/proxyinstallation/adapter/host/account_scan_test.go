package host

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const accountMountTable = "1 0 8:1 / / rw - ext4 none rw\n2 1 0:1 / /proc rw - proc proc rw\n3 1 0:2 / /sys rw - sysfs sysfs rw\n4 1 8:2 / /data rw - ext4 none rw\n5 2 8:3 / /proc/nested rw - ext4 none rw\n6 1 0:3 / /memory rw - tmpfs none rw\n7 1 8:1 /source /same rw - ext4 none rw\n8 1 0:4 / /opaque rw - unknownfs none rw\n9 1 8:4 / /var/lib/sing-box/nested rw - ext4 none rw\n"

func accountScanFixture(t *testing.T) Adapter {
	t.Helper()
	directory := t.TempDir()
	root := filepath.Join(directory, "root")
	for _, path := range []string{"proc/self", "proc/77", "proc/nested", "sys", "data", "memory", "same", "opaque", "var/lib/sing-box/nested"} {
		if err := os.MkdirAll(filepath.Join(root, path), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for path, body := range map[string]string{"proc/self/mountinfo": accountMountTable, "proc/77/status": "process metadata", "sys/virtual": "virtual metadata"} {
		if err := os.WriteFile(filepath.Join(root, path), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Only ownership predicates are translated: every regular fixture file is
	// account-owned, except uid-only/gid-only controls. Real find exercises
	// pruning, path escaping and exceptions;
	// the mount table is synthetic, and no real mounts or chown are performed.
	command := `#!/bin/sh
case "${0##*/}" in
cat)
  [ "$SCAN_CASE" != read ] || exit 1
  if [ -e "$SCAN_READ" ]; then
    [ "$SCAN_CASE" != reread ] || exit 1
    [ "$SCAN_CASE" != topology ] || { printf 'changed\n'; exit 0; }
  fi
  : > "$SCAN_READ"
  exec /bin/cat "$@";;
find)
  [ "$SCAN_CASE" != scan ] || exit 1
  if [ "$SCAN_CASE" = deadline ]; then : > "$SCAN_STARTED"; while :; do :; done; fi
  remaining=$#
  while [ "$remaining" -gt 0 ]; do
    arg=$1; shift; remaining=$((remaining-1))
    case "$arg" in
      -uid) [ "$1" = 999 ] || exit 99; shift; remaining=$((remaining-1)); set -- "$@" '(' -type f '!' -name gid-only ')';;
      -gid) [ "$1" = 998 ] || exit 99; shift; remaining=$((remaining-1)); set -- "$@" '(' -type f '!' -name uid-only ')';;
      *) set -- "$@" "$arg";;
    esac
  done
  exec /usr/bin/find "$@";;
pgrep)
  if [ "$SCAN_CASE" = foreign-process ] && [ "$1" != -x ]; then printf '77\n88\n'; else printf '77\n'; fi;;
*) exit 99;;
esac
`
	for _, name := range []string{"cat", "find", "pgrep"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(command), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", directory)
	t.Setenv("SCAN_READ", filepath.Join(directory, "read"))
	t.Setenv("SCAN_STARTED", filepath.Join(directory, "started"))
	t.Setenv("SCAN_CASE", "clean")
	return Adapter{root: root}
}
func accountFixtureFile(t *testing.T, a Adapter, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(a.path(path)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.path(path), []byte("account data"), 0o600); err != nil {
		t.Fatal(err)
	}
}
func TestAccountScanAllowsRunningProcessMetadataAndCleanMounts(t *testing.T) {
	a := accountScanFixture(t)
	if exclusive, observed := a.identityExclusive(t.Context(), testSetupSpec(), 999, 998, true); !exclusive || !observed {
		t.Fatalf("identity=%v observed=%v", exclusive, observed)
	}
	if !a.groupExclusive(t.Context(), testSetupSpec(), "sing-box:x:998:") {
		t.Fatal("group refused")
	}
	if exclusive, observed := a.processExclusive(t.Context(), "sing-box", 999, 998, true); !exclusive || !observed {
		t.Fatal("allowed running process refused")
	}
	t.Setenv("SCAN_CASE", "foreign-process")
	if exclusive, _ := a.processExclusive(t.Context(), "sing-box", 999, 998, true); exclusive {
		t.Fatal("foreign process admitted")
	}
	if a.groupExclusive(t.Context(), testSetupSpec(), "sing-box:x:998:") {
		t.Fatal("foreign group process admitted")
	}
}
func TestAccountScanFindsDataOnNestedRealBindTmpfsAndUnknownMounts(t *testing.T) {
	for _, path := range []string{"/data/foreign", "/proc/nested/foreign", "/memory/foreign", "/same/foreign", "/opaque/foreign", "/var/lib/sing-box/nested/foreign"} {
		t.Run(path, func(t *testing.T) {
			a := accountScanFixture(t)
			accountFixtureFile(t, a, path)
			if exclusive, observed := a.identityExclusive(t.Context(), testSetupSpec(), 999, 998, true); exclusive || !observed {
				t.Fatalf("identity=%v observed=%v", exclusive, observed)
			}
			if a.groupExclusive(t.Context(), testSetupSpec(), "sing-box:x:998:") {
				t.Fatal("foreign group file admitted")
			}
		})
	}
}
func TestAccountScanPreservesOnlyScopedConfigurationStateExceptions(t *testing.T) {
	a := accountScanFixture(t)
	accountFixtureFile(t, a, "/etc/sing-box/config.json")
	accountFixtureFile(t, a, "/var/lib/sing-box/owned")
	if exclusive, observed := a.identityExclusive(t.Context(), testSetupSpec(), 999, 998, true); !exclusive || !observed {
		t.Fatal("owned files refused")
	}
	if a.groupExclusive(t.Context(), testSetupSpec(), "sing-box:x:998:") {
		t.Fatal("leftover group ignores owned files")
	}
}
func TestAccountScanObservationFailuresAndDeadlinesRefuse(t *testing.T) {
	for _, fault := range []string{"read", "reread", "topology", "scan", "deadline", "cancelled"} {
		t.Run(fault, func(t *testing.T) {
			a := accountScanFixture(t)
			t.Setenv("SCAN_CASE", fault)
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			if fault == "cancelled" {
				cancel()
			}
			start := time.Now()
			if exclusive, observed := a.identityExclusive(ctx, testSetupSpec(), 999, 998, true); exclusive || observed {
				t.Fatalf("identity=%v observed=%v", exclusive, observed)
			}
			if fault == "deadline" {
				if _, err := os.Stat(os.Getenv("SCAN_STARTED")); err != nil {
					t.Fatal("deadline fixture never entered find", err)
				}
			}
			if time.Since(start) > 3*time.Second {
				t.Fatal("fixture deadline not honored")
			}
		})
	}
}
func TestAccountMountParserRejectsIncompleteAmbiguousUnsafeData(t *testing.T) {
	for _, body := range []string{"", strings.TrimSpace(accountMountTable), strings.ReplaceAll(accountMountTable, "8:1", "bad"), strings.ReplaceAll(accountMountTable, "/data", "/../data"), strings.ReplaceAll(accountMountTable, "/data", "/proc"), strings.ReplaceAll(accountMountTable, "4 1", "3 1"), strings.ReplaceAll(accountMountTable, "/data", `/bad\999`), strings.ReplaceAll(accountMountTable, "1 0", "x 0"), strings.ReplaceAll(accountMountTable, "1 0", "1 4"), strings.ReplaceAll(accountMountTable, "/ / rw - ext4", "/ / rw - proc"), "\xff\n", strings.Repeat("\n", (1<<20)+1)} {
		if _, err := accountMounts(body); err == nil {
			t.Errorf("accepted malformed table %q", body[:min(len(body), 100)])
		}
	}
	a := accountScanFixture(t)
	if err := os.WriteFile(a.path("/proc/self/mountinfo"), []byte("malformed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if exclusive, observed := a.identityExclusive(t.Context(), testSetupSpec(), 999, 998, true); exclusive || observed {
		t.Fatal("malformed observation admitted")
	}
	if _, err := accountMounts(strings.ReplaceAll(accountMountTable, "rw - ext4", "rw future:tag - ext4")); err != nil {
		t.Fatal(err)
	}
	if _, err := accountMounts(strings.ReplaceAll(accountMountTable, "1 0", "1 1")); err != nil {
		t.Fatal(err)
	}
	if path, err := accountMountPath(`/a\040b\011c\012d\134e`); err != nil || path != "/a b\tc\nd\\e" {
		t.Fatalf("path=%q err=%v", path, err)
	}
}
func TestAccountMountPatternsAreLiteral(t *testing.T) {
	a := accountScanFixture(t)
	table := accountMountTable + "10 1 0:9 / /v[ab]\\040space rw - proc none rw\n"
	if err := os.WriteFile(a.path("/proc/self/mountinfo"), []byte(table), 0o600); err != nil {
		t.Fatal(err)
	}
	accountFixtureFile(t, a, "/v[ab] space/metadata")
	if exclusive, _ := a.identityExclusive(t.Context(), testSetupSpec(), 999, 998, true); !exclusive {
		t.Fatal("literal virtual path refused")
	}
	accountFixtureFile(t, a, "/va space/foreign")
	if exclusive, _ := a.identityExclusive(t.Context(), testSetupSpec(), 999, 998, true); exclusive {
		t.Fatal("pattern hid foreign data")
	}
}

func TestAccountScanUIDOnlyAndGIDOnlyData(t *testing.T) {
	for _, name := range []string{"uid-only", "gid-only"} {
		t.Run(name, func(t *testing.T) {
			a := accountScanFixture(t)
			accountFixtureFile(t, a, "/proc/nested/"+name)
			if exclusive, observed := a.identityExclusive(t.Context(), testSetupSpec(), 999, 998, true); exclusive || !observed {
				t.Fatal("foreign account file admitted or unobserved")
			}
			if got := a.groupExclusive(t.Context(), testSetupSpec(), "sing-box:x:998:"); got != (name == "uid-only") {
				t.Fatal("group scan used incorrect owner predicate")
			}
		})
	}
}

func TestAccountScanHiddenVirtualMountCannotPruneVisibleOvermountData(t *testing.T) {
	a := accountScanFixture(t)
	table := accountMountTable + "10 1 0:9 / /data/hidden rw - proc none rw\n"
	if err := os.WriteFile(a.path("/proc/self/mountinfo"), []byte(table), 0o600); err != nil {
		t.Fatal(err)
	}
	accountFixtureFile(t, a, "/data/hidden/foreign")
	if exclusive, _ := a.identityExclusive(t.Context(), testSetupSpec(), 999, 998, true); exclusive {
		t.Fatal("hidden proc mount pruned visible foreign data in covering mount")
	}
}
