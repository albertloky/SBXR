// Isolated lifecycle/menu fixture, NOT a release or trusted target. The real
// terminal and Software Lifecycle code run with synthetic release/admission/
// runtime seams. Never use on a VPS or as packaged qualification evidence.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/albertloky/SBXR/internal/proxyinstallation"
	"github.com/albertloky/SBXR/internal/proxyinstallation/adapter/terminal"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func read(path string) []byte { b, err := os.ReadFile(path); must(err); return b }
func hash(b []byte) string    { return fmt.Sprintf("%x", sha256.Sum256(b)) }
func write(path string, b []byte, mode os.FileMode) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	must(err)
	_, err = f.Write(b)
	must(err)
	must(f.Chmod(mode))
	must(f.Close())
}
func marshal(v any) []byte { b, err := json.Marshal(v); must(err); return b }

type record struct {
	Schema       int                            `json:"schema"`
	Repository   string                         `json:"repository"`
	Tag          string                         `json:"tag"`
	Commit       string                         `json:"commit"`
	Index        string                         `json:"release_index_sha256"`
	Sequence     uint64                         `json:"sequence"`
	Architecture softwarelifecycle.Architecture `json:"architecture"`
	Executable   string                         `json:"executable_sha256"`
}

func release(tag, commit, index string, sequence uint64) softwarelifecycle.LatestRelease {
	return softwarelifecycle.LatestRelease{Identity: softwarelifecycle.ReleaseIdentity{Repository: softwarelifecycle.Repository, Tag: tag, Commit: commit, IndexSHA256: index}, Sequence: sequence}
}

var prior = release("v99.0.1", strings.Repeat("1", 40), strings.Repeat("a", 64), 9901)
var target = release("v99.0.2", strings.Repeat("2", 40), strings.Repeat("b", 64), 9902)

func prepare(work, source, candidate string) {
	arch := softwarelifecycle.Architecture(runtime.GOARCH)
	stamped := func(name string, r softwarelifecycle.LatestRelease, input string) []byte {
		b, err := softwarelifecycle.StampReleaseExecutable(read(input), r.Identity.Tag, r.Identity.Commit, r.Sequence, arch)
		must(err)
		if !softwarelifecycle.VerifyLinuxExecutable(b, arch) {
			panic("invalid fixture binary")
		}
		write(filepath.Join(work, name), b, 0o755)
		d := record{1, softwarelifecycle.Repository, r.Identity.Tag, r.Identity.Commit, r.Identity.IndexSHA256, r.Sequence, arch, hash(b)}
		write(filepath.Join(work, name+".json"), append(marshal(d), '\n'), 0o600)
		return b
	}
	stamped("source", prior, source)
	b := stamped("candidate", target, candidate)
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	tw := tar.NewWriter(gz)
	must(tw.WriteHeader(&tar.Header{Name: "sbxr", Mode: 0o755, Size: int64(len(b)), Typeflag: tar.TypeReg}))
	_, err := tw.Write(b)
	must(err)
	must(tw.Close())
	must(gz.Close())
	write(filepath.Join(work, "candidate.tgz"), compressed.Bytes(), 0o600)
}

type source struct{ work string }

func (s source) CheckLatest(context.Context) (softwarelifecycle.LatestRelease, softwarelifecycle.LatestReleaseOutcome) {
	return target, softwarelifecycle.LatestReleaseAccepted
}
func (s source) PrepareLatest(_ context.Context, arch softwarelifecycle.Architecture) (softwarelifecycle.UpdateCandidate, softwarelifecycle.LatestReleaseOutcome) {
	c, ok := softwarelifecycle.VerifyLatestUpdateArchive(target, arch, read(filepath.Join(s.work, "candidate.tgz")))
	if !ok {
		panic("synthetic candidate archive refused")
	}
	return c, softwarelifecycle.LatestReleaseAccepted
}

type proxy struct{}

func (proxy) Review(context.Context, proxyinstallation.Action) proxyinstallation.Review {
	return proxyinstallation.Review{Status: proxyinstallation.Running, Version: "ISOLATED FIXTURE — not a release",
		SubscriptionStatus: proxyinstallation.SubscriptionNotEnabled}
}
func (proxy) Execute(context.Context, proxyinstallation.PreparedAction, proxyinstallation.Confirmation, proxyinstallation.ProgressReporter) proxyinstallation.Result {
	panic("fixture never permits proxy mutations")
}

func main() {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 || string(read("/run/sbxr-isolated-test-host")) != "disposable SBXR test VM\n" {
		panic("marked disposable root Linux VM required")
	}
	if len(os.Args) == 5 && os.Args[1] == "prepare" {
		prepare(os.Args[2], os.Args[3], os.Args[4])
		return
	}
	if len(os.Args) != 1 {
		panic("unexpected arguments")
	}
	work := os.Getenv("SBXR_WINDOW_RECOVERY_FIXTURE")
	if work == "" {
		panic("fixture directory required")
	}
	target.Support = &softwarelifecycle.ReleaseSupport{Scope: softwarelifecycle.RecurringSubscriptionUpgrade,
		Sources: []softwarelifecycle.ReleaseIdentity{prior.Identity}, Contract: softwarelifecycle.SubscriptionUpdateContract}
	// These are explicitly synthetic proxy/runtime seams, not host trust proof.
	admit := func([]byte, softwarelifecycle.ReleaseIdentity, *softwarelifecycle.UpdateTarget) bool { return true }
	lifecycle := softwarelifecycle.NewInstalledWithUpdateRuntime(source{work}, admit, softwarelifecycle.UpdateRuntime{
		Acquire: func(_ context.Context, _ []byte, _ softwarelifecycle.ReleaseIdentity, _ *softwarelifecycle.UpdateTarget, lock *softwarelifecycle.MutationLockAuthority) (func(), bool) {
			return func() {}, lock != nil && lock.Holds("/run/lock/sbxr.lock")
		},
		Complete: func(_ context.Context, _ []byte, active softwarelifecycle.ReleaseIdentity, lock *softwarelifecycle.MutationLockAuthority) bool {
			if active != target.Identity || lock == nil || !lock.Holds("/run/lock/sbxr.lock") {
				return false
			}
			write(filepath.Join(work, "runtime-completed"), []byte("candidate forward runtime completed with lock held\n"), 0o600)
			return true
		},
	})
	os.Exit(terminal.Run(context.Background(), nil, os.Stdin, os.Stdout, os.Stderr, proxy{}, lifecycle))
}
