package ubuntu

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/albertloky/SBXR/internal/systemchanges"
)

const transactionDirectory = "var/lib/sbxr/transactions"

// Host owns the typed native effects and observations; Adapter owns their durability.
type Host interface {
	CaptureRollback(systemchanges.Step, func(source io.Reader) error) error
	Execute(systemchanges.Step, time.Duration) (systemchanges.StepEvidence, error)
	Check(systemchanges.Check, systemchanges.GatePhase, time.Duration) (systemchanges.HealthStatus, error)
	VerifyAgreement(systemchanges.Agreement) error
}

type snapshotManifest struct {
	SchemaVersion int                          `json:"schema_version"`
	Release       systemchanges.ReleaseBinding `json:"release_identity"`
	Reason        systemchanges.MutationClass  `json:"reason"`
	Files         map[string]string            `json:"sha256"`
}

type journalStep struct {
	Owner    systemchanges.Module        `json:"owner"`
	Forward  systemchanges.OperationKind `json:"forward"`
	Rollback systemchanges.OperationKind `json:"rollback"`
}

type journalEntry struct {
	Checkpoint systemchanges.DurableCheckpoint        `json:"checkpoint"`
	Step       int                                    `json:"step,omitempty"`
	ChangeSet  string                                 `json:"change_set,omitempty"`
	Starting   systemchanges.StateLineage             `json:"starting_state,omitempty"`
	PlanSHA256 string                                 `json:"plan_sha256,omitempty"`
	State      *systemchanges.StateTransactionBinding `json:"state,omitempty"`
	Steps      []journalStep                          `json:"steps,omitempty"`
	Checks     []systemchanges.Check                  `json:"health_gates,omitempty"`
	Evidence   *systemchanges.StepEvidence            `json:"evidence,omitempty"`
}

func (a Adapter) Prepare(lease systemchanges.ExecutionLease, preparation systemchanges.Preparation) error {
	if !lease.Authorized() || a.host == nil || !safeName(preparation.ChangeSet) {
		return errors.New("typed Ubuntu transaction host unavailable")
	}
	root, err := os.OpenRoot(a.root)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.MkdirAll(transactionDirectory, 0o700); err != nil {
		return err
	}
	if err := verifyDirectory(root, transactionDirectory, a.uid); err != nil {
		return err
	}
	target := path.Join(transactionDirectory, preparation.ChangeSet)
	temporary := target + ".preparing"
	if _, err := root.Lstat(target); err == nil || !errors.Is(err, fs.ErrNotExist) {
		return errors.New("active transaction material already exists")
	}
	if _, err := root.Lstat(temporary); err == nil || !errors.Is(err, fs.ErrNotExist) {
		return errors.New("unresolved temporary transaction material exists")
	}
	for _, directory := range []string{temporary, path.Join(temporary, "snapshot"), path.Join(temporary, "prepared")} {
		if err := root.Mkdir(directory, 0o700); err != nil {
			return err
		}
	}
	checksums := map[string]string{}
	write := func(name string, mode uint32, source io.Reader) error {
		if mode != 0o600 || !safeArtifact(name) || checksums[name] != "" {
			return errors.New("unsafe or duplicate transaction artifact")
		}
		checksum, err := writeProtected(root, path.Join(temporary, name), source, a.uid)
		if err == nil {
			checksums[name] = checksum
		}
		return err
	}
	if err := preparation.WriteStateArtifacts(write); err != nil {
		return err
	}
	for index, step := range preparation.Steps {
		called := false
		captureRollback := func(source io.Reader) error {
			if called || source == nil {
				return errors.New("rollback capture must provide one exact artifact")
			}
			called = true
			return write(fmt.Sprintf("snapshot/step-%03d.rollback", index+1), 0o600, source)
		}
		if err := a.host.CaptureRollback(step, captureRollback); err != nil || !called {
			return errors.New("rollback capture is incomplete")
		}
	}
	release := preparation.State.StartingRelease
	if release == (systemchanges.ReleaseBinding{}) {
		release = preparation.State.CandidateRelease
	}
	manifest := snapshotManifest{SchemaVersion: 1, Release: release, Reason: preparation.Mutation, Files: checksums}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	if _, err := writeProtected(root, path.Join(temporary, "manifest.json"), strings.NewReader(string(manifestBytes)), a.uid); err != nil {
		return err
	}
	steps := make([]journalStep, len(preparation.Steps))
	for index, step := range preparation.Steps {
		steps[index] = journalStep{Owner: step.Owner(), Forward: step.Forward(), Rollback: step.Rollback()}
	}
	entry := journalEntry{Checkpoint: systemchanges.Prepared, ChangeSet: preparation.ChangeSet, Starting: preparation.Starting, PlanSHA256: preparation.PlanSHA256, State: &preparation.State, Steps: steps, Checks: preparation.Checks}
	if _, err := writeProtected(root, path.Join(temporary, "journal.jsonl"), strings.NewReader(""), a.uid); err != nil {
		return err
	}
	for _, directory := range []string{path.Join(temporary, "snapshot"), path.Join(temporary, "prepared"), temporary} {
		if err := syncDirectory(root, directory); err != nil {
			return err
		}
	}
	if err := verifyTransaction(root, temporary, a.uid); err != nil {
		return err
	}
	if err := root.Rename(temporary, target); err != nil {
		return err
	}
	if err := syncDirectory(root, transactionDirectory); err != nil {
		return err
	}
	if err := verifyTransaction(root, target, a.uid); err != nil {
		return err
	}
	if err := appendJournal(root, path.Join(target, "journal.jsonl"), entry, a.uid); err != nil {
		return err
	}
	return verifyTransaction(root, target, a.uid)
}

func (a Adapter) Record(lease systemchanges.ExecutionLease, record systemchanges.CheckpointRecord) error {
	if !lease.Authorized() || !safeName(record.ChangeSet) || record.Checkpoint == "" {
		return errors.New("invalid journal checkpoint")
	}
	root, err := os.OpenRoot(a.root)
	if err != nil {
		return err
	}
	defer root.Close()
	target := path.Join(transactionDirectory, record.ChangeSet)
	if err := verifyTransaction(root, target, a.uid); err != nil {
		return err
	}
	return appendJournal(root, path.Join(target, "journal.jsonl"), journalEntry{Checkpoint: record.Checkpoint, Step: record.Step, Evidence: record.Evidence}, a.uid)
}

func (a Adapter) Execute(lease systemchanges.ExecutionLease, step systemchanges.Step, timeout time.Duration) (systemchanges.StepEvidence, error) {
	if !lease.Authorized() || a.host == nil {
		return systemchanges.StepEvidence{}, errors.New("typed Ubuntu transaction host unavailable")
	}
	return a.host.Execute(step, timeout)
}

func (a Adapter) Check(lease systemchanges.ExecutionLease, check systemchanges.Check, phase systemchanges.GatePhase, timeout time.Duration) (systemchanges.HealthStatus, error) {
	if !lease.Authorized() || a.host == nil {
		return systemchanges.Unknown, errors.New("typed Ubuntu transaction host unavailable")
	}
	return a.host.Check(check, phase, timeout)
}

func (a Adapter) VerifyAgreement(lease systemchanges.ExecutionLease, agreement systemchanges.Agreement) error {
	if !lease.Authorized() || a.host == nil {
		return errors.New("typed Ubuntu transaction host unavailable")
	}
	return a.host.VerifyAgreement(agreement)
}

func (a Adapter) Cleanup(lease systemchanges.ExecutionLease, changeSet string) error {
	if !lease.Authorized() || !safeName(changeSet) {
		return errors.New("invalid transaction identity")
	}
	root, err := os.OpenRoot(a.root)
	if err != nil {
		return err
	}
	defer root.Close()
	target := path.Join(transactionDirectory, changeSet)
	manifest, err := verifyTransactionManifest(root, target, a.uid)
	if err != nil {
		return err
	}
	entries, err := readJournal(root, path.Join(target, "journal.jsonl"))
	if err != nil || len(entries) == 0 || entries[len(entries)-1].Checkpoint != systemchanges.Complete {
		return errors.New("transaction is not durably Complete")
	}
	names := make([]string, 0, len(manifest.Files))
	for name := range manifest.Files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := root.Remove(path.Join(target, name)); err != nil {
			return err
		}
	}
	for _, name := range []string{"manifest.json", "journal.jsonl"} {
		if err := root.Remove(path.Join(target, name)); err != nil {
			return err
		}
	}
	for _, directory := range []string{"snapshot", "prepared", "."} {
		name := target
		if directory != "." {
			name = path.Join(target, directory)
		}
		if err := root.Remove(name); err != nil {
			return err
		}
	}
	return syncDirectory(root, transactionDirectory)
}

func writeProtected(root *os.Root, name string, source io.Reader, uid int) (string, error) {
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	digest := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(file, digest), source)
	syncErr := file.Sync()
	closeErr := file.Close()
	if copyErr != nil {
		return "", copyErr
	}
	if syncErr != nil {
		return "", syncErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	if err := verifyFile(root, name, uid); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func appendJournal(root *os.Root, name string, entry journalEntry, uid int) error {
	if err := verifyFile(root, name, uid); err != nil {
		return err
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	entries, err := readJournal(root, name)
	if err != nil || !validNextCheckpoint(entries, entry) {
		return errors.New("journal checkpoint order is invalid")
	}
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	if _, err = file.Write(append(data, '\n')); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return verifyLastJournalEntry(root, name, entry)
}

func verifyLastJournalEntry(root *os.Root, name string, want journalEntry) error {
	entries, err := readJournal(root, name)
	if err != nil || len(entries) == 0 {
		return errors.New("journal readback unavailable")
	}
	got, _ := json.Marshal(entries[len(entries)-1])
	expected, _ := json.Marshal(want)
	if string(got) != string(expected) {
		return errors.New("journal readback mismatch")
	}
	return nil
}

func readJournal(root *os.Root, name string) ([]journalEntry, error) {
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	var entries []journalEntry
	for scanner.Scan() {
		var current journalEntry
		if err := json.Unmarshal(scanner.Bytes(), &current); err != nil {
			return nil, err
		}
		entries = append(entries, current)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

func validNextCheckpoint(entries []journalEntry, next journalEntry) bool {
	if len(entries) == 0 {
		return next.Checkpoint == systemchanges.Prepared && next.ChangeSet != "" && next.PlanSHA256 != "" && next.State != nil && len(next.Steps) > 0 && len(next.Checks) > 0
	}
	if entries[0].Checkpoint != systemchanges.Prepared || len(entries[0].Steps) == 0 {
		return false
	}
	last, total := entries[len(entries)-1], len(entries[0].Steps)
	switch last.Checkpoint {
	case systemchanges.Prepared:
		return next.Checkpoint == systemchanges.StepStarted && next.Step == 1
	case systemchanges.StepStarted:
		return next.Checkpoint == systemchanges.StepCompleted && next.Step == last.Step && validEvidence(next.Evidence)
	case systemchanges.StepCompleted:
		if last.Step < total {
			return next.Checkpoint == systemchanges.StepStarted && next.Step == last.Step+1
		}
		return next.Checkpoint == systemchanges.PrePublicationHealthPassed && next.Step == 0
	case systemchanges.PrePublicationHealthPassed:
		return next.Checkpoint == systemchanges.StatePublicationStarted && next.Step == 0
	case systemchanges.StatePublicationStarted:
		return next.Checkpoint == systemchanges.StatePublished && next.Step == 0
	case systemchanges.StatePublished:
		return next.Checkpoint == systemchanges.PostPublicationHealthPassed && next.Step == 0
	case systemchanges.PostPublicationHealthPassed:
		return next.Checkpoint == systemchanges.Complete && next.Step == 0
	}
	return false
}

func validEvidence(evidence *systemchanges.StepEvidence) bool {
	if evidence == nil || evidence.Code == "" || len(evidence.Code) > 128 || len(evidence.SHA256) != 64 {
		return false
	}
	for _, character := range evidence.Code {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '-' {
			continue
		}
		return false
	}
	_, err := hex.DecodeString(evidence.SHA256)
	return err == nil
}

func verifyTransaction(root *os.Root, directory string, uid int) error {
	_, err := verifyTransactionManifest(root, directory, uid)
	return err
}

func verifyTransactionManifest(root *os.Root, directory string, uid int) (snapshotManifest, error) {
	for _, name := range []string{directory, path.Join(directory, "snapshot"), path.Join(directory, "prepared")} {
		if err := verifyDirectory(root, name, uid); err != nil {
			return snapshotManifest{}, err
		}
	}
	for _, name := range []string{"manifest.json", "journal.jsonl"} {
		if err := verifyFile(root, path.Join(directory, name), uid); err != nil {
			return snapshotManifest{}, err
		}
	}
	data, err := root.ReadFile(path.Join(directory, "manifest.json"))
	if err != nil {
		return snapshotManifest{}, err
	}
	var manifest snapshotManifest
	if err := json.Unmarshal(data, &manifest); err != nil || manifest.SchemaVersion != 1 || manifest.Release == (systemchanges.ReleaseBinding{}) || manifest.Reason == "" {
		return snapshotManifest{}, errors.New("invalid snapshot manifest")
	}
	want := map[string]bool{"manifest.json": true, "journal.jsonl": true, "snapshot": true, "prepared": true}
	for name, checksum := range manifest.Files {
		if !safeArtifact(name) || len(checksum) != 64 {
			return snapshotManifest{}, errors.New("invalid snapshot artifact binding")
		}
		artifact := path.Join(directory, name)
		if err := verifyFile(root, artifact, uid); err != nil {
			return snapshotManifest{}, err
		}
		content, err := root.ReadFile(artifact)
		if err != nil {
			return snapshotManifest{}, err
		}
		digest := sha256.Sum256(content)
		if hex.EncodeToString(digest[:]) != checksum {
			return snapshotManifest{}, errors.New("snapshot checksum mismatch")
		}
		want[name] = true
	}
	err = fs.WalkDir(root.FS(), directory, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if name == directory {
			return nil
		}
		relative := strings.TrimPrefix(name, directory+"/")
		if !want[relative] {
			return fmt.Errorf("unexpected transaction artifact %s", relative)
		}
		return nil
	})
	return manifest, err
}

func verifyDirectory(root *os.Root, name string, uid int) error {
	info, err := root.Lstat(name)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || !exactMode(info.Mode(), 0o700) || info.Sys().(*syscall.Stat_t).Uid != uint32(uid) {
		return fs.ErrPermission
	}
	return nil
}

func verifyFile(root *os.Root, name string, uid int) error {
	info, err := root.Lstat(name)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || !exactMode(info.Mode(), 0o600) || info.Sys().(*syscall.Stat_t).Uid != uint32(uid) || info.Sys().(*syscall.Stat_t).Nlink != 1 {
		return fs.ErrPermission
	}
	return nil
}

func syncDirectory(root *os.Root, name string) error {
	directory, err := root.Open(name)
	if err != nil {
		return err
	}
	err = directory.Sync()
	closeErr := directory.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func safeArtifact(name string) bool {
	parts := strings.Split(name, "/")
	return len(parts) == 2 && (parts[0] == "snapshot" || parts[0] == "prepared") && safeName(parts[1])
}

func safeName(name string) bool {
	if name == "" || len(name) > 128 {
		return false
	}
	for _, character := range name {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' || character == '.' {
			continue
		}
		return false
	}
	return true
}
