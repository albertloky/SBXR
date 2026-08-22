package softwarelifecycle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"runtime"
	"strings"
	"syscall"
)

const maxUpdateRecord = 4 << 10

type UpdateCandidate struct{ cell *updateCandidateCell }

type updateCandidateCell struct {
	release      LatestRelease
	architecture Architecture
	executable   []byte
	record       []byte
}

type LatestUpdateSource interface {
	LatestReleaseSource
	PrepareLatest(context.Context, Architecture) (UpdateCandidate, LatestReleaseOutcome)
}

func (candidate UpdateCandidate) ExecutableSHA256() (string, bool) {
	if candidate.cell == nil || len(candidate.cell.executable) == 0 {
		return "", false
	}
	digest := sha256.Sum256(candidate.cell.executable)
	return hex.EncodeToString(digest[:]), true
}

func ReleaseArchiveExecutableSHA256(archive []byte) (string, bool) {
	executable, ok := updateArchiveExecutable(archive)
	if !ok {
		return "", false
	}
	digest := sha256.Sum256(executable)
	return hex.EncodeToString(digest[:]), true
}

func VerifyLatestUpdateArchive(release LatestRelease, architecture Architecture, archive []byte) (UpdateCandidate, bool) {
	executable, ok := updateArchiveExecutable(archive)
	if !ok {
		return UpdateCandidate{}, false
	}
	if !VerifyLinuxExecutable(executable, architecture) {
		return UpdateCandidate{}, false
	}
	return newUpdateCandidate(release, architecture, executable)
}

func newUpdateCandidate(release LatestRelease, architecture Architecture, executable []byte) (UpdateCandidate, bool) {
	embedded, ok := readEmbeddedIdentity(executable)
	if !ok || !validLatestRelease(release) || embedded.Repository != release.Identity.Repository || embedded.Tag != release.Identity.Tag || embedded.Commit != release.Identity.Commit || embedded.Sequence != release.Sequence || embedded.Architecture != architecture {
		return UpdateCandidate{}, false
	}
	digest := sha256.Sum256(executable)
	record, err := json.Marshal(installedRecord{Schema: 1, Repository: release.Identity.Repository, Tag: release.Identity.Tag, Commit: release.Identity.Commit, ReleaseIndexSHA256: release.Identity.IndexSHA256, Sequence: release.Sequence, Architecture: architecture, ExecutableSHA256: hex.EncodeToString(digest[:])})
	if err != nil {
		return UpdateCandidate{}, false
	}
	record = append(record, '\n')
	if verified, valid := verifyInstalledRelease(record, executable); !valid || verified.identity != release.Identity || verified.sequence != release.Sequence {
		return UpdateCandidate{}, false
	}
	return UpdateCandidate{cell: &updateCandidateCell{release: release, architecture: architecture, executable: append([]byte(nil), executable...), record: record}}, true
}

func updateArchiveExecutable(body []byte) ([]byte, bool) {
	if len(body) == 0 || len(body) > MaxAssetBytes {
		return nil, false
	}
	input := bytes.NewReader(body)
	compressed, err := gzip.NewReader(input)
	if err != nil {
		return nil, false
	}
	compressed.Multistream(false)
	archive := tar.NewReader(io.LimitReader(compressed, MaxAssetBytes+1))
	header, err := archive.Next()
	if err != nil || header.Name != "sbxr" || header.Typeflag != tar.TypeReg || header.Linkname != "" || header.Mode != 0o755 || header.Uid != 0 || header.Gid != 0 || (header.Uname != "" && header.Uname != "root") || (header.Gname != "" && header.Gname != "root") || header.Size <= 0 || header.Size > maxInstalledBinary {
		_ = compressed.Close()
		return nil, false
	}
	executable, err := io.ReadAll(io.LimitReader(archive, maxInstalledBinary+1))
	_, extra := archive.Next()
	remaining, drainErr := io.Copy(io.Discard, compressed)
	closeErr := compressed.Close()
	return executable, err == nil && int64(len(executable)) == header.Size && errors.Is(extra, io.EOF) && remaining == 0 && drainErr == nil && closeErr == nil && input.Len() == 0 && int64(len(executable)) <= maxInstalledBinary
}

func VerifyLinuxExecutable(executable []byte, architecture Architecture) bool {
	file, err := elf.NewFile(bytes.NewReader(executable))
	if err != nil {
		return false
	}
	defer file.Close()
	if file.Class != elf.ELFCLASS64 || file.Section(".gopclntab") == nil {
		return false
	}
	for _, program := range file.Progs {
		if program.Type == elf.PT_INTERP {
			return false
		}
	}
	if libraries, err := file.ImportedLibraries(); err != nil || len(libraries) != 0 {
		return false
	}
	info, err := buildinfo.Read(bytes.NewReader(executable))
	if err != nil || info.GoVersion != "go1.26.6" {
		return false
	}
	settings := map[string]string{}
	for _, setting := range info.Settings {
		if _, duplicate := settings[setting.Key]; duplicate {
			return false
		}
		settings[setting.Key] = setting.Value
	}
	if settings["GOOS"] != "linux" || settings["GOARCH"] != string(architecture) || settings["CGO_ENABLED"] != "0" {
		return false
	}
	switch file.Machine {
	case elf.EM_X86_64:
		return architecture == AMD64
	case elf.EM_AARCH64:
		return architecture == ARM64
	default:
		return false
	}
}

type updateCheckpoint string

const (
	preparedCheckpoint  updateCheckpoint = "Prepared"
	committedCheckpoint updateCheckpoint = "Committed"
)

type updateRecord struct {
	Schema                         int              `json:"schema"`
	Checkpoint                     updateCheckpoint `json:"checkpoint"`
	PriorExecutableSHA256          string           `json:"prior_executable_sha256"`
	PriorInstalledRecordSHA256     string           `json:"prior_installed_record_sha256"`
	CandidateExecutableSHA256      string           `json:"candidate_executable_sha256"`
	CandidateInstalledRecordSHA256 string           `json:"candidate_installed_record_sha256"`
}

const (
	UpdateInstalled           ResultCode = "SOFTWARE-LIFECYCLE-UPDATE-INSTALLED"
	UpdateAlreadyCurrent      ResultCode = "SOFTWARE-LIFECYCLE-UPDATE-ALREADY-CURRENT"
	UpdateReleaseRefused      ResultCode = "SOFTWARE-LIFECYCLE-UPDATE-RELEASE-REFUSED"
	UpdateReleaseUnavailable  ResultCode = "SOFTWARE-LIFECYCLE-UPDATE-RELEASE-UNAVAILABLE"
	UpdateConcurrentMutation  ResultCode = "SOFTWARE-LIFECYCLE-UPDATE-CONCURRENT-MUTATION"
	UpdateInterrupted         ResultCode = "SOFTWARE-LIFECYCLE-UPDATE-INTERRUPTED"
	UpdateFailed              ResultCode = "SOFTWARE-LIFECYCLE-UPDATE-FAILED"
	UpdatePriorRestored       ResultCode = "SOFTWARE-LIFECYCLE-UPDATE-PRIOR-RESTORED"
	UpdateRecoveryRequired    ResultCode = "SOFTWARE-LIFECYCLE-UPDATE-RECOVERY-REQUIRED"
	UpdateNotReady            ResultCode = "SOFTWARE-LIFECYCLE-UPDATE-NOT-READY"
	RecoverPriorRestored      ResultCode = "SOFTWARE-LIFECYCLE-RECOVER-PRIOR-RESTORED"
	RecoverCandidateRetained  ResultCode = "SOFTWARE-LIFECYCLE-RECOVER-CANDIDATE-RETAINED"
	RecoverRefused            ResultCode = "SOFTWARE-LIFECYCLE-RECOVER-REFUSED"
	RecoverFailed             ResultCode = "SOFTWARE-LIFECYCLE-RECOVER-FAILED"
	RecoverConcurrentMutation ResultCode = "SOFTWARE-LIFECYCLE-RECOVER-CONCURRENT-MUTATION"
	RecoverNotRequired        ResultCode = "SOFTWARE-LIFECYCLE-RECOVER-NOT-REQUIRED"
)

func (inspector filesystemInspector) recover(ctx context.Context, progress ProgressReporter) Result {
	root, err := os.OpenRoot(inspector.root)
	if err != nil {
		return updateResult(RecoveryRequiredState, nil, RecoverRefused, "SBXR recovery was refused because safe recovery could not be proven.")
	}
	defer root.Close()
	lock, concurrent, lockErr := acquireUpdateLock(root, inspector.uid)
	if lockErr != nil {
		if lock != nil {
			_ = lock.Close()
		}
		if concurrent {
			return updateResult(UpdateInProgress, nil, RecoverConcurrentMutation, "Another Software Lifecycle change is in progress.")
		}
		return updateResult(RecoveryRequiredState, nil, RecoverRefused, "SBXR recovery was refused because safe recovery could not be proven.")
	}
	defer func() { _ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN); _ = lock.Close() }()
	if mounted, err := inspector.recoveryPathMounted(); err != nil || mounted || !inspector.safeDirectory("/var/lib/sbxr", 0o700) {
		return updateResult(RecoveryRequiredState, nil, RecoverRefused, "SBXR recovery was refused because safe recovery could not be proven.")
	}

	record, err := readUpdateRecord(root)
	if err != nil {
		status := statusFromInspection(inspector.inspectReadyUnderLock())
		if status.State == Ready {
			status.Code = RecoverNotRequired
			status.Message = "SBXR does not need recovery."
			return status
		}
		return updateResult(RecoveryRequiredState, nil, RecoverRefused, "SBXR recovery was refused because safe recovery could not be proven.")
	}
	if ctx.Err() != nil {
		return updateResult(RecoveryRequiredState, nil, RecoverRefused, "SBXR recovery was refused because safe recovery could not be proven.")
	}
	if progress != nil {
		progress(Progress{Operation: RecoverOperation, Status: InspectingRecoveryEvidence, Mode: Spinner})
	}
	switch record.Checkpoint {
	case preparedCheckpoint:
		priorActive, err := provePreparedRecovery(root, record)
		if err != nil {
			return updateResult(RecoveryRequiredState, nil, RecoverRefused, "SBXR recovery was refused because safe recovery could not be proven.")
		}
		if inspector.beforeRecoveryMutation != nil {
			inspector.beforeRecoveryMutation()
		}
		if err := func() error {
			if priorActive {
				return finishPreparedCleanup(root, record)
			}
			return rollbackUpdate(root, record)
		}(); err != nil {
			return updateResult(RecoveryRequiredState, nil, RecoverFailed, "SBXR recovery could not reach a verified terminal state.")
		}
		status := statusFromInspection(inspector.inspectReadyUnderLock())
		if status.State != Ready {
			return updateResult(RecoveryRequiredState, nil, RecoverFailed, "SBXR recovery could not reach a verified terminal state.")
		}
		status.Code = RecoverPriorRestored
		status.Message = "The prior SBXR release was restored."
		return status
	case committedCheckpoint:
		if err := proveCommittedRecovery(root, record); err != nil {
			return updateResult(RecoveryRequiredState, nil, RecoverRefused, "SBXR recovery was refused because safe recovery could not be proven.")
		}
		if inspector.beforeRecoveryMutation != nil {
			inspector.beforeRecoveryMutation()
		}
		if err := cleanupCommitted(root, record); err != nil {
			return updateResult(RecoveryRequiredState, nil, RecoverFailed, "SBXR recovery could not reach a verified terminal state.")
		}
		status := statusFromInspection(inspector.inspectReadyUnderLock())
		if status.State != Ready {
			return updateResult(RecoveryRequiredState, nil, RecoverFailed, "SBXR recovery could not reach a verified terminal state.")
		}
		status.Code = RecoverCandidateRetained
		status.Message = "The committed SBXR release was retained."
		return status
	default:
		return updateResult(RecoveryRequiredState, nil, RecoverRefused, "SBXR recovery was refused because safe recovery could not be proven.")
	}
}

func (inspector filesystemInspector) recoveryPathMounted() (bool, error) {
	if runtime.GOOS != "linux" {
		return false, nil
	}
	body, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return false, err
	}
	wanted := map[string]bool{
		inspector.path(executablePath):      true,
		inspector.path(installedRecordPath): true,
		inspector.path(mutationLockPath):    true,
	}
	for _, name := range transactionPaths {
		wanted[inspector.path(name)] = true
	}
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 4 && wanted[decodeMountPath(fields[4])] {
			return true, nil
		}
	}
	return false, nil
}

func decodeMountPath(value string) string {
	return strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`).Replace(value)
}

func proveCommittedRecovery(root *os.Root, record updateRecord) error {
	if current, err := readUpdateRecord(root); err != nil || current != record {
		return errors.New("update record changed")
	}
	activeRecord, err := readBoundFile(root, "var/lib/sbxr/installed.json", 0o600, 1, maxInstalledRecord, record.CandidateInstalledRecordSHA256)
	if err != nil {
		return err
	}
	activeExecutable, err := readBoundFile(root, "usr/local/bin/sbxr", 0o755, 1, maxInstalledBinary, record.CandidateExecutableSHA256)
	if err != nil || !activePairBytes(activeRecord, activeExecutable) {
		return errors.New("committed candidate refused")
	}
	for _, material := range []struct {
		name   string
		mode   os.FileMode
		limit  int64
		digest string
	}{
		{"usr/local/bin/.sbxr-update-prior", 0o755, maxInstalledBinary, record.PriorExecutableSHA256},
		{"var/lib/sbxr/.installed.json.prior", 0o600, maxInstalledRecord, record.PriorInstalledRecordSHA256},
	} {
		if _, _, err := readOptionalOneOfBoundFile(root, material.name, material.mode, 1, material.limit, material.digest); err != nil {
			return err
		}
	}
	for _, name := range []string{"usr/local/bin/.sbxr-update-candidate", "var/lib/sbxr/.installed.json.candidate"} {
		if _, err := root.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			return errors.New("unexpected transaction material remains")
		}
	}
	_, _, err = readOptionalOneOfBoundFile(root, "var/lib/sbxr/.update.json.next", 0o600, 1, maxUpdateRecord, digestBytes(updateRecordBytes(bindCheckpoint(record, preparedCheckpoint))), digestBytes(updateRecordBytes(bindCheckpoint(record, committedCheckpoint))))
	return err
}

func provePreparedRecovery(root *os.Root, record updateRecord) (bool, error) {
	if current, err := readUpdateRecord(root); err != nil || current != record {
		return false, errors.New("update record changed")
	}
	activeRecord, err := readOneOfBoundFile(root, "var/lib/sbxr/installed.json", 0o600, 1, maxInstalledRecord, record.PriorInstalledRecordSHA256, record.CandidateInstalledRecordSHA256)
	if err != nil {
		return false, err
	}
	activeExecutable, err := readActiveRecoveryExecutable(root, record)
	if err != nil {
		return false, err
	}
	priorActive := digestBytes(activeRecord) == record.PriorInstalledRecordSHA256 && digestBytes(activeExecutable) == record.PriorExecutableSHA256 && activePairBytes(activeRecord, activeExecutable)
	priorExecutable, executablePriorPresent, err := readOptionalPriorExecutable(root, record.PriorExecutableSHA256)
	if err != nil || !executablePriorPresent && !priorActive {
		return false, errors.New("prior recovery authority unavailable")
	}
	priorRecord, recordPriorPresent, err := readOptionalOneOfBoundFile(root, "var/lib/sbxr/.installed.json.prior", 0o600, 1, maxInstalledRecord, record.PriorInstalledRecordSHA256)
	if err != nil || !recordPriorPresent && !priorActive {
		return false, errors.New("prior recovery authority unavailable")
	}
	if !executablePriorPresent {
		priorExecutable = activeExecutable
	}
	if !recordPriorPresent {
		priorRecord = activeRecord
	}
	if !activePairBytes(priorRecord, priorExecutable) {
		return false, errors.New("prior recovery authority unavailable")
	}
	candidateRecord, recordPresent, err := readOptionalOneOfBoundFile(root, "var/lib/sbxr/.installed.json.candidate", 0o600, 1, maxInstalledRecord, record.PriorInstalledRecordSHA256, record.CandidateInstalledRecordSHA256)
	if err != nil {
		return false, err
	}
	candidateExecutable, executablePresent, err := readOptionalOneOfBoundFile(root, "usr/local/bin/.sbxr-update-candidate", 0o755, 1, maxInstalledBinary, record.PriorExecutableSHA256, record.CandidateExecutableSHA256)
	if err != nil {
		return false, err
	}
	if _, _, err := readOptionalOneOfBoundFile(root, "var/lib/sbxr/.update.json.next", 0o600, 1, maxUpdateRecord, digestBytes(updateRecordBytes(bindCheckpoint(record, preparedCheckpoint))), digestBytes(updateRecordBytes(bindCheckpoint(record, committedCheckpoint)))); err != nil {
		return false, errors.New("update publication residue refused")
	}
	if digestBytes(activeRecord) == record.CandidateInstalledRecordSHA256 {
		candidateRecord, recordPresent = activeRecord, true
	}
	if digestBytes(activeExecutable) == record.CandidateExecutableSHA256 {
		candidateExecutable, executablePresent = activeExecutable, true
	}
	if recordPresent && executablePresent && !activePairBytes(candidateRecord, candidateExecutable) {
		return false, errors.New("candidate recovery evidence contradicted")
	}
	return priorActive, nil
}

func finishPreparedCleanup(root *os.Root, record updateRecord) error {
	if err := removePriorExecutableIfPresent(root, record.PriorExecutableSHA256); err != nil {
		return err
	}
	if err := removeOneOfIfPresent(root, "usr/local/bin/.sbxr-update-candidate", 0o755, 1, maxInstalledBinary, record.PriorExecutableSHA256, record.CandidateExecutableSHA256); err != nil {
		return err
	}
	if err := removeOneOfIfPresent(root, "var/lib/sbxr/.installed.json.candidate", 0o600, 1, maxInstalledRecord, record.PriorInstalledRecordSHA256, record.CandidateInstalledRecordSHA256); err != nil {
		return err
	}
	return cleanupPrepared(root, record)
}

func removePriorExecutableIfPresent(root *os.Root, digest string) error {
	if _, err := root.Lstat("usr/local/bin/.sbxr-update-prior"); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if _, err := readPriorExecutable(root, digest); err != nil {
		return err
	}
	return root.Remove("usr/local/bin/.sbxr-update-prior")
}

func readOptionalPriorExecutable(root *os.Root, digest string) ([]byte, bool, error) {
	if _, err := root.Lstat("usr/local/bin/.sbxr-update-prior"); errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	} else if err != nil {
		return nil, false, err
	}
	body, err := readPriorExecutable(root, digest)
	return body, true, err
}

func readActiveRecoveryExecutable(root *os.Root, record updateRecord) ([]byte, error) {
	body, err := readOneOfBoundFile(root, "usr/local/bin/sbxr", 0o755, 1, maxInstalledBinary, record.PriorExecutableSHA256, record.CandidateExecutableSHA256)
	if err == nil {
		return body, nil
	}
	body, err = readOneOfBoundFile(root, "usr/local/bin/sbxr", 0o755, 2, maxInstalledBinary, record.PriorExecutableSHA256)
	if err != nil {
		return nil, err
	}
	if _, err := readPriorExecutable(root, record.PriorExecutableSHA256); err != nil {
		return nil, err
	}
	return body, nil
}

func readOptionalOneOfBoundFile(root *os.Root, name string, mode os.FileMode, links uint64, limit int64, digests ...string) ([]byte, bool, error) {
	if _, err := root.Lstat(name); errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	} else if err != nil {
		return nil, false, err
	}
	body, err := readOneOfBoundFile(root, name, mode, links, limit, digests...)
	return body, true, err
}

func readOneOfBoundFile(root *os.Root, name string, mode os.FileMode, links uint64, limit int64, digests ...string) ([]byte, error) {
	body, err := readRootFile(root, name, mode, links, limit)
	if err != nil {
		return nil, err
	}
	got := digestBytes(body)
	for _, digest := range digests {
		if got == digest {
			return body, nil
		}
	}
	return nil, errors.New("bound update material changed")
}

func (inspector filesystemInspector) update(ctx context.Context, latest LatestReleaseSource, progress ProgressReporter) Result {
	root, err := os.OpenRoot(inspector.root)
	if err != nil {
		return updateResult(RecoveryRequiredState, nil, UpdateRecoveryRequired, "SBXR needs recovery before normal operations can continue.")
	}
	defer root.Close()
	lock, concurrent, lockErr := acquireUpdateLock(root, inspector.uid)
	if lockErr != nil {
		if lock != nil {
			_ = lock.Close()
		}
		if concurrent {
			return updateResult(UpdateInProgress, nil, UpdateConcurrentMutation, "Another Software Lifecycle change is in progress.")
		}
		return updateResult(RecoveryRequiredState, nil, UpdateRecoveryRequired, "SBXR needs recovery before normal operations can continue.")
	}
	defer func() { _ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN); _ = lock.Close() }()

	priorInspection := inspector.inspectReadyUnderLock()
	priorStatus := statusFromInspection(priorInspection)
	prior, valid := verifyInstalledRelease(priorInspection.installedRecord, priorInspection.executable)
	if priorStatus.State != Ready || !valid {
		return updateResult(RecoveryRequiredState, nil, UpdateNotReady, "SBXR is not ready to update.")
	}
	if ctx.Err() != nil {
		return updateResult(Ready, &prior.identity, UpdateInterrupted, "The update was interrupted before installation.")
	}
	source, ok := latest.(LatestUpdateSource)
	if !ok {
		return updateResult(Ready, &prior.identity, UpdateReleaseRefused, "The latest SBXR release was refused.")
	}
	if progress != nil {
		progress(Progress{Operation: UpdateOperation, Status: CheckingQualifiedLatest, Mode: Spinner})
	}
	candidate, outcome := source.PrepareLatest(ctx, installedArchitecture(priorInspection.installedRecord))
	if ctx.Err() != nil {
		return updateResult(Ready, &prior.identity, UpdateInterrupted, "The update was interrupted before installation.")
	}
	if outcome == LatestReleaseUnavailable {
		return updateResult(Ready, &prior.identity, UpdateReleaseUnavailable, "The latest SBXR release is unavailable. Check again later.")
	}
	if outcome != LatestReleaseAccepted || candidate.cell == nil || candidate.cell.release.Identity == prior.identity && candidate.cell.release.Sequence != prior.sequence || candidate.cell.release.Identity != prior.identity && candidate.cell.release.Sequence <= prior.sequence {
		return updateResult(Ready, &prior.identity, UpdateReleaseRefused, "The latest SBXR release was refused.")
	}
	if candidate.cell.release.Identity == prior.identity && candidate.cell.release.Sequence == prior.sequence {
		return updateResult(Ready, &prior.identity, UpdateAlreadyCurrent, "SBXR is already current.")
	}
	record := bindUpdateRecord(priorInspection, candidate)
	if err := prepareUpdate(root, priorInspection, candidate); err != nil {
		if cleanupPrePrepared(root, record) != nil {
			return updateResult(RecoveryRequiredState, nil, UpdateRecoveryRequired, "The update needs recovery before normal operations can continue.")
		}
		return updateResult(Ready, &prior.identity, UpdateFailed, "The update failed before installation. The prior release is unchanged.")
	}
	if ctx.Err() != nil {
		if cleanupPrePrepared(root, record) != nil {
			return updateResult(RecoveryRequiredState, nil, UpdateRecoveryRequired, "The update needs recovery before normal operations can continue.")
		}
		return updateResult(Ready, &prior.identity, UpdateInterrupted, "The update was interrupted before installation.")
	}
	if err := publishUpdateRecord(root, record, ""); err != nil {
		if current, readErr := readUpdateRecord(root); readErr == nil && current == record {
			if rollbackUpdate(root, record) == nil {
				return updateResult(Ready, &prior.identity, UpdatePriorRestored, "The update failed. The prior release was restored.")
			}
			return updateResult(RecoveryRequiredState, nil, UpdateRecoveryRequired, "The update needs recovery before normal operations can continue.")
		}
		if cleanupPrePrepared(root, record) != nil {
			return updateResult(RecoveryRequiredState, nil, UpdateRecoveryRequired, "The update needs recovery before normal operations can continue.")
		}
		return updateResult(Ready, &prior.identity, UpdateFailed, "The update failed before installation. The prior release is unchanged.")
	}
	if progress != nil {
		progress(Progress{Operation: UpdateOperation, Status: "Activating the verified release", Mode: Spinner})
	}
	if err := activateCandidate(root, candidate); err != nil || !activePairMatches(root, candidate.cell.record, candidate.cell.executable) {
		if rollbackUpdate(root, record) == nil {
			return updateResult(Ready, &prior.identity, UpdatePriorRestored, "The update failed. The prior release was restored.")
		}
		return updateResult(RecoveryRequiredState, nil, UpdateRecoveryRequired, "The update needs recovery before normal operations can continue.")
	}
	record.Checkpoint = committedCheckpoint
	if err := publishUpdateRecord(root, record, preparedCheckpoint); err != nil {
		if current, readErr := readUpdateRecord(root); readErr == nil && current == record {
			return updateResult(RecoveryRequiredState, &candidate.cell.release.Identity, UpdateRecoveryRequired, "The update needs recovery before normal operations can continue.")
		}
		if rollbackUpdate(root, bindCheckpoint(record, preparedCheckpoint)) == nil {
			return updateResult(Ready, &prior.identity, UpdatePriorRestored, "The update failed. The prior release was restored.")
		}
		return updateResult(RecoveryRequiredState, nil, UpdateRecoveryRequired, "The update needs recovery before normal operations can continue.")
	}
	if err := cleanupCommitted(root, record); err != nil {
		return updateResult(RecoveryRequiredState, &candidate.cell.release.Identity, UpdateRecoveryRequired, "The update needs recovery before normal operations can continue.")
	}
	return Result{State: Ready, Installed: &candidate.cell.release.Identity, UpdateInstalled: true, Code: UpdateInstalled, Message: "SBXR was updated."}
}

func installedArchitecture(record []byte) Architecture {
	var value installedRecord
	if !decodeExactObject(record, &value) {
		return ""
	}
	return value.Architecture
}

func (inspector filesystemInspector) inspectReadyUnderLock() localInspection {
	if evidence, valid := inspector.hasTransactionEvidence(); !valid || evidence || !inspector.safeDirectory("/var/lib/sbxr", 0o700) {
		return localInspection{inspectionValid: valid, transactionEvidence: evidence}
	}
	executable, executableOK := inspector.readSafeFile(executablePath, 0o755, 1, maxInstalledBinary)
	record, recordOK := inspector.readSafeFile(installedRecordPath, 0o600, 1, maxInstalledRecord)
	return localInspection{inspectionValid: executableOK && recordOK, installedRecord: record, executable: executable}
}

func acquireUpdateLock(root *os.Root, uid uint32) (*os.File, bool, error) {
	lock, err := root.OpenFile("run/lock/sbxr.lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, false, err
	}
	info, err := lock.Stat()
	if err != nil || !safeLockInfo(info, uid) {
		return lock, false, errors.New("unsafe mutation lock")
	}
	err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	return lock, errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN), err
}

func prepareUpdate(root *os.Root, prior localInspection, candidate UpdateCandidate) error {
	if candidate.cell == nil || !activePairBytes(prior.installedRecord, prior.executable) {
		return errors.New("update material refused")
	}
	if err := writeUpdateFile(root, "usr/local/bin/.sbxr-update-candidate", candidate.cell.executable, 0o755); err != nil {
		return err
	}
	if err := writeUpdateFile(root, "var/lib/sbxr/.installed.json.candidate", candidate.cell.record, 0o600); err != nil {
		return err
	}
	if err := root.Link("usr/local/bin/sbxr", "usr/local/bin/.sbxr-update-prior"); err != nil {
		return err
	}
	if err := writeUpdateFile(root, "var/lib/sbxr/.installed.json.prior", prior.installedRecord, 0o600); err != nil {
		return err
	}
	if !fileMatches(root, "usr/local/bin/.sbxr-update-prior", prior.executable, 0o755, 2) || !fileMatches(root, "var/lib/sbxr/.installed.json.prior", prior.installedRecord, 0o600, 1) || !fileMatches(root, "usr/local/bin/.sbxr-update-candidate", candidate.cell.executable, 0o755, 1) || !fileMatches(root, "var/lib/sbxr/.installed.json.candidate", candidate.cell.record, 0o600, 1) {
		return errors.New("staged update changed")
	}
	return syncUpdateDirectories(root)
}

func bindUpdateRecord(prior localInspection, candidate UpdateCandidate) updateRecord {
	return updateRecord{Schema: 1, Checkpoint: preparedCheckpoint, PriorExecutableSHA256: digestBytes(prior.executable), PriorInstalledRecordSHA256: digestBytes(prior.installedRecord), CandidateExecutableSHA256: digestBytes(candidate.cell.executable), CandidateInstalledRecordSHA256: digestBytes(candidate.cell.record)}
}

func bindCheckpoint(record updateRecord, checkpoint updateCheckpoint) updateRecord {
	record.Checkpoint = checkpoint
	return record
}

func publishUpdateRecord(root *os.Root, record updateRecord, expected updateCheckpoint) error {
	if record.Schema != 1 || record.Checkpoint != preparedCheckpoint && record.Checkpoint != committedCheckpoint || !validUpdateDigests(record) {
		return errors.New("update record refused")
	}
	if expected == "" {
		if _, err := root.Lstat("var/lib/sbxr/update.json"); !errors.Is(err, os.ErrNotExist) {
			return errors.New("update record already exists")
		}
	} else {
		current, err := readUpdateRecord(root)
		if err != nil || current.Checkpoint != expected || bindCheckpoint(current, record.Checkpoint) != record {
			return errors.New("update checkpoint changed")
		}
	}
	body := updateRecordBytes(record)
	if err := writeUpdateFile(root, "var/lib/sbxr/.update.json.next", body, 0o600); err != nil {
		return err
	}
	if err := root.Rename("var/lib/sbxr/.update.json.next", "var/lib/sbxr/update.json"); err != nil {
		return err
	}
	return syncUpdateDirectory(root, "var/lib/sbxr")
}

func readUpdateRecord(root *os.Root) (updateRecord, error) {
	body, err := readRootFile(root, "var/lib/sbxr/update.json", 0o600, 1, maxUpdateRecord)
	if err != nil {
		return updateRecord{}, err
	}
	var record updateRecord
	if !decodeExactObject(body, &record) || record.Schema != 1 || record.Checkpoint != preparedCheckpoint && record.Checkpoint != committedCheckpoint || !validUpdateDigests(record) {
		return updateRecord{}, errors.New("update record refused")
	}
	return record, nil
}

func validUpdateDigests(record updateRecord) bool {
	return hashPattern.MatchString(record.PriorExecutableSHA256) && hashPattern.MatchString(record.PriorInstalledRecordSHA256) && hashPattern.MatchString(record.CandidateExecutableSHA256) && hashPattern.MatchString(record.CandidateInstalledRecordSHA256)
}

func activateCandidate(root *os.Root, candidate UpdateCandidate) error {
	if err := root.Rename("var/lib/sbxr/.installed.json.candidate", "var/lib/sbxr/installed.json"); err != nil || syncUpdateDirectory(root, "var/lib/sbxr") != nil {
		return errors.New("candidate record activation failed")
	}
	if err := root.Rename("usr/local/bin/.sbxr-update-candidate", "usr/local/bin/sbxr"); err != nil || syncUpdateDirectory(root, "usr/local/bin") != nil {
		return errors.New("candidate executable activation failed")
	}
	return nil
}

func rollbackUpdate(root *os.Root, record updateRecord) error {
	priorExecutable, err := readPriorExecutable(root, record.PriorExecutableSHA256)
	if err != nil {
		return err
	}
	priorRecord, err := readBoundFile(root, "var/lib/sbxr/.installed.json.prior", 0o600, 1, maxInstalledRecord, record.PriorInstalledRecordSHA256)
	if err != nil || !activePairBytes(priorRecord, priorExecutable) {
		return errors.New("prior release authority unavailable")
	}
	_ = root.Remove("var/lib/sbxr/.installed.json.candidate")
	_ = root.Remove("usr/local/bin/.sbxr-update-candidate")
	if err := writeUpdateFile(root, "var/lib/sbxr/.installed.json.candidate", priorRecord, 0o600); err != nil || root.Rename("var/lib/sbxr/.installed.json.candidate", "var/lib/sbxr/installed.json") != nil || syncUpdateDirectory(root, "var/lib/sbxr") != nil {
		return errors.New("prior record restoration failed")
	}
	if err := writeUpdateFile(root, "usr/local/bin/.sbxr-update-candidate", priorExecutable, 0o755); err != nil || root.Rename("usr/local/bin/.sbxr-update-candidate", "usr/local/bin/sbxr") != nil || syncUpdateDirectory(root, "usr/local/bin") != nil {
		return errors.New("prior executable restoration failed")
	}
	if !activePairMatches(root, priorRecord, priorExecutable) {
		return errors.New("restored prior release refused")
	}
	return cleanupPrepared(root, record)
}

func cleanupPrePrepared(root *os.Root, record updateRecord) error {
	for _, material := range []struct {
		name   string
		mode   os.FileMode
		links  uint64
		limit  int64
		digest string
	}{
		{"usr/local/bin/.sbxr-update-candidate", 0o755, 1, maxInstalledBinary, record.CandidateExecutableSHA256},
		{"var/lib/sbxr/.installed.json.candidate", 0o600, 1, maxInstalledRecord, record.CandidateInstalledRecordSHA256},
		{"var/lib/sbxr/.installed.json.prior", 0o600, 1, maxInstalledRecord, record.PriorInstalledRecordSHA256},
		{"usr/local/bin/.sbxr-update-prior", 0o755, 2, maxInstalledBinary, record.PriorExecutableSHA256},
	} {
		if err := removeBoundIfPresent(root, material.name, material.mode, material.links, material.limit, material.digest); err != nil {
			return err
		}
	}
	if err := removeOneOfIfPresent(root, "var/lib/sbxr/.update.json.next", 0o600, 1, maxUpdateRecord, digestBytes(updateRecordBytes(record))); err != nil {
		return err
	}
	return syncUpdateDirectories(root)
}

func cleanupPrepared(root *os.Root, record updateRecord) error {
	for _, material := range []struct {
		name   string
		mode   os.FileMode
		limit  int64
		digest string
	}{
		{"usr/local/bin/.sbxr-update-prior", 0o755, maxInstalledBinary, record.PriorExecutableSHA256},
		{"var/lib/sbxr/.installed.json.prior", 0o600, maxInstalledRecord, record.PriorInstalledRecordSHA256},
	} {
		if err := removeBoundIfPresent(root, material.name, material.mode, 1, material.limit, material.digest); err != nil {
			return err
		}
	}
	for _, name := range []string{"usr/local/bin/.sbxr-update-candidate", "var/lib/sbxr/.installed.json.candidate"} {
		if _, err := root.Lstat(name); err == nil || !errors.Is(err, os.ErrNotExist) {
			return errors.New("unexpected transaction material remains")
		}
	}
	prepared := bindCheckpoint(record, preparedCheckpoint)
	committed := bindCheckpoint(record, committedCheckpoint)
	if err := removeOneOfIfPresent(root, "var/lib/sbxr/.update.json.next", 0o600, 1, maxUpdateRecord, digestBytes(updateRecordBytes(prepared)), digestBytes(updateRecordBytes(committed))); err != nil {
		return err
	}
	if err := syncUpdateDirectories(root); err != nil {
		return err
	}
	if err := root.Remove("var/lib/sbxr/update.json"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncUpdateDirectory(root, "var/lib/sbxr")
}

func cleanupCommitted(root *os.Root, record updateRecord) error {
	activeRecord, err := readBoundFile(root, "var/lib/sbxr/installed.json", 0o600, 1, maxInstalledRecord, record.CandidateInstalledRecordSHA256)
	if err != nil {
		return err
	}
	activeExecutable, err := readBoundFile(root, "usr/local/bin/sbxr", 0o755, 1, maxInstalledBinary, record.CandidateExecutableSHA256)
	if err != nil || !activePairBytes(activeRecord, activeExecutable) {
		return errors.New("committed candidate refused")
	}
	return cleanupPrepared(root, record)
}

func writeUpdateFile(root *os.Root, name string, body []byte, mode os.FileMode) error {
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return err
	}
	written, writeErr := file.Write(body)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || written != len(body) || syncErr != nil || closeErr != nil {
		_ = root.Remove(name)
		return errors.New("durable update write failed")
	}
	return nil
}

func removeBoundIfPresent(root *os.Root, name string, mode os.FileMode, links uint64, limit int64, digest string) error {
	return removeOneOfIfPresent(root, name, mode, links, limit, digest)
}

func removeOneOfIfPresent(root *os.Root, name string, mode os.FileMode, links uint64, limit int64, digests ...string) error {
	if _, err := root.Lstat(name); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	body, err := readRootFile(root, name, mode, links, limit)
	if err != nil {
		return err
	}
	matched := false
	for _, digest := range digests {
		matched = matched || digestBytes(body) == digest
	}
	if !matched {
		return errors.New("bound update material changed")
	}
	return root.Remove(name)
}

func updateRecordBytes(record updateRecord) []byte {
	body, _ := json.Marshal(record)
	return append(body, '\n')
}

func fileMatches(root *os.Root, name string, body []byte, mode os.FileMode, links uint64) bool {
	got, err := readRootFile(root, name, mode, links, int64(len(body)))
	return err == nil && bytes.Equal(got, body)
}

func readBoundFile(root *os.Root, name string, mode os.FileMode, links uint64, limit int64, digest string) ([]byte, error) {
	body, err := readRootFile(root, name, mode, links, limit)
	if err != nil || digestBytes(body) != digest {
		return nil, errors.New("bound update material changed")
	}
	return body, nil
}

func readPriorExecutable(root *os.Root, digest string) ([]byte, error) {
	const prior = "usr/local/bin/.sbxr-update-prior"
	if body, err := readBoundFile(root, prior, 0o755, 1, maxInstalledBinary, digest); err == nil {
		return body, nil
	}
	body, err := readBoundFile(root, prior, 0o755, 2, maxInstalledBinary, digest)
	if err != nil {
		return nil, err
	}
	priorInfo, err := root.Lstat(prior)
	if err != nil {
		return nil, err
	}
	active, err := root.OpenFile("usr/local/bin/sbxr", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer active.Close()
	if !sameFile(priorInfo, active) {
		return nil, errors.New("unexplained prior executable link")
	}
	return body, nil
}

func readRootFile(root *os.Root, name string, mode os.FileMode, links uint64, limit int64) ([]byte, error) {
	info, err := root.Lstat(name)
	if err != nil || !safeFileInfo(info, uint32(os.Getuid()), mode, links, limit) {
		return nil, errors.New("unsafe update material")
	}
	file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if !sameFile(info, file) {
		return nil, errors.New("update material changed")
	}
	body, err := io.ReadAll(io.LimitReader(file, limit+1))
	return body, errors.Join(err, func() error {
		if int64(len(body)) > limit {
			return errors.New("update material oversized")
		}
		return nil
	}())
}

func activePairMatches(root *os.Root, record, executable []byte) bool {
	gotRecord, recordErr := readRootFile(root, "var/lib/sbxr/installed.json", 0o600, 1, maxInstalledRecord)
	gotExecutable, executableErr := readRootFile(root, "usr/local/bin/sbxr", 0o755, 1, maxInstalledBinary)
	return recordErr == nil && executableErr == nil && bytes.Equal(gotRecord, record) && bytes.Equal(gotExecutable, executable) && activePairBytes(gotRecord, gotExecutable)
}

func activePairBytes(record, executable []byte) bool {
	_, ok := verifyInstalledRelease(record, executable)
	return ok
}
func digestBytes(body []byte) string {
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}

func syncUpdateDirectories(root *os.Root) error {
	return errors.Join(syncUpdateDirectory(root, "usr/local/bin"), syncUpdateDirectory(root, "var/lib/sbxr"))
}

func syncUpdateDirectory(root *os.Root, name string) error {
	directory, err := root.Open(name)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func updateResult(state LifecycleState, installed *ReleaseIdentity, code ResultCode, message string) Result {
	return Result{State: state, Installed: installed, Code: code, Message: message}
}
