package softwarelifecycle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"reflect"
)

const (
	maxInstalledRecord = 4 << 10
	maxInstalledBinary = 256 << 20
)

var identityMagic = []byte("SBXR-IDENTITY-V1")

type LifecycleState string

const (
	Ready                 LifecycleState = "Ready"
	UpdateInProgress      LifecycleState = "Update in progress"
	RecoveryRequiredState LifecycleState = "Recovery required"
)

type ResultCode string

const (
	StatusReady             ResultCode = "SOFTWARE-LIFECYCLE-STATUS-READY"
	StatusUpdateInProgress  ResultCode = "SOFTWARE-LIFECYCLE-STATUS-UPDATE-IN-PROGRESS"
	StatusRecoveryRequired  ResultCode = "SOFTWARE-LIFECYCLE-STATUS-RECOVERY-REQUIRED"
	CheckUpdateAvailable    ResultCode = "SOFTWARE-LIFECYCLE-CHECK-UPDATE-AVAILABLE"
	CheckAlreadyCurrent     ResultCode = "SOFTWARE-LIFECYCLE-CHECK-ALREADY-CURRENT"
	CheckReleaseRefused     ResultCode = "SOFTWARE-LIFECYCLE-CHECK-RELEASE-REFUSED"
	CheckReleaseUnavailable ResultCode = "SOFTWARE-LIFECYCLE-CHECK-RELEASE-UNAVAILABLE"
	CheckConcurrentChange   ResultCode = "SOFTWARE-LIFECYCLE-CHECK-CONCURRENT-CHANGE"
	CheckNotReady           ResultCode = "SOFTWARE-LIFECYCLE-CHECK-NOT-READY"
)

type Result struct {
	State           LifecycleState
	Installed       *ReleaseIdentity
	Latest          *ReleaseIdentity
	UpdateInstalled bool
	Code            ResultCode
	Message         string
}

type ProgressMode string

const (
	Spinner     ProgressMode = "spinner"
	ProgressBar ProgressMode = "progress bar"
)

type Operation string

const (
	CheckOperation   Operation = "Check"
	UpdateOperation  Operation = "Update"
	RecoverOperation Operation = "Recover"
)

type Progress struct {
	Operation Operation
	Status    string
	Mode      ProgressMode
	Completed uint64
	Total     uint64
}

type ProgressReporter func(Progress)

type LatestRelease struct {
	Identity ReleaseIdentity
	Sequence uint64
}

type LatestReleaseOutcome uint8

const (
	LatestReleaseAccepted LatestReleaseOutcome = iota + 1
	LatestReleaseRefused
	LatestReleaseUnavailable
)

type LatestReleaseSource interface {
	CheckLatest(context.Context) (LatestRelease, LatestReleaseOutcome)
}

// Interface is the complete Owner-facing Software Lifecycle seam.
type Interface interface {
	Status(context.Context) Result
	Check(context.Context, ProgressReporter) Result
	Update(context.Context, ProgressReporter) Result
	Recover(context.Context, ProgressReporter) Result
}

type installedInterface struct {
	local  localInspector
	latest LatestReleaseSource
}

// localInspector is the private Adapter seam behind the Owner-facing Interface.
type localInspector interface {
	inspect(context.Context) localInspection
}

type localInspection struct {
	inspectionValid, lockHeld, transactionEvidence bool
	installedRecord, executable                    []byte
}

func NewInstalled(latest LatestReleaseSource) Interface {
	return newInstalledInterface(newLocalInspector("/", 0), latest)
}

func newInstalledInterface(local localInspector, latest LatestReleaseSource) Interface {
	return installedInterface{local: local, latest: latest}
}

func (module installedInterface) Status(ctx context.Context) Result {
	if module.local == nil {
		return recoveryRequiredResult()
	}
	return statusFromInspection(module.local.inspect(ctx))
}

func (module installedInterface) Check(ctx context.Context, _ ProgressReporter) Result {
	if module.local == nil {
		return checkNotReady(recoveryRequiredResult())
	}
	before := module.local.inspect(ctx)
	status := statusFromInspection(before)
	if status.State != Ready {
		return checkNotReady(status)
	}
	installed, ok := verifyInstalledRelease(before.installedRecord, before.executable)
	if !ok {
		return checkNotReady(recoveryRequiredResult())
	}
	if module.latest == nil {
		return Result{State: Ready, Installed: &installed.identity, Code: CheckReleaseRefused, Message: "The latest SBXR release was refused."}
	}
	latest, outcome := module.latest.CheckLatest(ctx)
	after := module.local.inspect(ctx)
	if !reflect.DeepEqual(before, after) {
		result := statusFromInspection(after)
		result.Code = CheckConcurrentChange
		result.Message = "Local Software Lifecycle facts changed during the check."
		result.Latest = nil
		return result
	}
	base := Result{State: Ready, Installed: &installed.identity}
	switch outcome {
	case LatestReleaseUnavailable:
		base.Code = CheckReleaseUnavailable
		base.Message = "The latest SBXR release is unavailable. Check again later."
		return base
	case LatestReleaseAccepted:
		if !validLatestRelease(latest) {
			break
		}
		if latest.Identity == installed.identity && latest.Sequence == installed.sequence {
			base.Latest = &latest.Identity
			base.Code = CheckAlreadyCurrent
			base.Message = "SBXR is already current."
			return base
		}
		if latest.Identity != installed.identity && latest.Sequence > installed.sequence {
			base.Latest = &latest.Identity
			base.Code = CheckUpdateAvailable
			base.Message = "A newer qualified SBXR release is available."
			return base
		}
	}
	base.Code = CheckReleaseRefused
	base.Message = "The latest SBXR release was refused."
	return base
}

func (module installedInterface) Update(ctx context.Context, _ ProgressReporter) Result {
	return module.Status(ctx)
}

func (module installedInterface) Recover(ctx context.Context, _ ProgressReporter) Result {
	return module.Status(ctx)
}

func recoveryRequiredResult() Result {
	return Result{State: RecoveryRequiredState, Code: StatusRecoveryRequired, Message: "SBXR needs recovery before normal operations can continue."}
}

func statusFromInspection(inspection localInspection) Result {
	if inspection.lockHeld {
		return Result{State: UpdateInProgress, Code: StatusUpdateInProgress, Message: "Another Software Lifecycle change is in progress."}
	}
	if !inspection.inspectionValid || inspection.transactionEvidence {
		return recoveryRequiredResult()
	}
	identity, ok := verifyInstalledPair(inspection.installedRecord, inspection.executable)
	if !ok {
		return recoveryRequiredResult()
	}
	return Result{State: Ready, Installed: &identity, Code: StatusReady, Message: "SBXR is ready."}
}

func checkNotReady(result Result) Result {
	result.Code = CheckNotReady
	result.Message = "SBXR is not ready to check for updates."
	return result
}

func validLatestRelease(release LatestRelease) bool {
	return release.Sequence > 0 && release.Identity.Repository == Repository && immutableReleaseTag.MatchString(release.Identity.Tag) && commitPattern.MatchString(release.Identity.Commit) && hashPattern.MatchString(release.Identity.IndexSHA256)
}

type installedRecord struct {
	Schema             int          `json:"schema"`
	Repository         string       `json:"repository"`
	Tag                string       `json:"tag"`
	Commit             string       `json:"commit"`
	ReleaseIndexSHA256 string       `json:"release_index_sha256"`
	Sequence           uint64       `json:"sequence"`
	Architecture       Architecture `json:"architecture"`
	ExecutableSHA256   string       `json:"executable_sha256"`
}

type embeddedIdentity struct {
	Schema        int          `json:"schema"`
	Repository    string       `json:"repository"`
	Tag           string       `json:"tag"`
	Commit        string       `json:"commit"`
	Sequence      uint64       `json:"sequence"`
	Architecture  Architecture `json:"architecture"`
	PayloadSHA256 string       `json:"payload_sha256"`
}

func verifyInstalledPair(recordBytes, executable []byte) (ReleaseIdentity, bool) {
	verified, ok := verifyInstalledRelease(recordBytes, executable)
	return verified.identity, ok
}

type installedRelease struct {
	identity ReleaseIdentity
	sequence uint64
}

func verifyInstalledRelease(recordBytes, executable []byte) (installedRelease, bool) {
	var record installedRecord
	if !decodeExactObject(recordBytes, &record) || !validInstalledRecord(record) {
		return installedRelease{}, false
	}
	embedded, ok := readEmbeddedIdentity(executable)
	if !ok || embedded.Repository != record.Repository || embedded.Tag != record.Tag || embedded.Commit != record.Commit || embedded.Sequence != record.Sequence || embedded.Architecture != record.Architecture {
		return installedRelease{}, false
	}
	digest := sha256.Sum256(executable)
	if hex.EncodeToString(digest[:]) != record.ExecutableSHA256 {
		return installedRelease{}, false
	}
	return installedRelease{identity: ReleaseIdentity{Repository: record.Repository, Tag: record.Tag, Commit: record.Commit, IndexSHA256: record.ReleaseIndexSHA256}, sequence: record.Sequence}, true
}

func validInstalledRecord(record installedRecord) bool {
	return record.Schema == 1 && record.Repository == Repository && immutableReleaseTag.MatchString(record.Tag) && commitPattern.MatchString(record.Commit) && hashPattern.MatchString(record.ReleaseIndexSHA256) && record.Sequence > 0 && (record.Architecture == AMD64 || record.Architecture == ARM64) && hashPattern.MatchString(record.ExecutableSHA256)
}

func decodeExactObject(document []byte, target any) bool {
	if len(document) == 0 || bytes.HasPrefix(document, []byte{0xef, 0xbb, 0xbf}) || !json.Valid(document) || ValidateUniqueJSON(document) != nil {
		return false
	}
	strict := json.NewDecoder(bytes.NewReader(document))
	strict.DisallowUnknownFields()
	return strict.Decode(target) == nil
}

func readEmbeddedIdentity(executable []byte) (embeddedIdentity, bool) {
	tailSize := sha256.Size + 8 + len(identityMagic)
	if len(executable) <= tailSize || len(executable) > maxInstalledBinary || !bytes.Equal(executable[len(executable)-len(identityMagic):], identityMagic) {
		return embeddedIdentity{}, false
	}
	lengthOffset := len(executable) - len(identityMagic) - 8
	length := binary.LittleEndian.Uint64(executable[lengthOffset : lengthOffset+8])
	if length == 0 || length > maxInstalledRecord || int(length)+tailSize >= len(executable) {
		return embeddedIdentity{}, false
	}
	documentOffset := len(executable) - tailSize - int(length)
	document := executable[documentOffset : documentOffset+int(length)]
	want := sha256.Sum256(document)
	if !bytes.Equal(executable[documentOffset+int(length):lengthOffset], want[:]) {
		return embeddedIdentity{}, false
	}
	var identity embeddedIdentity
	if !decodeExactObject(document, &identity) || identity.Schema != 1 || identity.Repository != Repository || !immutableReleaseTag.MatchString(identity.Tag) || !commitPattern.MatchString(identity.Commit) || identity.Sequence == 0 || identity.Architecture != AMD64 && identity.Architecture != ARM64 || !hashPattern.MatchString(identity.PayloadSHA256) {
		return embeddedIdentity{}, false
	}
	payloadDigest := sha256.Sum256(executable[:documentOffset])
	return identity, hex.EncodeToString(payloadDigest[:]) == identity.PayloadSHA256
}
