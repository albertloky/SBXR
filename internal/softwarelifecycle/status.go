package softwarelifecycle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
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
	StatusReady            ResultCode = "SOFTWARE-LIFECYCLE-STATUS-READY"
	StatusUpdateInProgress ResultCode = "SOFTWARE-LIFECYCLE-STATUS-UPDATE-IN-PROGRESS"
	StatusRecoveryRequired ResultCode = "SOFTWARE-LIFECYCLE-STATUS-RECOVERY-REQUIRED"
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

// Interface is the complete Owner-facing Software Lifecycle seam.
type Interface interface {
	Status(context.Context) Result
	Check(context.Context, ProgressReporter) Result
	Update(context.Context, ProgressReporter) Result
	Recover(context.Context, ProgressReporter) Result
}

type installedInterface struct{ local localInspector }

// localInspector is the private Adapter seam behind the Owner-facing Interface.
type localInspector interface {
	inspect(context.Context) localInspection
}

type localInspection struct {
	safe, lockHeld, transactionEvidence bool
	installedRecord, executable         []byte
}

func NewInstalled() Interface { return newInstalledInterface(newLocalInspector("/", 0)) }

func newInstalledInterface(local localInspector) Interface { return installedInterface{local: local} }

func (module installedInterface) Status(ctx context.Context) Result {
	if module.local == nil {
		return recoveryRequiredResult()
	}
	inspection := module.local.inspect(ctx)
	if inspection.lockHeld {
		return Result{State: UpdateInProgress, Code: StatusUpdateInProgress, Message: "Another Software Lifecycle change is in progress."}
	}
	if !inspection.safe || inspection.transactionEvidence {
		return recoveryRequiredResult()
	}
	identity, ok := verifyInstalledPair(inspection.installedRecord, inspection.executable)
	if !ok {
		return recoveryRequiredResult()
	}
	return Result{State: Ready, Installed: &identity, Code: StatusReady, Message: "SBXR is ready."}
}

// Later tickets replace these status-only integration-line results with their
// specified behavior without changing Interface.
func (module installedInterface) Check(ctx context.Context, _ ProgressReporter) Result {
	return module.Status(ctx)
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
	var record installedRecord
	if !decodeExactObject(recordBytes, &record) || !validInstalledRecord(record) {
		return ReleaseIdentity{}, false
	}
	embedded, ok := readEmbeddedIdentity(executable)
	if !ok || embedded.Repository != record.Repository || embedded.Tag != record.Tag || embedded.Commit != record.Commit || embedded.Sequence != record.Sequence || embedded.Architecture != record.Architecture {
		return ReleaseIdentity{}, false
	}
	digest := sha256.Sum256(executable)
	if hex.EncodeToString(digest[:]) != record.ExecutableSHA256 {
		return ReleaseIdentity{}, false
	}
	return ReleaseIdentity{Repository: record.Repository, Tag: record.Tag, Commit: record.Commit, IndexSHA256: record.ReleaseIndexSHA256}, true
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
