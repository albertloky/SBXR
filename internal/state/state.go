package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"reflect"
	"strings"
	"sync/atomic"
)

const supportedSchema = 1

// InstallationStatus is separate from every Module's Health Results.
type InstallationStatus string

const (
	NotInstalled     InstallationStatus = "Not installed"
	Managed          InstallationStatus = "Managed"
	ChangeInProgress InstallationStatus = "Change in progress"
	RecoveryRequired InstallationStatus = "Recovery Required"
)

// BaselineProof states which coordinated admission fact has been proven.
type BaselineProof string

const (
	CleanVPS        BaselineProof = "Clean VPS"
	ManagedEvidence BaselineProof = "SBXR-managed evidence"
)

// ReleaseIdentity names one exact verified SBXR release.
type ReleaseIdentity struct {
	Repository         string `json:"repository"`
	Tag                string `json:"tag"`
	Commit             string `json:"commit"`
	ReleaseIndexSHA256 string `json:"release_index_sha256"`
}

// ChangeSetIdentity names one coordinated installation mutation.
type ChangeSetIdentity string

// LineageProof is the coordinated current State fact supplied to Load.
type LineageProof struct {
	Revision               uint64
	LastCompletedChangeSet ChangeSetIdentity
	ReleaseIdentity        ReleaseIdentity
	ActiveChangeSet        ChangeSetIdentity
}

// LoadRequest contains only the admission and lineage facts Load must prove.
type LoadRequest struct {
	Baseline         BaselineProof
	SupportedRelease ReleaseIdentity
	Lineage          *LineageProof
}

// Snapshot is the validated current Desired State and its lineage envelope.
type Snapshot struct {
	Revision               uint64
	ReleaseIdentity        ReleaseIdentity
	LastCompletedChangeSet ChangeSetIdentity
	DesiredState           DesiredState
}

// CurrentOperation is the only mutation detail exposed during Change in progress.
type CurrentOperation struct {
	ChangeSet ChangeSetIdentity
}

// Result is the safe caller-facing outcome of Load.
type Result struct {
	Status           InstallationStatus
	Snapshot         *Snapshot
	CurrentOperation *CurrentOperation
	loaded           *loadedState
}

func (result Result) String() string {
	revision := uint64(0)
	if result.Snapshot != nil {
		revision = result.Snapshot.Revision
	}
	operation := ChangeSetIdentity("")
	if result.CurrentOperation != nil {
		operation = result.CurrentOperation.ChangeSet
	}
	return fmt.Sprintf("State result: status=%s revision=%d current_operation=%s", result.Status, revision, operation)
}

func (result Result) GoString() string { return result.String() }

type loadedState struct {
	owner           *implementation
	status          InstallationStatus
	revision        uint64
	payloadChecksum string
	bytes           []byte
	used            atomic.Bool
}

// Finding is a typed, secret-safe refusal suitable for a Correction Flow.
type Finding struct {
	Code       string
	Concept    string
	Found      string
	Required   string
	Why        string
	NextAction string
}

func (f *Finding) Error() string {
	return fmt.Sprintf("%s: %s; found %s; required %s; %s; next: %s", f.Code, f.Concept, f.Found, f.Required, f.Why, f.NextAction)
}

// Storage is the State-owned Seam implemented by one production Adapter.
type Storage interface {
	Read() ([]byte, error)
	Publish(expectedPrior, candidate []byte, candidateSHA256 string) ([]byte, error)
}

// Interface is the caller-facing State Module boundary.
type Interface struct{ implementation *implementation }

type implementation struct {
	storage Storage
}

// New wires Load to its one storage boundary.
func New(storage Storage) Interface {
	return Interface{implementation: &implementation{storage: storage}}
}

// Load returns a proven clean baseline or a validated current snapshot without
// changing State or host resources.
func (i Interface) Load(request LoadRequest) (Result, error) {
	if i.implementation == nil || i.implementation.storage == nil {
		return refuse("STATE-STORAGE-UNAVAILABLE", "Desired State storage", "no storage Adapter", "the production State storage Adapter", "State cannot prove current intent", "restore the State Adapter and check again")
	}

	data, err := i.implementation.storage.Read()
	if errors.Is(err, fs.ErrNotExist) {
		if request.Baseline == CleanVPS && request.Lineage == nil {
			return Result{Status: NotInstalled, loaded: &loadedState{owner: i.implementation, status: NotInstalled}}, nil
		}
		return refuse("STATE-LINEAGE-MISSING", "Desired State lineage", "state.json is absent beside managed or claimed lineage", "absence only with a proven Clean VPS baseline", "SBXR cannot prove a Not installed or Managed baseline", "reimage to a Clean VPS or use the Recovery Required flow")
	}
	if err != nil {
		var finding *Finding
		if errors.As(err, &finding) {
			return Result{Status: RecoveryRequired}, finding
		}
		return refuse("STATE-STORAGE-READ", "Desired State storage", "a protected read failed", "one readable root-only state.json", "SBXR cannot prove the current document", "correct the storage problem and check again")
	}
	if request.Baseline != ManagedEvidence || request.Lineage == nil {
		return refuse("STATE-LINEAGE-UNPROVABLE", "Desired State lineage", "state.json exists without coordinated managed evidence", "matching managed evidence and lineage", "SBXR never adopts discovered State", "use the Recovery Required flow")
	}

	document, finding := decode(data)
	if finding != nil {
		return Result{Status: RecoveryRequired}, finding
	}
	if document.ReleaseIdentity != request.SupportedRelease {
		return refuse("STATE-RELEASE-UNSUPPORTED", "Release Identity", "the stored release is not the supported release", "the exact supported Release Identity", "this executable cannot safely interpret current State", "use a compatible verified release and check again")
	}
	if document.Revision != request.Lineage.Revision {
		return refuse("STATE-LINEAGE-REVISION", "Desired State revision", fmt.Sprintf("revision %d disagrees with proven lineage", document.Revision), fmt.Sprintf("revision %d", request.Lineage.Revision), "the current revision cannot be proven", "use the Recovery Required flow")
	}
	if document.ReleaseIdentity != request.Lineage.ReleaseIdentity {
		return refuse("STATE-LINEAGE-RELEASE", "Release Identity lineage", "the stored and proven releases disagree", "one exact matching Release Identity", "the current release lineage cannot be proven", "use the Recovery Required flow")
	}
	if document.LastCompletedChangeSet != request.Lineage.LastCompletedChangeSet {
		return refuse("STATE-LINEAGE-CHANGE-SET", "last completed Change Set", "the stored and proven Change Set identities disagree", "one exact matching completed Change Set", "the current transaction lineage cannot be proven", "use the Recovery Required flow")
	}
	if request.Lineage.ActiveChangeSet != "" && !validChangeSetIdentity(request.Lineage.ActiveChangeSet) {
		return refuse("STATE-LINEAGE-ACTIVE-CHANGE-SET", "active Change Set", "an invalid active Change Set identity", "one valid coordinated Change Set identity", "Change in progress cannot be proven", "use the Recovery Required flow")
	}

	status := Managed
	var operation *CurrentOperation
	if request.Lineage.ActiveChangeSet != "" {
		status = ChangeInProgress
		operation = &CurrentOperation{ChangeSet: request.Lineage.ActiveChangeSet}
	}
	return Result{Status: status, Snapshot: &Snapshot{
		Revision:               document.Revision,
		ReleaseIdentity:        document.ReleaseIdentity,
		LastCompletedChangeSet: document.LastCompletedChangeSet,
		DesiredState:           document.desiredState,
	}, CurrentOperation: operation, loaded: &loadedState{owner: i.implementation, status: status, revision: document.Revision, payloadChecksum: document.Checksum, bytes: append([]byte(nil), data...)}}, nil
}

type persistedDocument struct {
	SchemaVersion          uint64            `json:"schema_version"`
	Revision               uint64            `json:"revision"`
	ReleaseIdentity        ReleaseIdentity   `json:"release_identity"`
	LastCompletedChangeSet ChangeSetIdentity `json:"last_completed_change_set"`
	Payload                json.RawMessage   `json:"payload"`
	Checksum               string            `json:"checksum"`
	desiredState           DesiredState
}

func decode(data []byte) (persistedDocument, *Finding) {
	if err := rejectDuplicateKeys(data); err != nil {
		if errors.Is(err, errDuplicateKey) {
			return persistedDocument{}, finding("STATE-DOCUMENT-DUPLICATE-KEY", "Desired State JSON", "a duplicate object key", "one unambiguous value per field", "duplicate keys can be interpreted differently", "correct the document source and rebuild from a proven baseline")
		}
		return persistedDocument{}, finding("STATE-DOCUMENT-MALFORMED", "Desired State JSON", "malformed JSON", "one complete JSON document", "SBXR cannot interpret damaged State safely", "use the Recovery Required flow")
	}
	if err := validateFieldNames(data); err != nil {
		if errors.Is(err, errUnknownField) {
			return persistedDocument{}, finding("STATE-DOCUMENT-UNSUPPORTED-FIELD", "Desired State schema", "an unsupported field", "only exact fields defined by the supported schema", "silently accepting or dropping fields could change Owner intent", "use a compatible verified release and check again")
		}
		return persistedDocument{}, finding("STATE-DOCUMENT-INVALID", "Desired State envelope", "a missing or invalid typed value", "all required values in their exact supported types", "the stored intent is not a complete typed document", "use the Recovery Required flow")
	}

	var document persistedDocument
	if err := strictDecode(data, &document); err != nil {
		if strings.Contains(err.Error(), "unknown field") {
			return persistedDocument{}, finding("STATE-DOCUMENT-UNSUPPORTED-FIELD", "Desired State schema", "an unsupported field", "only fields defined by the supported schema", "silently dropping fields could change Owner intent", "use a compatible verified release and check again")
		}
		return persistedDocument{}, finding("STATE-DOCUMENT-INVALID", "Desired State envelope", "an invalid typed value", "all required values in their exact supported types", "the stored intent is not a valid typed document", "use the Recovery Required flow")
	}
	if document.SchemaVersion != supportedSchema {
		return persistedDocument{}, finding("STATE-SCHEMA-UNSUPPORTED", "Desired State schema", fmt.Sprintf("schema %d", document.SchemaVersion), fmt.Sprintf("schema %d", supportedSchema), "this slice supports no migration path", "use a compatible verified release and check again")
	}
	if document.Revision == 0 || !validChangeSetIdentity(document.LastCompletedChangeSet) || !validReleaseIdentity(document.ReleaseIdentity) || !validSHA256(document.Checksum) {
		return persistedDocument{}, finding("STATE-DOCUMENT-INVALID", "Desired State envelope", "a missing or invalid envelope value", "a positive revision, exact Release Identity, completed Change Set, and SHA-256 checksum", "the stored lineage is incomplete", "use the Recovery Required flow")
	}
	var payload DesiredState
	trimmedPayload := bytes.TrimSpace(document.Payload)
	if len(trimmedPayload) < 2 || trimmedPayload[0] != '{' || trimmedPayload[len(trimmedPayload)-1] != '}' {
		return persistedDocument{}, finding("STATE-DOCUMENT-INVALID", "Desired State payload", "an invalid typed payload", "one complete supported typed payload", "the stored intent is incomplete", "use the Recovery Required flow")
	}
	if err := validateExactJSON(document.Payload, reflect.TypeOf(DesiredState{})); err != nil {
		if errors.Is(err, errUnknownField) {
			return persistedDocument{}, finding("STATE-DOCUMENT-UNSUPPORTED-FIELD", "Desired State payload", "an unsupported or case-changed field", "only exact fields defined by the supported schema", "silently accepting or dropping fields could change Owner intent", "use a compatible verified release and check again")
		}
		return persistedDocument{}, finding("STATE-DOCUMENT-INVALID", "Desired State payload", "a required field is absent", "one complete supported typed payload", "the stored intent is incomplete", "use the Recovery Required flow")
	}
	if err := strictDecode(document.Payload, &payload); err != nil {
		if strings.Contains(err.Error(), "unknown field") {
			return persistedDocument{}, finding("STATE-DOCUMENT-UNSUPPORTED-FIELD", "Desired State payload", "an unsupported field", "only fields defined by the supported schema", "silently dropping fields could change Owner intent", "use a compatible verified release and check again")
		}
		return persistedDocument{}, finding("STATE-DOCUMENT-INVALID", "Desired State payload", "an invalid typed payload", "one complete supported typed payload", "the stored intent is incomplete", "use the Recovery Required flow")
	}
	document.desiredState = DesiredState(payload)
	checksum := sha256.Sum256(document.Payload)
	if hex.EncodeToString(checksum[:]) != document.Checksum {
		return persistedDocument{}, finding("STATE-CHECKSUM-MISMATCH", "Desired State integrity", "the payload integrity check failed", "the persisted payload checksum to match", "the document may have changed outside an approved Change Set", "use the Recovery Required flow")
	}
	if finding := validateDesiredState(payload); finding != nil {
		return persistedDocument{}, finding
	}
	return document, nil
}

func strictDecode(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

var errDuplicateKey = errors.New("duplicate JSON key")
var errUnknownField = errors.New("unknown JSON field")
var errMissingField = errors.New("missing JSON field")

func validateFieldNames(data []byte) error {
	return validateExactJSON(data, reflect.TypeOf(persistedDocument{}))
}

var jsonUnmarshaler = reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()

func validateExactJSON(data []byte, valueType reflect.Type) error {
	for valueType.Kind() == reflect.Pointer {
		valueType = valueType.Elem()
	}
	if reflect.PointerTo(valueType).Implements(jsonUnmarshaler) || valueType.Kind() != reflect.Struct {
		return nil
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil || object == nil {
		return errMissingField
	}
	fields := map[string]reflect.Type{}
	for index := range valueType.NumField() {
		field := valueType.Field(index)
		if !field.IsExported() {
			continue
		}
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name == "-" {
			continue
		}
		if name == "" {
			name = field.Name
		}
		fields[name] = field.Type
	}
	for name := range object {
		if _, exists := fields[name]; !exists {
			return errUnknownField
		}
	}
	for name, fieldType := range fields {
		raw, exists := object[name]
		if !exists {
			return errMissingField
		}
		if err := validateExactJSON(raw, fieldType); err != nil {
			return err
		}
	}
	return nil
}

func rejectDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]struct{}{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("non-string JSON object key")
				}
				if _, exists := seen[key]; exists {
					return errDuplicateKey
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return errors.New("unexpected JSON delimiter")
		}
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func validReleaseIdentity(identity ReleaseIdentity) bool {
	return identity.Repository != "" && identity.Tag != "" && validHex(identity.Commit, 40, 64) && validHex(identity.ReleaseIndexSHA256, 64)
}

func validSHA256(value string) bool { return validHex(value, 64) }

func validChangeSetIdentity(value ChangeSetIdentity) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("-_.:", character) {
			continue
		}
		return false
	}
	return true
}

func validHex(value string, lengths ...int) bool {
	validLength := false
	for _, length := range lengths {
		validLength = validLength || len(value) == length
	}
	if !validLength || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func refuse(code, concept, found, required, why, next string) (Result, error) {
	return Result{Status: RecoveryRequired}, finding(code, concept, found, required, why, next)
}

func finding(code, concept, found, required, why, next string) *Finding {
	return &Finding{Code: code, Concept: concept, Found: found, Required: required, Why: why, NextAction: next}
}
