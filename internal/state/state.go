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
	"slices"
	"strings"
	"sync/atomic"
)

type SchemaVersion uint64

const supportedSchema SchemaVersion = 2

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
	SchemaVersion          SchemaVersion
	Revision               uint64
	ReleaseIdentity        ReleaseIdentity
	LastCompletedChangeSet ChangeSetIdentity
	DesiredState           DesiredState
}

// MigrationStepReview is one explicit schema-to-schema transformation and its
// secret-safe Owner review facts. Schema 1 has no predecessor, so v1 returns no steps.
type MigrationStepReview struct {
	FromSchema              SchemaVersion
	ToSchema                SchemaVersion
	MeaningChanges          []string
	GeneratedServiceEffects []string
	ServiceInterruption     bool
	RequiredOwnerInput      bool
}

// MigrationReview states the exact schema path and release compatibility
// established by Load or PrepareCommit without claiming an update succeeded.
type MigrationReview struct {
	StartingSchema                  SchemaVersion
	TargetSchema                    SchemaVersion
	StartingRelease                 ReleaseIdentity
	TargetRelease                   ReleaseIdentity
	Steps                           []MigrationStepReview
	StartingReleaseCanReadCandidate bool
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
	Migration        *MigrationReview
	loaded           *loadedState
}

// HealthReleaseInspection is the non-secret Release Identity already proven by
// one exact fresh Managed Load. Its proof bit cannot be caller-authored.
type HealthReleaseInspection struct {
	identity ReleaseIdentity
	verified bool
}

// SystemChangesLineageInspection exposes only the non-secret lineage from one
// exact typed Load; callers cannot construct or reuse its proof bit.
type SystemChangesLineageInspection struct {
	revision uint64
	sha256   string
	change   ChangeSetIdentity
	release  ReleaseIdentity
	verified bool
}

func (inspection SystemChangesLineageInspection) SystemChangesStateLineageFacts() (uint64, string, ChangeSetIdentity, ReleaseIdentity, bool) {
	return inspection.revision, inspection.sha256, inspection.change, inspection.release, inspection.verified
}

func (i Interface) SystemChangesLineageInspection(result Result) SystemChangesLineageInspection {
	if i.implementation == nil || result.loaded == nil || result.loaded.owner != i.implementation || result.loaded.status != Managed || result.Status != Managed || result.Snapshot == nil || result.Snapshot.Revision != result.loaded.revision {
		return SystemChangesLineageInspection{}
	}
	document, problem := decode(result.loaded.bytes)
	if problem != nil || document.Revision != result.Snapshot.Revision || document.LastCompletedChangeSet != result.Snapshot.LastCompletedChangeSet || document.ReleaseIdentity != result.Snapshot.ReleaseIdentity || document.Checksum != result.loaded.payloadChecksum {
		return SystemChangesLineageInspection{}
	}
	return SystemChangesLineageInspection{revision: document.Revision, sha256: document.Checksum, change: document.LastCompletedChangeSet, release: document.ReleaseIdentity, verified: true}
}

func (inspection HealthReleaseInspection) HealthReleaseIdentityFacts() (string, string, string, string, bool) {
	identity := inspection.identity
	return identity.Repository, identity.Tag, identity.Commit, identity.ReleaseIndexSHA256, inspection.verified
}

func (i Interface) HealthReleaseInspection(result Result) HealthReleaseInspection {
	if i.implementation == nil || result.loaded == nil || result.loaded.owner != i.implementation || result.loaded.status != Managed || result.Status != Managed || result.Snapshot == nil {
		return HealthReleaseInspection{}
	}
	document, problem := decode(result.loaded.bytes)
	if problem != nil || document.ReleaseIdentity != result.Snapshot.ReleaseIdentity {
		return HealthReleaseInspection{}
	}
	return HealthReleaseInspection{identity: result.Snapshot.ReleaseIdentity, verified: true}
}

// WithManagedConnectionProfileSecrets gives the owning Connection Profiles
// composition one short-lived reader for an exact fresh Managed Load. The
// reader returns no value after the callback completes.
func (i Interface) WithManagedConnectionProfileSecrets(result Result, use func(Snapshot, ConnectionProfileSecretReader) error) error {
	if i.implementation == nil || result.loaded == nil || result.loaded.owner != i.implementation || result.Status != Managed || result.Snapshot == nil || use == nil || !result.loaded.profileSecretsUsed.CompareAndSwap(false, true) {
		return finding("STATE-CLIENT-ACCESS-LEASE", "Managed Client Access values", "the exact fresh Managed State authority is unavailable", "one fresh Managed Load and one immediate owning-Module callback", "protected values cannot be leased from caller-made or reused State", "reload current State and review again")
	}
	lease := newSecretReaderLease()
	defer lease.revoke()
	snapshot := *result.Snapshot
	return use(snapshot, &connectionProfileSecretReader{lease: lease})
}

func (i Interface) WithManagedSubscriptionSecrets(result Result, use func(Snapshot, ClientAccessReader) error) error {
	if i.implementation == nil || result.loaded == nil || result.loaded.owner != i.implementation || result.Status != Managed || result.Snapshot == nil || use == nil || !result.loaded.subscriptionSecretsUsed.CompareAndSwap(false, true) {
		return finding("STATE-SUBSCRIPTION-LEASE", "Managed Subscription Publication values", "the exact fresh Managed State authority is unavailable", "one fresh Managed Load and one immediate Subscription Publication callback", "protected values cannot be leased from caller-made or reused State", "reload current State and review again")
	}
	lease := newSecretReaderLease()
	defer lease.revoke()
	return use(*result.Snapshot, &clientAccessReader{lease: lease})
}

func (i Interface) WithManagedCloudflareSecrets(result Result, use func(Snapshot, InfrastructureSecretReader) error) error {
	if i.implementation == nil || result.loaded == nil || result.loaded.owner != i.implementation || result.Status != Managed || result.Snapshot == nil || use == nil || !result.loaded.cloudflareSecretsUsed.CompareAndSwap(false, true) {
		return finding("STATE-CLOUDFLARE-LEASE", "Managed Cloudflare authority", "the exact fresh Managed State authority is unavailable", "one fresh Managed Load and one immediate Cloudflare Tunnel callback", "Infrastructure Secrets cannot be leased from caller-made or reused State", "reload current State and review again")
	}
	lease := newSecretReaderLease()
	defer lease.revoke()
	return use(*result.Snapshot, &infrastructureSecretReader{lease: lease})
}

// SoftwareLifecycleCapability is State's secret-free proof of the current
// Managed Connection Profile capability state.
type SoftwareLifecycleCapability struct {
	revision                uint64
	stateSHA256             string
	cloudflareProfilesSetUp bool
}

func (*SoftwareLifecycleCapability) String() string {
	return "Software Lifecycle capability: protected"
}
func (*SoftwareLifecycleCapability) GoString() string {
	return "Software Lifecycle capability: protected"
}
func (*SoftwareLifecycleCapability) MarshalJSON() ([]byte, error) {
	return nil, errProtectedValueRendering
}

func (capability *SoftwareLifecycleCapability) SoftwareLifecycleManagedCapability() (revision uint64, stateSHA256 string, cloudflareProfilesSetUp bool, valid bool) {
	if capability == nil || capability.revision == 0 || !validSHA256(capability.stateSHA256) {
		return 0, "", false, false
	}
	return capability.revision, capability.stateSHA256, capability.cloudflareProfilesSetUp, true
}

func (i Interface) SoftwareLifecycleCapability(result Result) *SoftwareLifecycleCapability {
	if i.implementation == nil || result.loaded == nil || result.loaded.owner != i.implementation || result.loaded.status != Managed || result.Status != Managed || result.Snapshot == nil || result.Snapshot.Revision != result.loaded.revision {
		return nil
	}
	document, problem := decode(result.loaded.bytes)
	realityOnly, lifecycleFinding := validateProfileLifecycles(document.desiredState.ConnectionProfiles, document.SchemaVersion == 1)
	if problem != nil || lifecycleFinding != nil || document.Revision != result.loaded.revision || document.Checksum != result.loaded.payloadChecksum {
		return nil
	}
	return &SoftwareLifecycleCapability{revision: document.Revision, stateSHA256: document.Checksum, cloudflareProfilesSetUp: !realityOnly}
}

// ManagementTokenInventory is State's secret-free proof of the current
// behaviors that depend on Cloudflare management authority.
type ManagementTokenInventory struct {
	revision     uint64
	stateSHA256  string
	dependencies []string
}

func (*ManagementTokenInventory) String() string {
	return "Cloudflare management-token inventory: protected"
}
func (*ManagementTokenInventory) GoString() string {
	return "Cloudflare management-token inventory: protected"
}
func (inventory *ManagementTokenInventory) StateManagementTokenInventory() ([]byte, bool) {
	if inventory == nil || inventory.revision == 0 || !validSHA256(inventory.stateSHA256) {
		return nil, false
	}
	encoded, err := json.Marshal(struct {
		Revision     uint64
		StateSHA256  string
		Dependencies []string
	}{inventory.revision, inventory.stateSHA256, inventory.dependencies})
	return encoded, err == nil
}

// ManagementTokenInventory derives the removal review from the exact loaded
// State rather than accepting a caller-authored dependency list.
func (i Interface) ManagementTokenInventory(result Result) (*ManagementTokenInventory, error) {
	if i.implementation == nil || result.loaded == nil || result.loaded.owner != i.implementation || result.Status != Managed || result.Snapshot == nil || result.Snapshot.Revision != result.loaded.revision {
		return nil, finding("STATE-CLOUDFLARE-TOKEN-INVENTORY", "Cloudflare management-token dependencies", "the current Managed State authority is unavailable", "one fresh exact State Load", "a caller cannot declare its own removal inventory", "load current State and review again")
	}
	return &ManagementTokenInventory{
		revision:     result.loaded.revision,
		stateSHA256:  result.loaded.payloadChecksum,
		dependencies: []string{"Tunnel", "DNS", "certificate", "profile", "repair", "update"},
	}, nil
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
	owner                                                              *implementation
	status                                                             InstallationStatus
	revision                                                           uint64
	payloadChecksum                                                    string
	bytes                                                              []byte
	present                                                            bool
	migration                                                          MigrationReview
	used                                                               atomic.Bool
	profileSecretsUsed, subscriptionSecretsUsed, cloudflareSecretsUsed atomic.Bool
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
// The root architecture test permits only adapter/filesystem to pass it to New;
// other product Modules cannot construct a raw persistence path.
type Storage interface {
	Read() ([]byte, error)
	Publish(expectedPrior, candidate []byte, candidateSHA256 string) ([]byte, error)
}

// Interface is the caller-facing State Module boundary.
type Interface struct{ implementation *implementation }

type implementation struct {
	storage Storage
}

// New wires Load to its one storage boundary. Production construction is
// restricted to adapter/filesystem by the root architecture test.
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
	migration := MigrationReview{
		StartingSchema: document.SchemaVersion, TargetSchema: supportedSchema,
		StartingRelease: document.ReleaseIdentity, TargetRelease: request.SupportedRelease,
		Steps: migrationSteps(document.SchemaVersion), StartingReleaseCanReadCandidate: document.SchemaVersion == supportedSchema && document.ReleaseIdentity == request.SupportedRelease,
	}
	return Result{Status: status, Snapshot: &Snapshot{
		SchemaVersion:          document.SchemaVersion,
		Revision:               document.Revision,
		ReleaseIdentity:        document.ReleaseIdentity,
		LastCompletedChangeSet: document.LastCompletedChangeSet,
		DesiredState:           document.desiredState,
	}, CurrentOperation: operation, Migration: cloneMigrationReview(&migration), loaded: &loadedState{owner: i.implementation, status: status, revision: document.Revision, payloadChecksum: document.Checksum, bytes: append([]byte(nil), data...), migration: migration}}, nil
}

func cloneMigrationReview(review *MigrationReview) *MigrationReview {
	if review == nil {
		return nil
	}
	cloned := *review
	cloned.Steps = append([]MigrationStepReview(nil), review.Steps...)
	for index := range cloned.Steps {
		cloned.Steps[index].MeaningChanges = append([]string(nil), review.Steps[index].MeaningChanges...)
		cloned.Steps[index].GeneratedServiceEffects = append([]string(nil), review.Steps[index].GeneratedServiceEffects...)
	}
	if cloned.Steps == nil {
		cloned.Steps = []MigrationStepReview{}
	}
	return &cloned
}

type persistedDocument struct {
	SchemaVersion          SchemaVersion     `json:"schema_version"`
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
	if document.SchemaVersion != 1 && document.SchemaVersion != supportedSchema {
		return persistedDocument{}, finding("STATE-SCHEMA-UNSUPPORTED", "Desired State schema", fmt.Sprintf("schema %d", document.SchemaVersion), "schema 1 or 2", "no complete sequential migration path exists", "use a compatible verified release and check again")
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
	if document.SchemaVersion == 1 && hasExplicitProfileLifecycle(payload.ConnectionProfiles) {
		return persistedDocument{}, finding("STATE-DOCUMENT-UNSUPPORTED-FIELD", "Desired State schema 1", "a schema 2 lifecycle field", "only fields defined by schema 1", "schema meaning cannot change without migration", "use a compatible verified release and review the migration")
	}
	document.desiredState = DesiredState(payload)
	checksum := sha256.Sum256(document.Payload)
	if hex.EncodeToString(checksum[:]) != document.Checksum {
		return persistedDocument{}, finding("STATE-CHECKSUM-MISMATCH", "Desired State integrity", "the payload integrity check failed", "the persisted payload checksum to match", "the document may have changed outside an approved Change Set", "use the Recovery Required flow")
	}
	if finding := validateDesiredStateVersion(payload, true); finding != nil {
		return persistedDocument{}, finding
	}
	if document.Revision == 1 {
		realityOnly, lifecycleFinding := validateProfileLifecycles(payload.ConnectionProfiles, document.SchemaVersion == 1)
		if lifecycleFinding != nil || !realityOnly {
			return persistedDocument{}, profileLifecycleFinding("Desired State revision 1", "the revision contains more than VLESS REALITY Vision")
		}
	}
	return document, nil
}

func hasExplicitProfileLifecycle(profiles ConnectionProfiles) bool {
	return profiles.VLESSRealityVision.Lifecycle != "" || profiles.VLESSXHTTP.Lifecycle != "" || profiles.VLESSWebSocket.Lifecycle != "" || profiles.Hysteria2.Lifecycle != "" || profiles.TUIC.Lifecycle != "" || profiles.AnyTLS.Lifecycle != ""
}

func migrationSteps(start SchemaVersion) []MigrationStepReview {
	if start != 1 {
		return []MigrationStepReview{}
	}
	return []MigrationStepReview{{
		FromSchema: 1, ToSchema: 2,
		MeaningChanges:          []string{"Schema 2 adds the Owner-approved certificate renewal email and explicit Connection Profile lifecycle states"},
		GeneratedServiceEffects: []string{"Regenerate and validate all release-bound service and subscription material"},
		ServiceInterruption:     true,
		RequiredOwnerInput:      true,
	}}
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
	type exactField struct {
		valueType reflect.Type
		required  bool
	}
	fields := map[string]exactField{}
	for index := range valueType.NumField() {
		field := valueType.Field(index)
		if !field.IsExported() {
			continue
		}
		tag := strings.Split(field.Tag.Get("json"), ",")
		name := tag[0]
		if name == "-" {
			continue
		}
		if name == "" {
			name = field.Name
		}
		fields[name] = exactField{valueType: field.Type, required: !slices.Contains(tag[1:], "omitempty")}
	}
	for name := range object {
		if _, exists := fields[name]; !exists {
			return errUnknownField
		}
	}
	for name, field := range fields {
		raw, exists := object[name]
		if !exists {
			if field.required {
				return errMissingField
			}
			continue
		}
		if err := validateExactJSON(raw, field.valueType); err != nil {
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
