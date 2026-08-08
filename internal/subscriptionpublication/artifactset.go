package subscriptionpublication

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strings"

	"github.com/albertloky/SBXR/internal/state"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

var artifactNames = []string{"base64", "raw", "v2rayn", "shadowrocket", "karing", "mihomo", "sing-box", "metadata"}
var identityPattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)

type Omission struct {
	ID string `json:"id"`
}

type Metadata struct {
	Schema               string                `json:"schema"`
	ChangeSet            string                `json:"change_set"`
	SelectedAddress      string                `json:"selected_address"`
	DesiredStateSHA256   string                `json:"desired_state_sha256"`
	ManagedInputsSHA256  string                `json:"managed_inputs_sha256"`
	RelevantChecksums    RelevantChecksums     `json:"relevant_checksums"`
	Compatibility        string                `json:"compatibility_definition"`
	DesiredStateRevision uint64                `json:"desired_state_revision"`
	ReleaseIdentity      state.ReleaseIdentity `json:"release_identity"`
	ClientAccessAction   ClientAccessAction    `json:"client_access_action,omitempty"`
	Representations      []string              `json:"representations"`
	ArtifactSHA256       map[string]string     `json:"artifact_sha256"`
	ProfileCount         int                   `json:"profile_count"`
	Omissions            []Omission            `json:"omissions"`
	ValidationComplete   bool                  `json:"validation_complete"`
}

type ArtifactFile struct {
	Name string
	Body []byte
}

func (ArtifactFile) MarshalJSON() ([]byte, error) {
	return nil, errors.New("Subscription Publication artifact file cannot be rendered")
}
func (ArtifactFile) String() string   { return "Subscription Publication artifact file: body redacted" }
func (ArtifactFile) GoString() string { return "Subscription Publication artifact file: body redacted" }

type PreparedArtifactSet struct {
	files    []ArtifactFile
	metadata artifactSetMetadata
}

func (PreparedArtifactSet) MarshalJSON() ([]byte, error) {
	return nil, errors.New("Subscription Publication artifact set cannot be rendered")
}
func (PreparedArtifactSet) String() string {
	return "Subscription Publication artifact set: bodies redacted"
}
func (PreparedArtifactSet) GoString() string {
	return "Subscription Publication artifact set: bodies redacted"
}

type artifactSetMetadata Metadata

func NewPreparedArtifactSet(bodies map[string][]byte, metadata Metadata) (PreparedArtifactSet, error) {
	bodies = cloneArtifacts(bodies)
	metadata.ArtifactSHA256 = artifactSHA256(bodies)
	internal := artifactSetMetadata(metadata)
	encoded, err := json.Marshal(internal)
	if err != nil {
		return PreparedArtifactSet{}, err
	}
	bodies["metadata"] = append(encoded, '\n')
	files := make([]ArtifactFile, len(artifactNames))
	for index, name := range artifactNames {
		files[index] = ArtifactFile{Name: name, Body: append([]byte(nil), bodies[name]...)}
	}
	return validatePreparedArtifactFiles(files)
}

func DecodePreparedArtifactSet(source io.Reader) (PreparedArtifactSet, error) {
	if source == nil {
		return PreparedArtifactSet{}, errors.New("Subscription Publication artifact bundle unavailable")
	}
	reader := tar.NewReader(io.LimitReader(source, 32<<20))
	files := make([]ArtifactFile, 0, len(artifactNames))
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil || header.Typeflag != tar.TypeReg || header.Size < 0 || header.Size > 4<<20 || header.Mode != 0o640 {
			return PreparedArtifactSet{}, errors.New("Subscription Publication artifact bundle is invalid")
		}
		body, err := io.ReadAll(reader)
		if err != nil {
			return PreparedArtifactSet{}, errors.New("Subscription Publication artifact bundle is invalid")
		}
		files = append(files, ArtifactFile{Name: header.Name, Body: body})
	}
	return validatePreparedArtifactFiles(files)
}

func DecodePreparedArtifactFiles(files []ArtifactFile) (PreparedArtifactSet, error) {
	return validatePreparedArtifactFiles(files)
}

func validatePreparedArtifactFiles(files []ArtifactFile) (PreparedArtifactSet, error) {
	if len(files) != len(artifactNames) {
		return PreparedArtifactSet{}, errors.New("Subscription Publication artifact set is incomplete")
	}
	bodies := make(map[string][]byte, len(files))
	for index, file := range files {
		if file.Name != artifactNames[index] || len(file.Body) > 4<<20 {
			return PreparedArtifactSet{}, errors.New("Subscription Publication artifact identity is invalid")
		}
		bodies[file.Name] = file.Body
	}
	var metadata artifactSetMetadata
	decoder := json.NewDecoder(bytes.NewReader(bodies["metadata"]))
	decoder.DisallowUnknownFields()
	decodeErr := decoder.Decode(&metadata)
	address, addressErr := netip.ParseAddr(metadata.SelectedAddress)
	_, validAction := clientAccessEffect(metadata.ClientAccessAction)
	if decodeErr != nil || decoder.Decode(&struct{}{}) != io.EOF || metadata.Schema != "sbxr-subscription-artifact-set-v1" || !safePlanIdentity(metadata.ChangeSet) || addressErr != nil || !address.IsGlobalUnicast() || metadata.DesiredStateRevision == 0 || !validPlanSHA(metadata.DesiredStateSHA256) || !validPlanSHA(metadata.ManagedInputsSHA256) || !validPlanSHA(metadata.RelevantChecksums.ConnectionProfiles) || !validPlanSHA(metadata.RelevantChecksums.Subscription) || metadata.Compatibility != string(CurrentCompatibilityDefinition) || metadata.ProfileCount < 0 || metadata.ProfileCount > 6 || strings.Join(metadata.Representations, ",") != strings.Join(artifactNames[:7], ",") || !validRelease(metadata.ReleaseIdentity) || !validAction || !metadata.ValidationComplete || !validArtifactOmissions(metadata.Omissions, metadata.ProfileCount) || !validArtifactSHA256(metadata.ArtifactSHA256, bodies) {
		return PreparedArtifactSet{}, errors.New("Subscription Publication artifact metadata is invalid")
	}
	decoded, err := base64.StdEncoding.DecodeString(string(bodies["base64"]))
	if err != nil || !bytes.Equal(decoded, bodies["raw"]) || !bytes.Equal(bodies["base64"], bodies["v2rayn"]) || !bytes.Equal(bodies["base64"], bodies["shadowrocket"]) || !bytes.Equal(bodies["karing"], bodies["sing-box"]) || !json.Valid(bodies["sing-box"]) || len(bodies["mihomo"]) == 0 {
		return PreparedArtifactSet{}, errors.New("Subscription Publication artifact bodies are inconsistent")
	}
	count := 0
	if len(bodies["raw"]) > 0 {
		count = strings.Count(string(bodies["raw"]), "\n") + 1
	}
	if count != metadata.ProfileCount {
		return PreparedArtifactSet{}, errors.New("Subscription Publication artifact count is inconsistent")
	}
	clone := make([]ArtifactFile, len(files))
	for index, file := range files {
		clone[index] = ArtifactFile{Name: file.Name, Body: append([]byte(nil), file.Body...)}
	}
	return PreparedArtifactSet{files: clone, metadata: metadata}, nil
}

func (set PreparedArtifactSet) Bundle() ([]byte, error) {
	if len(set.files) != len(artifactNames) {
		return nil, errors.New("Subscription Publication artifact set unavailable")
	}
	var bundle bytes.Buffer
	writer := tar.NewWriter(&bundle)
	for _, file := range set.files {
		if err := writer.WriteHeader(&tar.Header{Name: file.Name, Mode: 0o640, Size: int64(len(file.Body)), Typeflag: tar.TypeReg, Format: tar.FormatPAX}); err != nil {
			return nil, err
		}
		if _, err := writer.Write(file.Body); err != nil {
			return nil, err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return bundle.Bytes(), nil
}

func (set PreparedArtifactSet) Files() []ArtifactFile {
	files := make([]ArtifactFile, len(set.files))
	for index, file := range set.files {
		files[index] = ArtifactFile{Name: file.Name, Body: append([]byte(nil), file.Body...)}
	}
	return files
}

func (set PreparedArtifactSet) GenerationID() string {
	return fmt.Sprintf("revision-%020d-%s", set.metadata.DesiredStateRevision, set.metadata.DesiredStateSHA256[:12])
}

func (set PreparedArtifactSet) SelectedAddress() string { return set.metadata.SelectedAddress }

func (set PreparedArtifactSet) AgreesWith(binding systemchanges.StateTransactionBinding) bool {
	release := set.metadata.ReleaseIdentity
	return set.metadata.ChangeSet == binding.ChangeSet && set.metadata.DesiredStateRevision == binding.CandidateRevision && set.metadata.DesiredStateSHA256 == binding.CandidateSHA256 && release.Repository == binding.CandidateRelease.Repository && release.Tag == binding.CandidateRelease.Tag && release.Commit == binding.CandidateRelease.Commit && release.ReleaseIndexSHA256 == binding.CandidateRelease.ReleaseIndexSHA256
}

func validArtifactOmissions(omissions []Omission, profileCount int) bool {
	valid := map[string]bool{"vless-reality-vision": true, "vless-xhttp": true, "vless-websocket": true, "hysteria2": true, "tuic": true, "anytls": true}
	seen := map[string]bool{}
	for _, omission := range omissions {
		if !valid[omission.ID] || seen[omission.ID] {
			return false
		}
		seen[omission.ID] = true
	}
	return len(omissions)+profileCount == 6
}

func artifactSHA256(bodies map[string][]byte) map[string]string {
	digests := make(map[string]string, len(artifactNames)-1)
	for _, name := range artifactNames[:7] {
		digest := sha256.Sum256(bodies[name])
		digests[name] = hex.EncodeToString(digest[:])
	}
	return digests
}

func validArtifactSHA256(want map[string]string, bodies map[string][]byte) bool {
	if len(want) != len(artifactNames)-1 {
		return false
	}
	for name, got := range artifactSHA256(bodies) {
		if want[name] != got {
			return false
		}
	}
	return true
}

func safePlanIdentity(value string) bool { return identityPattern.MatchString(value) }

func cloneArtifacts(source map[string][]byte) map[string][]byte {
	clone := make(map[string][]byte, len(source))
	for name, body := range source {
		clone[name] = append([]byte(nil), body...)
	}
	return clone
}

func BundleSHA256(bundle []byte) string {
	digest := sha256.Sum256(bundle)
	return hex.EncodeToString(digest[:])
}

func Names() []string { return append([]string(nil), artifactNames...) }
