package softwarelifecycle

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
)

const (
	payloadMetadataSchema = 1
	maxPayloadMetadata    = 8 << 20
)

var payloadTrailerMagic = []byte("SBXR-PAYLOAD-METADATA-V1")

type EmbeddedBuildIdentity struct {
	Repository    string `json:"repository"`
	Tag           string `json:"tag"`
	Commit        string `json:"commit"`
	PayloadSHA256 string `json:"payload_sha256"`
}

type EmbeddedMigration struct {
	Name          string `json:"name"`
	From          uint64 `json:"from"`
	To            uint64 `json:"to"`
	NetworkAccess bool   `json:"network_access"`
	Document      []byte `json:"document"`
}

type ComponentBaselines struct {
	Xray          string `json:"xray"`
	SingBox       string `json:"sing_box"`
	AnyTLSMinimum string `json:"anytls_minimum"`
	Cloudflared   string `json:"cloudflared"`
	Certbot       string `json:"certbot"`
	Mihomo        string `json:"mihomo"`
}

type ManagedPaths struct {
	Programs            string `json:"programs"`
	OwnerState          string `json:"owner_state"`
	SecretMaterial      string `json:"secret_material"`
	ActiveSubscriptions string `json:"active_subscriptions"`
}

type PayloadMetadata struct {
	Schema               int                   `json:"schema"`
	Build                EmbeddedBuildIdentity `json:"build"`
	Architecture         Architecture          `json:"architecture"`
	StateSchema          uint64                `json:"state_schema"`
	MinimumUpdaterSchema uint64                `json:"minimum_updater_schema"`
	Schemas              map[string][]byte     `json:"schemas"`
	Units                map[string][]byte     `json:"units"`
	Artifacts            map[string][]byte     `json:"artifacts"`
	Migrations           []EmbeddedMigration   `json:"migrations"`
	Baselines            ComponentBaselines    `json:"baselines"`
	Paths                ManagedPaths          `json:"paths"`
}

type PayloadMaterial struct {
	StateDefinitions map[string][]byte
	UnitSets         []map[string]string
	ArtifactSets     []map[string][]byte
}

// NewPayloadMetadata assembles the exact release-owned material supplied by
// the composition root. The owning Module rejects missing or duplicate facts.
func NewPayloadMetadata(identity EmbeddedBuildIdentity, architecture Architecture, material PayloadMaterial) (PayloadMetadata, error) {
	units := map[string][]byte{}
	for _, set := range material.UnitSets {
		for name, unit := range set {
			if _, duplicate := units[name]; duplicate {
				return PayloadMetadata{}, errors.New("duplicate managed unit")
			}
			units[name] = []byte(unit)
		}
	}
	artifacts := map[string][]byte{}
	for _, set := range material.ArtifactSets {
		for name, body := range set {
			if _, duplicate := artifacts[name]; duplicate {
				return PayloadMetadata{}, errors.New("duplicate qualification artifact")
			}
			artifacts[name] = append([]byte(nil), body...)
		}
	}
	metadata := PayloadMetadata{
		Schema: 1, Build: identity, Architecture: architecture, StateSchema: 1, MinimumUpdaterSchema: 1,
		Schemas:    map[string][]byte{"desired-state-v1.schema.json": append([]byte(nil), material.StateDefinitions["desired-state-v1.schema.json"]...)},
		Migrations: []EmbeddedMigration{},
		Units:      units, Artifacts: artifacts, Baselines: QualifiedComponentBaselines(), Paths: QualifiedPaths(),
	}
	metadata.Build.PayloadSHA256 = strings.Repeat("0", 64)
	if !validPayloadMetadata(metadata) {
		return PayloadMetadata{}, errors.New("release material refused")
	}
	metadata.Build.PayloadSHA256 = ""
	return metadata, nil
}

func ManagedUnitNames() []string {
	return []string{"cloudflared.service", "sbxr-cert-renew.service", "sbxr-cert-renew.timer", "sbxr-health-check.service", "sbxr-health-check.timer", "sbxr-subscription.service", "sbxr-update-check.service", "sbxr-update-check.timer", "sing-box.service", "xray.service"}
}

func QualificationArtifactNames() []string {
	return []string{"cloudflared.yml", "sing-box.json", "subscription-base64.txt", "subscription-karing.json", "subscription-mihomo.yaml", "subscription-raw.txt", "subscription-shadowrocket.txt", "subscription-sing-box.json", "subscription-v2rayn.txt", "xray.json"}
}

func QualifiedComponentBaselines() ComponentBaselines {
	return ComponentBaselines{Xray: "v26.3.27", SingBox: "v1.13.16", AnyTLSMinimum: "v1.12.0", Cloudflared: "2026.7.3", Certbot: ">=5.4 supported distribution", Mihomo: "v1.19.29"}
}

func QualifiedPaths() ManagedPaths {
	return ManagedPaths{Programs: "/opt/sbxr/releases/", OwnerState: "/var/lib/sbxr/", SecretMaterial: "/etc/sbxr/", ActiveSubscriptions: "/var/lib/sbxr/subscriptions/current/"}
}

func StampPayload(executable []byte, metadata PayloadMetadata) ([]byte, error) {
	if len(executable) == 0 || len(executable) > MaxAssetBytes {
		return nil, errors.New("payload executable refused")
	}
	digest := sha256.Sum256(executable)
	metadata.Build.PayloadSHA256 = hex.EncodeToString(digest[:])
	if !validPayloadMetadata(metadata) {
		return nil, errors.New("payload metadata refused")
	}
	document, err := json.Marshal(metadata)
	if err != nil || len(document) == 0 || len(document) > maxPayloadMetadata {
		return nil, errors.New("payload metadata unavailable")
	}
	documentDigest := sha256.Sum256(document)
	if len(executable)+len(document)+sha256.Size+8+len(payloadTrailerMagic) > MaxAssetBytes {
		return nil, errors.New("payload executable refused")
	}
	result := make([]byte, 0, len(executable)+len(document)+sha256.Size+8+len(payloadTrailerMagic))
	result = append(result, executable...)
	result = append(result, document...)
	result = append(result, documentDigest[:]...)
	result = binary.LittleEndian.AppendUint64(result, uint64(len(document)))
	result = append(result, payloadTrailerMagic...)
	return result, nil
}

func ReadPayloadMetadata(input io.ReaderAt, size int64) (PayloadMetadata, []byte, error) {
	tailSize := int64(sha256.Size + 8 + len(payloadTrailerMagic))
	if input == nil || size <= tailSize || size > MaxAssetBytes {
		return PayloadMetadata{}, nil, errors.New("payload metadata refused")
	}
	tail := make([]byte, tailSize)
	if _, err := input.ReadAt(tail, size-tailSize); err != nil || !bytes.Equal(tail[len(tail)-len(payloadTrailerMagic):], payloadTrailerMagic) {
		return PayloadMetadata{}, nil, errors.New("payload trailer refused")
	}
	lengthOffset := len(tail) - len(payloadTrailerMagic) - 8
	length := binary.LittleEndian.Uint64(tail[lengthOffset : lengthOffset+8])
	if length == 0 || length > maxPayloadMetadata || int64(length)+tailSize >= size {
		return PayloadMetadata{}, nil, errors.New("payload metadata size refused")
	}
	documentOffset := size - tailSize - int64(length)
	document := make([]byte, length)
	if _, err := input.ReadAt(document, documentOffset); err != nil || ValidateUniqueJSON(document) != nil {
		return PayloadMetadata{}, nil, errors.New("payload metadata document refused")
	}
	wantDigest := sha256.Sum256(document)
	if !bytes.Equal(tail[:sha256.Size], wantDigest[:]) {
		return PayloadMetadata{}, nil, errors.New("payload metadata digest refused")
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var metadata PayloadMetadata
	if decoder.Decode(&metadata) != nil || decoder.Decode(&struct{}{}) != io.EOF || !validPayloadMetadata(metadata) {
		return PayloadMetadata{}, nil, errors.New("payload metadata refused")
	}
	payload := make([]byte, documentOffset)
	if _, err := input.ReadAt(payload, 0); err != nil {
		return PayloadMetadata{}, nil, errors.New("payload executable refused")
	}
	payloadDigest := sha256.Sum256(payload)
	if metadata.Build.PayloadSHA256 != hex.EncodeToString(payloadDigest[:]) {
		return PayloadMetadata{}, nil, errors.New("payload build identity refused")
	}
	return metadata, payload, nil
}

func validPayloadMetadata(value PayloadMetadata) bool {
	if value.Schema != payloadMetadataSchema || value.Build.Repository != Repository || !safeTag(value.Build.Tag) || !commitPattern.MatchString(value.Build.Commit) || !hashPattern.MatchString(value.Build.PayloadSHA256) || value.Architecture != AMD64 && value.Architecture != ARM64 || value.StateSchema != 1 || value.MinimumUpdaterSchema != 1 || !reflect.DeepEqual(value.Baselines, QualifiedComponentBaselines()) || !reflect.DeepEqual(value.Paths, QualifiedPaths()) {
		return false
	}
	if len(value.Schemas) != 1 || !validStateSchema(value.Schemas["desired-state-v1.schema.json"]) || len(value.Migrations) != 0 {
		return false
	}
	if !exactDocumentNames(value.Units, ManagedUnitNames()) || !exactDocumentNames(value.Artifacts, QualificationArtifactNames()) || !json.Valid(value.Artifacts["xray.json"]) || !json.Valid(value.Artifacts["sing-box.json"]) || !json.Valid(value.Artifacts["subscription-karing.json"]) || !json.Valid(value.Artifacts["subscription-sing-box.json"]) {
		return false
	}
	for name, want := range qualifiedArtifactSHA256 {
		digest := sha256.Sum256(value.Artifacts[name])
		if hex.EncodeToString(digest[:]) != want {
			return false
		}
	}
	for _, tag := range []string{"vless-reality-vision", "vless-xhttp", "vless-websocket"} {
		if !bytes.Contains(value.Artifacts["xray.json"], []byte(tag)) {
			return false
		}
	}
	for _, tag := range []string{"hysteria2", "tuic", "anytls"} {
		if !bytes.Contains(value.Artifacts["sing-box.json"], []byte(tag)) {
			return false
		}
	}
	for _, name := range ManagedUnitNames() {
		unit := string(value.Units[name])
		if strings.HasSuffix(name, ".timer") {
			if strings.Contains(unit, "ExecStart=") || strings.Count(unit, "Unit="+strings.TrimSuffix(name, ".timer")+".service") != 1 {
				return false
			}
		} else if strings.Count(unit, "ExecStart="+managedServiceCommands[name]) != 1 || strings.Count(unit, "ExecStart=") != 1 {
			return false
		}
	}
	return true
}

var managedServiceCommands = map[string]string{
	"cloudflared.service":       "/usr/bin/cloudflared tunnel --no-autoupdate run --token-file /etc/sbxr/cloudflared/token",
	"sbxr-cert-renew.service":   "/usr/local/bin/sbxr private certificate-renewal",
	"sbxr-health-check.service": "/usr/local/bin/sbxr private health-check",
	"sbxr-subscription.service": "/usr/local/bin/sbxr __subscription-serve",
	"sbxr-update-check.service": "/usr/local/bin/sbxr private update-check",
	"sing-box.service":          "/usr/bin/sing-box run -c /etc/sbxr/sing-box/config.json",
	"xray.service":              "/usr/bin/xray run -config /etc/sbxr/xray/config.json",
}

func validStateSchema(document []byte) bool {
	digest := sha256.Sum256(document)
	return ValidateUniqueJSON(document) == nil && hex.EncodeToString(digest[:]) == qualifiedStateSchemaSHA256
}

const qualifiedStateSchemaSHA256 = "3e1488c7c2a999883a878aa03091db89f6abe9ae32bf0739d9ebf604f3ff2edf"

var qualifiedArtifactSHA256 = map[string]string{
	"cloudflared.yml":               "f777beda7b02af53ae71a3b235a26c76ddaab447be0ba4acab5d6189669460ed",
	"sing-box.json":                 "f32b2619c234e184bdf7aa01aa13e2bb20b3a2285384f1d2c9dce2b2c3a06efe",
	"subscription-base64.txt":       "8acd3bca5ae4dbafee955d4cbed6db129760ac699119b72e80ffa30f4028a960",
	"subscription-karing.json":      "30c70352a28d0e8808212166993fcf94a6a07bafecd3b41eabfc279574bb5b80",
	"subscription-mihomo.yaml":      "f5b039787cf08fc7ba7d9dcee41601b4d2cb7cca4646c5e5023c694b6f59b089",
	"subscription-raw.txt":          "2ffe5c5a918329d710834d58f1101eb026a68a038117b36f631b2810cbda893c",
	"subscription-shadowrocket.txt": "8acd3bca5ae4dbafee955d4cbed6db129760ac699119b72e80ffa30f4028a960",
	"subscription-sing-box.json":    "30c70352a28d0e8808212166993fcf94a6a07bafecd3b41eabfc279574bb5b80",
	"subscription-v2rayn.txt":       "8acd3bca5ae4dbafee955d4cbed6db129760ac699119b72e80ffa30f4028a960",
	"xray.json":                     "b6d7ff0ec92959b8c0e9da60a69d0ecb138a81c68500b69e5c57d06959cf69d6",
}

func exactDocumentNames(documents map[string][]byte, names []string) bool {
	if len(documents) != len(names) {
		return false
	}
	for _, name := range names {
		if len(documents[name]) == 0 {
			return false
		}
	}
	return true
}
