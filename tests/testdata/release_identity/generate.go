// Run offline from the repository root with the preserved Go 1.26.6 toolchain.
// Only synthetic bytes; no release, signing, publication, downloads or execution.
package main

import (
	"bytes"
	"encoding/binary"
	lifecycle "github.com/albertloky/SBXR/internal/softwarelifecycle"
	"os"
	"runtime/debug"
	"strings"
)

func main() {
	const root = "tests/testdata/release_identity/"
	const tag = "v3.2.1"
	commit := strings.Repeat("b", 40)
	executable, err := lifecycle.StampReleaseExecutable([]byte("synthetic offline executable\n"), tag, commit, 193, lifecycle.AMD64)
	must(err)
	must(os.WriteFile(root+"go-stamped.bin", executable, 0644))
	assets := []lifecycle.LatestAssetProof{}
	for _, name := range lifecycle.LatestReleaseIndexedAssetNames() {
		assets = append(assets, lifecycle.LatestAssetProof{Name: name, Size: 1, SHA256: strings.Repeat("a", 64)})
	}
	index, err := lifecycle.BuildLatestReleaseIndex(tag, commit, 193, assets)
	must(err)
	must(os.WriteFile(root+"go-index-v1.json", index, 0644))
	index, err = lifecycle.BuildSubscriptionReleaseIndex(tag, commit, 193, assets, lifecycle.ReleaseSupport{Scope: lifecycle.SubscriptionCleanInstallOnly, Sources: []lifecycle.ReleaseIdentity{}, Contract: lifecycle.SubscriptionUpdateContract})
	must(err)
	must(os.WriteFile(root+"go-index-v2.json", index, 0644))
	for _, architecture := range []lifecycle.Architecture{lifecycle.AMD64, lifecycle.ARM64} {
		for _, variant := range []string{"valid", "wrong-toolchain", "duplicate-setting", "orphan-replacement"} {
			payload := syntheticELF(architecture, variant)
			accepted := lifecycle.VerifyLinuxExecutable(payload, architecture)
			if accepted != (variant == "valid") {
				panic("preserved Go verifier disagrees with fixture: " + variant)
			}
			executable, err := lifecycle.StampReleaseExecutable(payload, tag, commit, 193, architecture)
			must(err)
			must(os.WriteFile(root+"go-"+string(architecture)+"-"+variant+".bin", executable, 0644))
		}
	}
}
func must(err error) {
	if err != nil {
		panic(err)
	}
}

// Minimal, inert ELF fixtures. Their tables and compiler evidence are real wire
// structures; these bytes are never executed and are not native build evidence.
func syntheticELF(architecture lifecycle.Architecture, variant string) []byte {
	settings := []debug.BuildSetting{{Key: "CGO_ENABLED", Value: "0"}, {Key: "GOARCH", Value: string(architecture)}, {Key: "GOOS", Value: "linux"}}
	if variant == "duplicate-setting" {
		settings = append(settings, debug.BuildSetting{Key: "GOOS", Value: "linux"})
	}
	module := (&debug.BuildInfo{Path: "github.com/albertloky/SBXR/cmd/sbxr", Main: debug.Module{Path: "github.com/albertloky/SBXR", Version: "(devel)"}, Settings: settings}).String()
	if variant == "orphan-replacement" {
		module = "=>\tdep\tv1.0.0\tsum\n" + module
	}
	framed := append([]byte{0x30, 0x77, 0xaf, 0x0c, 0x92, 0x74, 0x08, 0x02, 0x41, 0xe1, 0xc1, 0x07, 0xe6, 0xd6, 0x18, 0xe6}, []byte(module)...)
	framed = append(framed, []byte{0xf9, 0x32, 0x43, 0x31, 0x86, 0x18, 0x20, 0x72, 0x00, 0x82, 0x42, 0x10, 0x41, 0x16, 0xd8, 0xf2}...)
	version := "go1.26.6"
	if variant == "wrong-toolchain" {
		version = "go1.26.5"
	}
	info := make([]byte, 32)
	copy(info, []byte("\xff Go buildinf:"))
	info[14] = 8
	info[15] = 2
	info = binary.AppendUvarint(info, uint64(len(version)))
	info = append(info, version...)
	info = binary.AppendUvarint(info, uint64(len(framed)))
	info = append(info, framed...)
	type section struct {
		name  string
		body  []byte
		kind  uint32
		flags uint64
	}
	sections := []section{{"", nil, 0, 0}, {".text", []byte("SBXR SYNTHETIC INERT ELF"), 1, 6}, {".rodata", []byte("offline fixture only"), 1, 2}, {".gopclntab", []byte{1}, 1, 2}, {".go.buildinfo", info, 1, 3}}
	names := []byte{0}
	offsets := []uint32{0}
	for _, section := range sections[1:] {
		offsets = append(offsets, uint32(len(names)))
		names = append(names, section.name...)
		names = append(names, 0)
	}
	offsets = append(offsets, uint32(len(names)))
	names = append(names, []byte(".shstrtab\x00")...)
	sections = append(sections, section{".shstrtab", names, 3, 0})
	out := make([]byte, 120)
	copy(out, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(out[16:], 2)
	machine := uint16(62)
	if architecture == lifecycle.ARM64 {
		machine = 183
	}
	binary.LittleEndian.PutUint16(out[18:], machine)
	binary.LittleEndian.PutUint32(out[20:], 1)
	binary.LittleEndian.PutUint64(out[24:], 0x400080)
	binary.LittleEndian.PutUint64(out[32:], 64)
	binary.LittleEndian.PutUint16(out[52:], 64)
	binary.LittleEndian.PutUint16(out[54:], 56)
	binary.LittleEndian.PutUint16(out[56:], 1)
	binary.LittleEndian.PutUint16(out[58:], 64)
	binary.LittleEndian.PutUint16(out[60:], uint16(len(sections)))
	binary.LittleEndian.PutUint16(out[62:], uint16(len(sections)-1))
	locations := []int{}
	for _, section := range sections {
		aligned := (len(out) + 15) &^ 15
		out = append(out, make([]byte, aligned-len(out))...)
		locations = append(locations, len(out))
		out = append(out, section.body...)
	}
	size := len(out)
	binary.LittleEndian.PutUint64(out[40:], uint64(size))
	for i, section := range sections {
		entry := make([]byte, 64)
		if i != 0 {
			binary.LittleEndian.PutUint32(entry[0:], offsets[i])
			binary.LittleEndian.PutUint32(entry[4:], section.kind)
			binary.LittleEndian.PutUint64(entry[8:], section.flags)
			binary.LittleEndian.PutUint64(entry[16:], 0x400000+uint64(locations[i]))
			binary.LittleEndian.PutUint64(entry[24:], uint64(locations[i]))
			binary.LittleEndian.PutUint64(entry[32:], uint64(len(section.body)))
			binary.LittleEndian.PutUint64(entry[48:], 16)
		}
		out = append(out, entry...)
	}
	binary.LittleEndian.PutUint32(out[64:], 1)
	binary.LittleEndian.PutUint32(out[68:], 5)
	binary.LittleEndian.PutUint64(out[80:], 0x400000)
	binary.LittleEndian.PutUint64(out[88:], 0x400000)
	binary.LittleEndian.PutUint64(out[96:], uint64(size))
	binary.LittleEndian.PutUint64(out[104:], uint64(size))
	binary.LittleEndian.PutUint64(out[112:], 1)
	if !bytes.Contains(out, []byte("SBXR SYNTHETIC")) {
		panic("fixture marker missing")
	}
	return out
}
