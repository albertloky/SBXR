//go:build ignore

// Run from the repository root with Go 1.26.6. Fixed public test inputs only.
package main

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/albertloky/SBXR/internal/proxyinstallation/adapter/singbox"
)

type identity struct {
	Name       string `json:"name"`
	UUID       string `json:"uuid"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	ShortID    string `json:"short_id"`
}

type validation struct {
	identity
	Valid bool `json:"valid"`
}

func main() {
	output := "tests/testdata/identity_generation"
	if len(os.Args) == 2 {
		output = os.Args[1]
	}
	makeIdentity := func(name, privateHex string) identity {
		privateBytes, err := hex.DecodeString(privateHex)
		if err != nil {
			panic("fixture hex refused")
		}
		private, err := ecdh.X25519().NewPrivateKey(privateBytes)
		if err != nil {
			panic("fixture key refused")
		}
		return identity{name, "12345678-1234-4234-8234-123456789abc", base64.RawURLEncoding.EncodeToString(private.Bytes()), base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes()), "0102abcd"}
	}
	identities := []identity{
		makeIdentity("zero", strings.Repeat("00", 32)),
		makeIdentity("sequential", "1415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30313233"),
		makeIdentity("rfc7748-alice", "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"),
		makeIdentity("rfc7748-bob", "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"),
		makeIdentity("all-ff", strings.Repeat("ff", 32)),
	}
	var cases []validation
	add := func(name string, mutate func(*identity)) {
		candidate := identities[0]
		candidate.Name = name
		mutate(&candidate)
		id := singbox.Identity{UUID: candidate.UUID, PrivateKey: candidate.PrivateKey, PublicKey: candidate.PublicKey, ShortID: candidate.ShortID}
		cases = append(cases, validation{candidate, singbox.New().ValidIdentity(id)})
	}
	add("canonical", func(*identity) {})
	add("uppercase-short-id", func(v *identity) { v.ShortID = "0102ABCD" })
	add("private-crlf", func(v *identity) { v.PrivateKey = v.PrivateKey[:3] + "\r\n" + v.PrivateKey[3:] })
	add("public-crlf", func(v *identity) { v.PublicKey = "\n" + v.PublicKey + "\r\n" })
	add("private-unused-bits", func(v *identity) { v.PrivateKey = strings.Repeat("A", 42) + "B" })
	add("public-unused-bits", func(v *identity) { v.PublicKey = v.PublicKey[:42] + "R" })
	add("private-padding", func(v *identity) { v.PrivateKey += "=" })
	add("public-padding", func(v *identity) { v.PublicKey += "=" })
	add("private-space", func(v *identity) { v.PrivateKey = " " + v.PrivateKey })
	add("public-space", func(v *identity) { v.PublicKey += " " })
	add("private-tab", func(v *identity) { v.PrivateKey = "\t" + v.PrivateKey })
	add("private-standard-alphabet", func(v *identity) { v.PrivateKey = "/" + v.PrivateKey[1:] })
	add("public-standard-alphabet", func(v *identity) { v.PublicKey = "+" + v.PublicKey[1:] })
	add("private-too-short", func(v *identity) { v.PrivateKey = v.PrivateKey[:42] })
	add("private-too-long", func(v *identity) { v.PrivateKey += "A" })
	add("public-too-short", func(v *identity) { v.PublicKey = v.PublicKey[:42] })
	add("public-too-long", func(v *identity) { v.PublicKey += "A" })
	add("mismatched-public-key", func(v *identity) { v.PublicKey = identities[2].PublicKey })
	add("zero-public-key", func(v *identity) { v.PublicKey = strings.Repeat("A", 43) })
	add("uppercase-uuid", func(v *identity) { v.UUID = strings.ToUpper(v.UUID) })
	add("wrong-uuid-version", func(v *identity) { v.UUID = "12345678-1234-3234-8234-123456789abc" })
	add("wrong-uuid-variant", func(v *identity) { v.UUID = "12345678-1234-4234-c234-123456789abc" })
	add("uuid-trailing-lf", func(v *identity) { v.UUID += "\n" })
	add("uuid-empty", func(v *identity) { v.UUID = "" })
	add("uuid-unicode", func(v *identity) { v.UUID = "💣" })
	add("short-id-too-short", func(v *identity) { v.ShortID = "0102ab" })
	add("short-id-too-long", func(v *identity) { v.ShortID += "00" })
	add("short-id-invalid", func(v *identity) { v.ShortID = "0102abcg" })
	add("short-id-unicode", func(v *identity) { v.ShortID = "💣💣" })
	body, err := json.MarshalIndent(struct {
		Identities []identity   `json:"identities"`
		Validation []validation `json:"validation"`
	}{identities, cases}, "", "  ")
	if err != nil || os.WriteFile(filepath.Join(output, "go-vectors.json"), append(body, '\n'), 0644) != nil {
		panic("fixture output failed")
	}
}
