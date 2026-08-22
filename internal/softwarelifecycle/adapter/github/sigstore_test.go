package github

import (
	"os"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/root"
)

func TestSigstoreVerifierAcceptsGitHubAttestationBundle(t *testing.T) {
	body, err := os.ReadFile("testdata/github-attestation.bundle")
	if err != nil {
		t.Fatal(err)
	}
	trustedRoot, err := root.NewTrustedRootFromJSON(trustedRootJSON)
	if err != nil {
		t.Fatal(err)
	}
	qualificationTrustedRoot, err := root.NewTrustedRootFromJSON(qualificationTrustedRootJSON)
	if err != nil {
		t.Fatal(err)
	}
	digest := "0add26026bed41b9bebd770353e6d4249cf30bbf3090c618e59f619b0c30d476"
	statement, err := sigstoreVerifier(trustedRoot, qualificationTrustedRoot)(body, "sha256", digest)
	if err != nil {
		t.Fatal(err)
	}
	if !qualificationStatementBinds(statement, digest) {
		t.Fatal("statement does not bind")
	}
}
