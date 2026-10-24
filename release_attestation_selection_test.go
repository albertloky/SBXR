package architecture_test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestStableAttestationObservationSummarizesEveryInitiator(t *testing.T) {
	body, err := os.ReadFile(".github/workflows/stable.yml")
	if err != nil {
		t.Fatal(err)
	}
	var filter string
	for _, line := range strings.Split(string(body), "\n") {
		if strings.Contains(line, `attestation="$(jq -cS --arg commit`) {
			start, end := strings.Index(line, "'{"), strings.LastIndex(line, "}'")
			if start >= 0 && end > start {
				filter = line[start+1 : end+1]
			}
		}
	}
	if filter == "" {
		t.Fatal("missing executable attestation observation")
	}
	for _, fixture := range []struct {
		initiators []string
		want       string
	}{{nil, ""}, {[]string{"github"}, "github"}, {[]string{"github", "github"}, "github"}, {[]string{"github", "external"}, ""}, {[]string{"external", "github"}, ""}} {
		records := []map[string]string{}
		for _, initiator := range fixture.initiators {
			records = append(records, map[string]string{"initiator": initiator})
		}
		input, _ := json.Marshal(map[string]any{"attestations": records})
		command := exec.Command("jq", "-cS", "--arg", "commit", "fixture-commit", filter)
		command.Stdin = bytes.NewReader(input)
		output, err := command.CombinedOutput()
		var got struct {
			Commit, Initiator, PredicateType string
			Count                            int
		}
		// Decode the snake-case field separately to keep the assertion explicit.
		var fields map[string]any
		if err != nil || json.Unmarshal(output, &got) != nil || json.Unmarshal(output, &fields) != nil || got.Commit != "fixture-commit" || got.Count != len(records) || got.Initiator != fixture.want || fields["predicate_type"] != "release" {
			t.Fatalf("initiators %v observation = %s, %v", fixture.initiators, output, err)
		}
	}
}

func TestStableFailureUsesTheSameTaggedPublicVerifier(t *testing.T) {
	body, err := os.ReadFile(".github/workflows/stable.yml")
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(body)
	failure := workflow[strings.Index(workflow, "  finalize-failure:"):]
	for _, required := range []string{
		`cargo run --locked --offline --release --manifest-path tooling/rust-package/Cargo.toml -- verify-public-release -tag "$tag"`,
		`.outcome == "accepted" and .release_identity == $expected.release_identity and .sequence == $expected.sequence`,
		`curl -fsSL "https://github.com/$GITHUB_REPOSITORY/releases/download/$tag/$name"`,
	} {
		if !strings.Contains(failure, required) {
			t.Fatalf("failure cleanup omitted %q", required)
		}
	}
	if strings.Contains(failure, "(.attestations | length) == 1") {
		t.Fatal("failure cleanup still substitutes a raw record count for verification")
	}
	var filter string
	for _, line := range strings.Split(failure, "\n") {
		const prefix = `jq -e --argjson expected "$release" '`
		if start := strings.Index(line, prefix); start >= 0 {
			rest := line[start+len(prefix):]
			if end := strings.Index(rest, "'"); end >= 0 {
				filter = rest[:end]
			}
		}
	}
	if filter == "" {
		t.Fatal("missing executable tagged-verification assertion")
	}
	expected := `{"release_identity":{"repository":"albertloky/SBXR","tag":"v3.1.93","commit":"fixture-commit","release_index_sha256":"fixture-index"},"sequence":171}`
	for _, fixture := range []struct {
		name, outcome, identity string
		sequence                int
		want                    bool
	}{
		{"accepted exact", "accepted", "fixture-index", 171, true},
		{"refused", "refused", "fixture-index", 171, false},
		{"unavailable", "unavailable", "fixture-index", 171, false},
		{"different bytes", "accepted", "different-index", 171, false},
		{"different sequence", "accepted", "fixture-index", 170, false},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			input, _ := json.Marshal(map[string]any{"outcome": fixture.outcome, "release_identity": map[string]string{"repository": "albertloky/SBXR", "tag": "v3.1.93", "commit": "fixture-commit", "release_index_sha256": fixture.identity}, "sequence": fixture.sequence})
			command := exec.Command("jq", "-e", "--argjson", "expected", expected, filter)
			command.Stdin = bytes.NewReader(input)
			if output, err := command.CombinedOutput(); (err == nil) != fixture.want {
				t.Fatalf("tagged verification assertion = %s, %v; want accepted %v", output, err, fixture.want)
			}
		})
	}
}
