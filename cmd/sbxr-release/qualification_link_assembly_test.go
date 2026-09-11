package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Feed retained operator fixtures through the Python assembler and the actual
// qualification command. The manifest, boundary and first eight accepted
// scenarios come from the same V4 policy fixture used by the command tests.
// This verifies cross-language compatibility, not live observation provenance.
func testLinkOperatorAssembly(t *testing.T, binary, boundary string, manifest []byte, evidence map[string]any) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(binary, 0700); err != nil {
		t.Fatal(err)
	}
	scenarios := evidence["scenarios"].([]any)
	input := map[string]any{
		"manifest": jsonObject(t, manifest),
		"boundary": jsonObject(t, []byte(boundary)),
		"prefix":   scenarios[:8],
		"now":      scenarios[8].(map[string]any)["validated_at"],
	}
	inputPath := filepath.Join(root, "authority.json")
	if err := os.WriteFile(inputPath, []byte(qualificationDocument(t, input)), 0600); err != nil {
		t.Fatal(err)
	}
	operator, err := filepath.Abs("../../.github/scripts/v3-operator")
	if err != nil {
		t.Fatal(err)
	}
	// Freeze fixture time only in this test process. Production assembly and the
	// outside driver continue to use the original collector's real deadline.
	const script = `
import datetime, json, pathlib, sys, time
from unittest import mock
sys.path.insert(0, sys.argv[1])
from test_link_evidence import LinkFixture, assembler
from test_later_evidence import LaterFixture
authority = json.loads(pathlib.Path(sys.argv[2]).read_bytes())
epoch = int(datetime.datetime.fromisoformat(authority.pop('now').replace('Z', '+00:00')).timestamp())
for number, scenario in enumerate(('link-precommit', 'link-postcommit') + assembler.later.SCENARIOS):
    current = epoch + number * 1500
    root = pathlib.Path(sys.argv[2]).parent / scenario
    root.mkdir(mode=0o700)
    fixture_type = LinkFixture if number < 2 else LaterFixture
    fixture = fixture_type(root, scenario, now=current)
    fixture.build(authority=authority, validator=pathlib.Path(sys.argv[3]))
    class FixtureDateTime(datetime.datetime):
        @classmethod
        def now(cls, tz=None):
            return cls.fromtimestamp(current + 60, tz)
    # The request deadline is current+30: validation here exercises the signed
    # grace after completion, while all scenario operations ended in time.
    with mock.patch.object(assembler, 'datetime', FixtureDateTime), mock.patch.object(time, 'time', return_value=current + 60):
        assembler.assemble(assembler.parser().parse_args(fixture.command[2:]))
    facts = json.loads(fixture.output.read_bytes())
    authority['prefix'] = facts['detailed_evidence']['scenarios']
    assert len(authority['prefix']) == 9 + number
    row = authority['prefix'][-1]
    if number < 2:
        assert row['boundary'] == ('before-commitment' if number == 0 else 'after-commitment')
        assert row['recovery_direction'] == ('rollback' if number == 0 else 'forward')
assert len(authority['prefix']) == 25
`
	command := exec.Command("python3", "-c", script, operator, inputPath, binary)
	command.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("link operator assembly into qualification validator: %v\n%s", err, output)
	}
}
