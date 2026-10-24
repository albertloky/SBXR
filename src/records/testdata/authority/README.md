# Historical authority and current HTTP transition fixtures

All values are fixed synthetic data. `abbe4d7dbe9ca7de93afa6475975fc4cb35ef74a`
is the unchanged committed Go reference. Nothing here reads real credentials or
acts on a host, service, firewall, client, Cloudflare account or live resource.

The 67 JSON records were emitted by the production Go ownership encoder and each
accepted by `decodeOwnership` before writing. They retain schema 1/2, setup,
dedicated tunnel, current HTTP enablement checkpoints, active/compromised HTTP,
independent link rotation, runtime repair, historical HTTPS/renewal/certificate
operations, startup, eleven Client Identity cutover checkpoints, retirement,
pending transport migration and software/profile removal. Rust must decode and
re-encode every canonical byte, including field/resource order and trailing LF.
Canonical nil completed-effect slices in link rotation/repair are JSON null;
Client Identity completed effects are arrays, including an initial empty array.

`adversarial.vectors` contains 144 readable mutation descriptors. Each mutation is
independently rejected by the preserved Go decoder and Rust. They test unknown,
duplicate and escaped duplicate keys; missing/null/positional authority; exact
resources/creators; HTTP/TLS contradictions; link/configuration source-target
selection; effect order; revocation directions; retirement modes; removal bounds.
No canonical fixture is replaced by a less strict expected value.

The adjacent `.go.txt` generators are source overlays, not modifications to Go:

```sh
run="$PWD/.scratch/acceptance/rust-authority-regenerate"
mkdir -p "$run"
mkdir "$run/t"
cp src/records/testdata/authority/generate-overlay.go.txt "$run/generate-test.go"
cp src/records/testdata/authority/adversarial-overlay.go.txt "$run/adversarial-test.go"
python3 - "$run" <<'PY'
import json, pathlib, sys
root=pathlib.Path.cwd(); run=pathlib.Path(sys.argv[1])
(run/'overlay.json').write_text(json.dumps({'Replace':{
 str(root/'internal/proxyinstallation/rust_authority_fixture_test.go'):str(run/'generate-test.go'),
 str(root/'internal/proxyinstallation/rust_adversarial_test.go'):str(run/'adversarial-test.go')}}))
PY
export TMPDIR="$run/t" GOCACHE="$run/go-cache"
export SBXR_AUTHORITY_FIXTURES="$PWD/src/records/testdata/authority"
export GOTOOLCHAIN=local GOENV=off GOPROXY=off GOSUMDB=off
# Use the cached official Go 1.26.6 binary, not an unrelated global toolchain.
/path/to/go1.26.6/bin/go test -overlay "$run/overlay.json" \
  ./internal/proxyinstallation \
  -run '^TestRust(AuthorityFixtures|AdversarialAuthority)$' -count=1
```

The valid generator regenerates only named fixture files. Review diffs explicitly.
The adversarial generator reads fixtures and descriptors and rejects unexpected
Go acceptance; it writes no output. Rust checks are in `src/authority_tests.rs`
and `src/durable_tests.rs`. Use the local toolchain and task-specific target/TMPDIR
from `docs/rust-rewrite.md`. Current evidence is retained in
`.scratch/acceptance/rust-authority/`, including initial refusal, Go generation,
Go/Rust adversarial checks, publication failure injection, mutation and integrated
checks. These tests do not qualify root/systemd/Linux durability, real deployment,
actual revocation of network sessions, Karing or release provenance.
