# Private Subscription Serving

`Prepare`, `Inspect`, and `Serve` are the concrete private Module boundary.
The sing-box Adapter supplies typed Client Access Values; the Module never
imports Proxy Installation or publishes durable state. `Prepare` returns an
immutable state after exact profile, credential-generation and trusted TLS
validation. `Inspect` separates certificate validity from runtime knowledge:
a prepared state alone does not prove a running service. A stopped result is
published only after the listener and all accepted connections have ended.

The artifact is the exact single VLESS REALITY URI from #333, with one LF,
ordered fields, percent encoding and a 4,096-byte ceiling. Authentication uses
the exact unescaped `/s/` path, canonical 43-character base64url encoding,
SHA-256 and fixed-length constant-time comparison. HTTP/1.1 GET is the only
accepted request. Query strings, bodies, other methods and credentials receive
the same no-store 404. No request values or raw network errors are logged.

## Network bounds

- Eight executing workers, counted from accepted connection through TLS,
  header read, response write and close. A stalled handshake also occupies one.
- One additional synchronous overload responder can complete TLS and emit
  generic 503, never an artifact. It has a one-second total deadline and cannot
  spawn further work. The accept loop pauses until it ends.
- Every normal connection has one five-second absolute deadline covering TLS,
  headers and writing. Header input is limited to 8,192 bytes. There is no
  keep-alive, pipelining service, HTTP/2, body draining or background handler.
- Rate accounting starts after TLS, before parsing headers. The actual remote
  address is the only key. Each source has a burst of six, replenished at one
  per ten seconds. There are at most 1,024 entries; ten idle minutes expire an
  entry. Full tables reject unknown sources with the same generic 429.
- 429 and 503 carry `Retry-After: 10`. No credential or digest is a counter key.
- Cancellation or the earliest loaded chain expiry closes the listener and all
  accepted sockets, then joins workers before `Serve` returns. Already sent
  bytes and client caches cannot be revoked. The service stop limit is ten
  seconds with control-group termination as the operating-system backstop.

Invalid replacement preparation does not change a running immutable state.
There is no in-process file reload. A valid replacement is prepared and then
activated by Proxy Installation in its later reviewed/standing-authority path.

## Protected production role

The root-only executable recognizes only the fixed private
`--subscription-serving` argument. The argument is not authorization. Startup
requires the existing whole-host lock, a verified installed pair, the complete
supported Ownership Record, no pending/final authority, recorded IPv4, exact
configuration, certificate generation, fixed unit, private cgroup membership,
zero process capabilities, no-new-privileges and inaccessible credential,
staging, proc and host-control paths. It binds only the recorded IPv4 TCP 8443.
Missing or conflicting facts refuse silently and create no state.

The fixed systemd unit denies access to the entire credential staging directory,
not a list of currently known candidates. It also denies proc and systemd/D-Bus
control paths, preventing alternate host-root lookup and host-control access.
It has no access log, output capture, environment credential, runtime artifact
file or certificate-key copy. Certificate loading reads the four exact archive
files through bounded protected descriptors and checks their selected digests,
the fullchain/leaf/chain relationship and the exact canonical symlink targets.
TLS validates the key pair, exact sole IP SAN, chain and validity separately.

## Supported authority and removal slice

#347 adds optional schema-2 `serving` authority: `link_id`,
`credential_sha256`, `certificate_generation`, and four ordered
`certificate_sha256` values (`cert`, `chain`, `fullchain`, `privkey`). The
complete ordered resource/provenance inventory includes the fixed unit, token,
empty protected staging directory, two lineage directories and eight exact
archive-file/canonical-link entries. There is no separate authority file.

This is a runtime-only footprint. Only idle Running and committed removal are
admitted. A renewal configuration, enabled-unit link, override, extra generation,
unknown staging/state, or pending capability operation refuses. Owner
enablement remains disabled. Subscription Capability Status remains
`Problem detected` because this slice cannot prove managed renewal; a working
proxy remains independently `Running`. #348–#350 must extend the complete
contract before introducing their writers, creation, enablement and recovery.

Before committing removal, the Host Adapter locks all three existing official
Certbot directory-lock inodes with nonblocking POSIX locks under whole-host
authority. Missing/unsafe/busy locks refuse without changing durable authority
or creating/replacing shared files. The commitment retains all serving
provenance and the exclusion remains held through cleanup. Finish removal
reacquires that same exclusion. It stops the fixed service, proves cgroup-v2 descendant quiescence and
listener closure, removes only exact owned material with directory sync after
each deletion, reloads systemd, and proves absence before proxy/software
deletion. Retry re-observes partial deletions; it never restores serving or
generates a credential. Unrelated lineages, shared locks and accounts remain.
The existing exact-finisher restoration parser accepts this complete canonical
record without changing legacy schema-1 or subscription-absent schema-2 rules.

## Evidence boundary

Automated checks use real TLS with a test trust root, owning Module/Adapter
boundaries, production command construction, removal recovery and restoration.
The successful private dispatch composition uses the approved test Host Adapter
and a test trust root while crossing real profile extraction and HTTPS serving.
Linux-only subprocess checks exercise actual inaccessible mounts and capability
removal with synthetic cgroup membership; they explicitly skip without root
mount capability. This is not actual systemd service launch, public CA trust,
packaged VPS acceptance, or Karing acceptance. Those remain Release Qualification
obligations, not claims made by a passing unit suite.
