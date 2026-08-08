# Subscription Publication acceptance

This procedure covers issues #109 and #110: deterministic raw, base64, v2rayN, and six-Connection-Profile Mihomo rendering from one complete typed Connection Profile source.

## Module Verification — automated — Codex

Run:

```sh
go test ./internal/subscriptionpublication -run TestRender
```

Pass only when these stable checks all pass:

- `SUBSCRIPTION-PUBLICATION-RAW`: one URI per enabled Connection Profile, canonical order, UTF-8, LF separators, and no wrapper text.
- `SUBSCRIPTION-PUBLICATION-BASE64`: standard padded base64 decodes to the exact raw bytes.
- `SUBSCRIPTION-PUBLICATION-V2RAYN`: v2rayN bytes equal the complete base64 URI list.
- `SUBSCRIPTION-PUBLICATION-URI-FIELDS`: every fixed scheme, user-info value, address, port, query key, fragment, TLS verification value, REALITY value, XHTTP `mode=auto`, and TUIC congestion value agrees with the typed source; forbidden obfuscation and zero-RTT fields are absent.
- `SUBSCRIPTION-PUBLICATION-ENCODING`: IPv4, bracketed IPv6, reserved characters, spaces, non-ASCII labels, paths, and passwords survive a URI parse without changing value.
- `SUBSCRIPTION-PUBLICATION-DETERMINISM`: rendering the same source twice produces byte-identical raw, base64, and v2rayN output.
- `SUBSCRIPTION-PUBLICATION-OMISSION`: a disabled Connection Profile's exact omission fact produces no URI and no substituted Connection Profile.
- `SUBSCRIPTION-PUBLICATION-SECRETS`: independent credential and path markers reach only their own URI; ordinary formatting, JSON rendering, and errors expose no body or Client Access Value.
- `SUBSCRIPTION-PUBLICATION-MIHOMO-COUNT`: exactly the enabled Connection Profiles appear once with unique stable names.
- `SUBSCRIPTION-PUBLICATION-MIHOMO-FIELDS`: all six exact top-level and nested field contracts agree with the typed source; unknown or unsupported fields are refused.
- `SUBSCRIPTION-PUBLICATION-MIHOMO-GROUP`: the stable `SBXR` select group refers only to rendered Connection Profile names and `MATCH,SBXR` is the final route.
- `SUBSCRIPTION-PUBLICATION-MIHOMO-TLS`: every direct Connection Profile uses the canonical Direct TLS Hostname, verification remains enabled, TUIC 0-RTT remains disabled, and disabled Hysteria2 obfuscation is absent.
- `SUBSCRIPTION-PUBLICATION-MIHOMO-VALIDATION`: a full-document validator must accept before `Render` returns any artifact; refusal and malformed output produce one secret-safe failure.
- `SUBSCRIPTION-PUBLICATION-MIHOMO-OMISSION`: a disabled Connection Profile disappears from both `proxies` and group references without substitution; when all six are disabled, the valid document contains an empty `proxies` list and no group or rule.

## Seam Verification — reviewed fixtures — Codex

`TestRenderProducesDeterministicRawBase64AndV2RayN` parses every complete URI with Go's maintained `net/url` parser and compares it with literal reviewed fixtures for all six contracts. This is `SUBSCRIPTION-PUBLICATION-PARSER` evidence. It proves URI syntax and field preservation, not import or connectivity in v2rayN or any other maintained client.

Run the complete Mihomo document through one exact acceptance binary:

```sh
SBXR_MIHOMO_BIN=/path/to/pinned/mihomo \
SBXR_MIHOMO_VERSION=vX.Y.Z \
go test ./internal/subscriptionpublication -run TestPinnedMihomoAcceptsCompleteDocument -count=1
```

The test first checks that `mihomo -v` reports the exact required version token, then runs `mihomo -t` against the complete generated document, the all-disabled document, and malformed output in isolated temporary directories. This is `SUBSCRIPTION-PUBLICATION-MIHOMO-PINNED` evidence. A local fixture or skipped test cannot replace this command, and a pass does not prove HTTP retrieval, maintained-client import, or Connection Profile connectivity.

## Evidence record

The issue comment records only the command, Passed or Failed status, stable check codes, Connection Profile counts, omission counts, parser/validator identity, exact pinned Mihomo version, and commit SHA. It must not contain a URI or YAML body, credential, subscription token, complete URL, QR data, secret-derived checksum, raw validator output, or client-support claim.

| Acceptance stage | Owner | Status for this slice |
|---|---|---|
| Module Verification | Codex | Passed only when the focused command above passes. |
| Seam Verification | Codex | Passed for URI fixtures only until the exact pinned Mihomo command above also passes. |
| Integrated Verification | Codex | Pending — complete artifact-set activation and Subscription Serving are later slices. |
| Codex Live Acceptance | Codex | Pending — no maintained client import or connection was run here. |
| Owner Acceptance | Albert | Pending — no maintained Owner client or device was used here. |

Passing this procedure is Module evidence for issues #109 and #110. It is not Module Acceptance for parent issue #108 and not Release Qualification.
