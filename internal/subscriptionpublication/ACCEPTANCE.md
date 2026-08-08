# Subscription Publication acceptance

This procedure covers issue #109: deterministic raw, base64, and v2rayN rendering from one complete typed Connection Profile source.

## Module Verification — automated

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
- `SUBSCRIPTION-PUBLICATION-OMISSION`: a disabled profile's exact omission fact produces no URI and no substituted profile.
- `SUBSCRIPTION-PUBLICATION-SECRETS`: independent credential and path markers reach only their own URI; ordinary formatting, JSON rendering, and errors expose no body or Client Access Value.

## Seam Verification — reviewed fixtures

`TestRenderProducesDeterministicRawBase64AndV2RayN` parses every complete URI with Go's maintained `net/url` parser and compares it with literal reviewed fixtures for all six contracts. This is `SUBSCRIPTION-PUBLICATION-PARSER` evidence. It proves URI syntax and field preservation, not import or connectivity in v2rayN or any other maintained client.

## Evidence record

The issue comment records only the command, Passed or Failed status, stable check codes, profile counts, omission counts, parser name, and commit SHA. It must not contain a URI body, credential, subscription token, complete URL, QR data, secret-derived checksum, or client-support claim.

| Acceptance stage | Status for this slice |
|---|---|
| Module Verification | Passed only when the focused command above passes. |
| Seam Verification | Passed only for the reviewed `net/url` fixtures above. |
| Integrated Verification | Pending — complete artifact-set activation and Subscription Serving are later slices. |
| Codex Live Acceptance | Pending — no maintained client import or connection was run here. |
| Owner Acceptance | Pending — no maintained Owner client or device was used here. |

Passing this procedure is Module evidence for issue #109. It is not Module Acceptance for parent issue #108 and not Release Qualification.
