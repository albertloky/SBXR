# Official Karing evidence for the first Subscription Artifact

Research snapshot: 2026-08-30. The current stable first-party Karing release checked here is `v1.2.23.2606`, published on 2026-08-05. The current stable sing-box release is `v1.13.20`, published on 2026-08-29. This note supports [Choose the first Karing Subscription Artifact contract](https://github.com/albertloky/SBXR/issues/333). It does not implement the artifact or qualify a live Karing client.

## Question

What exact secret-bearing Subscription Artifact should the stable HTTPS Subscription Link return so that Karing can import and refresh one SBXR VLESS REALITY Proxy Profile while Karing retains ownership of DNS, routing, TUN, and selector behavior?

## Evidence limit

Karing removed `lib/app/utils`, including its importer and HTTP downloader, from the public repository on 2025-06-09. Current lifecycle and replacement behavior remains inspectable, but exact current parsing behavior does not. Detailed format findings below use the last publicly inspectable official parser at commit `e3c19f1e`; current official documentation and releases corroborate intended V2Ray, VLESS, and sing-box compatibility, but they do not expose the current parser implementation. [Official removal commit](https://github.com/KaringX/karing/commit/3c00ed6480b10eb3a9e7b702669dd917a4c9c65e) [Current official compatibility statement](https://github.com/KaringX/karing/blob/fbaf3600e9239db14882d594907879230004921f/README.md#L9-L20) [Current official add-profile documentation](https://github.com/KaringX/karing-docu/blob/9a6b1b248ea08e67682b28a31fbc02e211333cca/docs/app-manual/add-profiles.md#L16-L26)

Consequently, static evidence can support a proposed contract and a bounded compatibility claim. It cannot replace live import and refresh against the exact packaged Karing version.

## Verified source facts

### Plain newline-separated VLESS URI content

- The last public Karing parser first tries to Base64-decode the whole body. If that fails, it parses the original content. The text parser accepts actual or escaped CRLF/LF, CR, or `|` separators, requires at least one `://`, and dispatches each `vless` item to its VLESS parser. A plain UTF-8 body containing one `vless://` URI and a final LF is inside this behavior. [Official whole-body and line-list parser](https://github.com/KaringX/karing/blob/e3c19f1eb1225dbd48a4862f0983b82d0af8de69/lib/app/utils/v2ray_txt_utils.dart#L208-L266) [Official scheme dispatch](https://github.com/KaringX/karing/blob/e3c19f1eb1225dbd48a4862f0983b82d0af8de69/lib/app/utils/v2ray_txt_utils.dart#L361-L484)
- The Karing VLESS parser reads the server and port from the URI authority; the UUID from user info; `flow`, `security`, `sni`, `type`, `fp` or `fingerprint`, `pbk`, and `sid` from query parameters; and the node name from the decoded fragment. `security=reality` enables TLS and creates REALITY options from `pbk` and `sid`. [Official Karing VLESS REALITY parser](https://github.com/KaringX/karing/blob/e3c19f1eb1225dbd48a4862f0983b82d0af8de69/lib/app/utils/v2ray_txt_utils.dart#L975-L1090)
- The upstream VLESS share-link proposal requires a valid URL, case-sensitive fields, URI-component encoding, a UUID, host, port in `1..65535`, and an encoded descriptive fragment. It defines `type`, `encryption`, `flow`, and `security`; REALITY uses `security=reality`, requires `fp` and `pbk`, and defines `sni` and `sid`. [Official XTLS VLESS share-link proposal](https://github.com/XTLS/Xray-core/discussions/716)
- The sing-box VLESS outbound schema requires `server`, `server_port`, and `uuid`; the documented flow value is `xtls-rprx-vision`. The sing-box REALITY client schema uses `public_key` and `short_id`, and the client needs uTLS enabled. These JSON field names are not URI parameter names; the share URI uses the XTLS proposal's `pbk`, `sid`, and `fp` names that Karing parses. [Official sing-box VLESS outbound documentation](https://sing-box.sagernet.org/configuration/outbound/vless/) [Official sing-box REALITY and uTLS documentation](https://sing-box.sagernet.org/configuration/shared/tls/#reality-fields)

### Whole-body Base64 URI content

- The last public Karing parser accepts a whole response body that is standard Base64, repairs missing padding with Dart's `base64.normalize`, decodes it as UTF-8, and then sends it through the same URI-list parser. This is Base64 around the complete list, not a different URI representation. [Official Base64 decode path](https://github.com/KaringX/karing/blob/e3c19f1eb1225dbd48a4862f0983b82d0af8de69/lib/app/utils/v2ray_txt_utils.dart#L208-L220)
- Base64 adds one encoding layer and increases the artifact size. It provides no secrecy because anyone with the Subscription Link can decode it. The official Karing documentation does not require Base64 for a V2Ray subscription. [Official add-profile documentation](https://github.com/KaringX/karing-docu/blob/9a6b1b248ea08e67682b28a31fbc02e211333cca/docs/app-manual/add-profiles.md#L16-L26)

### Complete sing-box client JSON

- The last public Karing JSON importer accepts a JSON object with an `outbounds` list, skips `direct`, `block`, `dns`, `selector`, and `urltest`, converts supported server outbounds into Karing proxy nodes, and fails when no usable server remains. It is an extractor, not a sing-box configuration installer. [Official supported-outbound extraction](https://github.com/KaringX/karing/blob/e3c19f1eb1225dbd48a4862f0983b82d0af8de69/lib/app/utils/singbox_json_utils.dart#L11-L125) [Official JSON entry point](https://github.com/KaringX/karing/blob/e3c19f1eb1225dbd48a4862f0983b82d0af8de69/lib/app/utils/singbox_json_utils.dart#L240-L255)
- The extractor does not import `inbounds`, TUN, DNS, logging, experimental state, or selector/urltest outbounds as the active Karing client configuration. When the user enables Karing's “keep diversion rules” option, it can translate only a limited subset of remote `route.rule_set` and `route.rules` relationships; otherwise the route conversion object is not supplied. [Official limited route conversion](https://github.com/KaringX/karing/blob/e3c19f1eb1225dbd48a4862f0983b82d0af8de69/lib/app/utils/singbox_json_utils.dart#L127-L225) [Current default `keepDiversionRules=false`](https://github.com/KaringX/karing/blob/fbaf3600e9239db14882d594907879230004921f/lib/screens/add_profile_by_link_or_content_screen.dart#L59-L76) [Current import call](https://github.com/KaringX/karing/blob/fbaf3600e9239db14882d594907879230004921f/lib/screens/add_profile_by_link_or_content_screen.dart#L241-L275)
- A complete sing-box client JSON therefore does not give the publisher precise ownership of Karing DNS, TUN, selectors, or the whole routing configuration. Karing discards most of those sections and conditionally converts a narrow routing subset. For one proxy node, the extra sections add bytes and ambiguity without adding required behavior.

### HTTP and media behavior

- The last public Karing downloader sends `Accept: */*`, requires HTTP status `200`, saves the response, and does not use the response `Content-Type` to select a parser. The auto-configuration path reads the temporary file as a string and detects the format from its content. [Official HTTP download behavior](https://github.com/KaringX/karing/blob/e3c19f1eb1225dbd48a4862f0983b82d0af8de69/lib/app/utils/http_utils.dart#L109-L142) [Official download-to-content path](https://github.com/KaringX/karing/blob/e3c19f1eb1225dbd48a4862f0983b82d0af8de69/lib/app/utils/auto_conf_utils.dart#L280-L343)
- `text/plain; charset=utf-8` is therefore the accurate media type for the proposed URI-list artifact, but it was not a parser gate in the last public implementation. `application/json; charset=utf-8` would be accurate for the JSON alternative. `application/octet-stream` is unnecessary for either.
- The inspected Karing path does not use a URL filename extension, `Content-Disposition`, `ETag`, or `Last-Modified` to select or conditionally refresh this artifact. It performs a GET of the saved URL on each manual or due refresh. Static source does not establish a current response-size or node-count maximum. The old `2 * 1024` constant truncates error telemetry; it is not an input bound. [Official telemetry truncation](https://github.com/KaringX/karing/blob/e3c19f1eb1225dbd48a4862f0983b82d0af8de69/lib/app/utils/auto_conf_utils.dart#L38-L46) [Official current refresh path](https://github.com/KaringX/karing/blob/fbaf3600e9239db14882d594907879230004921f/lib/app/modules/server_manager.dart#L579-L645)

### Naming

- Karing requires a unique non-empty profile remark and rejects a duplicate Subscription Link or duplicate remark. When no name is supplied to the add screen, it suggests one from the URL fragment, `remarks` query parameter, `name` query parameter, short HTML title, or URL host, in that order. This profile remark comes from Karing's add flow, not from the downloaded URI-list body. [Official validation](https://github.com/KaringX/karing/blob/fbaf3600e9239db14882d594907879230004921f/lib/screens/add_profile_by_link_or_content_screen.dart#L210-L238) [Official suggested-name order](https://github.com/KaringX/karing/blob/fbaf3600e9239db14882d594907879230004921f/lib/screens/add_profile_by_link_or_content_screen.dart#L148-L207)
- The VLESS node name comes from the URI fragment, then the `remarks` parameter, then `host:port`. A stable percent-encoded fragment is the artifact-controlled node name. [Official Karing VLESS naming](https://github.com/KaringX/karing/blob/e3c19f1eb1225dbd48a4862f0983b82d0af8de69/lib/app/utils/v2ray_txt_utils.dart#L1055-L1065)
- A sing-box JSON proxy outbound must have a non-empty `tag`, which becomes the Karing node tag. Duplicate tags receive suffixes. [Official sing-box tag requirement and import](https://github.com/KaringX/karing/blob/e3c19f1eb1225dbd48a4862f0983b82d0af8de69/lib/app/utils/singbox_json_utils.dart#L45-L111) [Official duplicate-tag handling](https://github.com/KaringX/karing/blob/e3c19f1eb1225dbd48a4862f0983b82d0af8de69/lib/app/utils/tag_gen.dart#L1-L23)

### Refresh and ownership

- A newly added remote profile currently defaults to a 12-hour update interval. The user can change or disable it; the edit UI clamps a non-null interval to five minutes through 365 days. Karing also exposes a manual update control. [Official default interval](https://github.com/KaringX/karing/blob/fbaf3600e9239db14882d594907879230004921f/lib/screens/add_profile_by_link_or_content_screen.dart#L59-L76) [Official interval edit bounds](https://github.com/KaringX/karing/blob/fbaf3600e9239db14882d594907879230004921f/lib/screens/my_profiles_edit_screen.dart#L404-L425) [Official manual update documentation](https://github.com/KaringX/karing-docu/blob/9a6b1b248ea08e67682b28a31fbc02e211333cca/docs/app-manual/my-profiles.md#L16-L23)
- Karing checks for due updates after VPN connection, app resume, and initialization; on PC it also checks every 30 minutes. A check refreshes only remote profiles whose saved interval has elapsed. This means “12 hours” is the default eligibility interval, not a promise that a refresh occurs at an exact wall-clock second on every platform. [Official update triggers](https://github.com/KaringX/karing/blob/fbaf3600e9239db14882d594907879230004921f/lib/app/modules/server_manager.dart#L464-L497) [Official due check](https://github.com/KaringX/karing/blob/fbaf3600e9239db14882d594907879230004921f/lib/app/modules/server_manager.dart#L579-L645)
- A successful refresh replaces the profile's imported server list. It preserves the Karing group identity and enabled state, and it preserves recorded latency only when the new node tag exactly matches the old tag. The refresh call carries the existing profile remark, URL, interval, filters, user-agent settings, route-retention choice, reload choice, latency-test choices, and download strategy back into the load path. [Official refresh inputs](https://github.com/KaringX/karing/blob/fbaf3600e9239db14882d594907879230004921f/lib/app/modules/server_manager.dart#L579-L621) [Official replacement boundary](https://github.com/KaringX/karing/blob/fbaf3600e9239db14882d594907879230004921f/lib/app/modules/server_manager.dart#L1680-L1777)
- Karing explicitly warns that edits to imported nodes are restored by profile update. The Subscription Artifact therefore owns the imported node set and its node fields. Karing owns its profile record and settings; with diversion-rule retention disabled, Karing also retains DNS, routing, TUN, and selector behavior. [Official current warning](https://github.com/KaringX/karing/blob/fbaf3600e9239db14882d594907879230004921f/lib/i18n/en.i18n.json#L628-L636)
- A parse failure returns before the successful replacement block, so the inspected current structure retains the prior server list. It also records a new update-attempt time on an update error, which can defer the next automatic attempt until the configured interval. This is source evidence for the current control flow, but a live failure-refresh test remains necessary because the parser internals are not public. [Official error and replacement control flow](https://github.com/KaringX/karing/blob/fbaf3600e9239db14882d594907879230004921f/lib/app/modules/server_manager.dart#L1710-L1777)

## Proposed exact first contract

The smallest contract supported by the evidence is:

```text
vless://<uuid>@<server>:<port>?encryption=none&flow=xtls-rprx-vision&security=reality&sni=<percent-encoded-server-name>&fp=chrome&pbk=<percent-encoded-public-key>&sid=<percent-encoded-short-id>&type=tcp#<percent-encoded-stable-proxy-profile-name>
```

The HTTPS response contract should be:

- status: `200 OK`;
- media type: `Content-Type: text/plain; charset=utf-8`;
- body: exactly one non-empty UTF-8 VLESS URI line followed by one LF;
- byte bounds: `1..4096` bytes inclusive, including the final LF;
- syntax exclusions: no BOM, CR, blank line, comment, JSON wrapper, or Base64 wrapper;
- cardinality: exactly one VLESS URI for exactly one SBXR Proxy Profile;
- naming: the URI fragment is the stable, percent-encoded SBXR Proxy Profile display name;
- security response policy: `Cache-Control: no-store` and `X-Content-Type-Options: nosniff` because the body contains the Proxy Profile credential material;
- deterministic field order: use the query order shown above even though the upstream URI proposal says field order is not significant.

The `4096`-byte limit is an SBXR contract bound, not a Karing or VLESS upstream limit. One VLESS REALITY URI fits comfortably within it. It gives the publisher and consumer a clear refusal boundary without pretending the current closed parser has a published maximum.

Use a stable node fragment across refreshes so Karing can match the old and new tag and retain latency history. Keep the Karing profile remark owner-editable. If an onboarding link must suggest the profile remark, Karing's official custom scheme supports `karing://install-config?url=<encoded-url>&name=<encoded-name>`, but that onboarding wrapper is separate from the Subscription Artifact returned by the stable HTTPS URL. [Official Karing scheme documentation](https://github.com/KaringX/karing-docu/blob/9a6b1b248ea08e67682b28a31fbc02e211333cca/docs/cooperation/scheme.md#L12-L28)

## Comparison and decision implications

| Representation | Static Karing evidence | Ownership fit | First-contract result |
| --- | --- | --- | --- |
| One plain `vless://` REALITY URI plus LF | Accepted by the last public URI-list parser; current docs and releases state V2Ray/VLESS compatibility | Artifact owns one proxy node; Karing keeps app behavior | Use |
| Whole-body Base64 of the same list | Accepted by the last public parser | Same ownership, more bytes and another encoding failure mode | Do not use |
| Complete sing-box client JSON | Last public parser extracts supported outbounds and optionally a narrow routing subset | Extra client sections are ignored or conditionally translated; it does not apply the document intact | Do not use |

The complete JSON alternative has no demonstrated benefit for this destination. The destination requires one imported and refreshable Proxy Profile and explicitly leaves DNS, routing, TUN, and selectors with Karing. The URI expresses only that authority.

## Defensible compatibility claim

Before live acceptance, the strongest defensible claim is:

> The SBXR Subscription Artifact is a bounded plain-text VLESS REALITY share URI that follows the published XTLS VLESS share-link field convention. Official Karing documentation and releases state V2Ray/VLESS subscription compatibility, and Karing's last publicly inspectable parser accepts this representation. Acceptance against the exact current packaged Karing version remains pending.

Do not claim “Karing-certified,” “verified with current Karing,” “all Karing platforms,” “all VLESS clients,” “complete sing-box configuration compatibility,” automatic refresh at an exact time, or live traffic success until the matching evidence exists.

Recent official release notes show continued VLESS conversion work after the parser became private, including VLESS/XHTTP conversion fixes and nested V2Ray VLESS/Trojan compatibility. That supports the need for exact-version live acceptance rather than promoting historical parser inspection to current binary proof. [Official v1.2.21.2409 release](https://github.com/KaringX/karing/releases/tag/v1.2.21.2409) [Official v1.2.24.2704 release](https://github.com/KaringX/karing/releases/tag/v1.2.24.2704)

## Required live Karing acceptance

Use the exact stable Karing package and platform named by the release candidate. Record the Karing version, OS/device, SBXR release identity, Subscription Link identity without exposing its secret token, and test time.

1. Start with a Karing installation that has named non-default DNS, routing, TUN, selector, update-interval, and profile settings. Capture their before state.
2. Add the stable HTTPS Subscription Link. Confirm Karing accepts `200` plus `text/plain; charset=utf-8`, creates exactly one remote profile and one VLESS REALITY node, shows the intended stable node name, and exposes manual update.
3. Validate every imported field in Karing: server, port, UUID identity by redacted fingerprint, `xtls-rprx-vision`, REALITY, SNI/server name, `chrome` fingerprint, REALITY public-key fingerprint, short ID, and TCP transport.
4. Connect from a genuinely outside network and complete the accepted traffic proof. Static import success is not traffic success.
5. Change one safe node field at the same Subscription Link, manually refresh, and confirm Karing replaces that node field while preserving the profile remark, enabled state, update interval, filters, DNS, routing, TUN, selectors, and other Karing-owned settings.
6. Restore the valid artifact, then wait for an automatic due refresh and confirm the same ownership boundary. Record when Karing became eligible and when the platform actually performed the refresh.
7. Serve an HTTP error, empty body, oversized body, malformed URI, and valid URI with a changed node fragment in controlled tests. Confirm failure does not destroy the last working node; confirm the changed fragment behaves as a node replacement and does not preserve tag-keyed latency history.
8. Re-fetch the valid artifact and prove recovery. Confirm Karing still has exactly one working node and all Karing-owned settings match the before state.

Until these rows pass, the outcome is `static-official-evidence-passed-live-karing-pending`, not current Karing compatibility.
