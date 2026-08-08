// Package subscriptionpublication owns deterministic client representation
// rendering and later atomic publication.
//
// Its Interface renders one complete typed Connection Profile source into
// byte-stable raw, standard-base64, v2rayN, Shadowrocket candidate, Mihomo,
// sing-box, and Karing artifacts. It preserves the fixed URI and structured-
// document contracts, canonical order, stable routing references, deliberate
// omissions, safe encoding, IPv6, and normal TLS verification. Karing receives
// the validated five-Connection-Profile sing-box document; both representations
// explicitly report enabled VLESS XHTTP as Not offered rather than substituting
// another Connection Profile; deliberate disablement takes precedence and is
// reported as Disabled. Shadowrocket receives the six-URI base64 candidate, but
// every rendered Connection Profile remains pending Owner Acceptance.
// Caller-supplied pinned Mihomo and sing-box validators must accept the full
// documents. Rendering fails closed with a secret-safe error when validation or
// any required fact or Client Access Value is unavailable. Artifact bodies
// require explicit field access; ordinary Go formatting and JSON rendering
// remain redacted.
//
// View returns only token-free publication status, the exact seven named
// representation identities, actual counts and omissions, the selected
// subscription address, conservative Base64 fallback metadata, and agreement
// with proven Desired State. Stale compatibility definitions require
// regeneration. It returns no token or generated body, and User-Agent is never
// authentication, authorization, or compatibility proof.
//
// The package does not serve subscriptions, read Desired State, mutate
// Connection Profiles, expose credentials through diagnostics, substitute an
// unsupported Connection Profile, or claim maintained-client or Owner Acceptance.
package subscriptionpublication
