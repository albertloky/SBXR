// Package subscriptionpublication owns deterministic client representation
// rendering and later atomic publication.
//
// Its Interface renders one complete typed Connection Profiles source into
// byte-stable raw, standard-base64, v2rayN, and Mihomo artifacts. It preserves
// the six fixed URI and Mihomo contracts, canonical order, stable routing
// references, deliberate omissions, safe encoding, IPv6, and normal TLS
// verification. A caller-supplied pinned Mihomo validator must accept the full
// document. Rendering fails closed with a secret-safe error when validation or
// any required fact or Client Access Value is unavailable. Artifact bodies
// require explicit field access; ordinary Go formatting and JSON rendering
// remain redacted.
//
// The package does not serve subscriptions, read Desired State, mutate
// Connection Profiles, expose credentials through diagnostics, substitute an
// unsupported Connection Profile, or claim maintained-client or Owner Acceptance.
package subscriptionpublication
