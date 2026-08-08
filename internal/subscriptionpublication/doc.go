// Package subscriptionpublication owns deterministic client representation
// rendering and later atomic publication.
//
// Its Interface renders one complete typed Connection Profiles source into
// byte-stable raw, standard-base64, and v2rayN artifacts. It preserves the six
// fixed URI contracts, canonical order, deliberate omissions, safe component
// encoding, bracketed IPv6, and normal TLS verification. Rendering fails closed
// with a secret-safe error when any required fact or Client Access Value is
// unavailable. Artifact bodies require explicit field access; ordinary Go
// formatting and JSON rendering remain redacted.
//
// The package does not serve subscriptions, read Desired State, mutate
// Connection Profiles, expose credentials through diagnostics, substitute an
// unsupported profile, or claim maintained-client or Owner Acceptance.
package subscriptionpublication
