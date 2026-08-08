// Package subscriptionpublication owns deterministic client representation
// rendering and later atomic publication.
//
// Its Interface renders one complete typed Connection Profiles source into
// byte-stable raw, standard-base64, v2rayN, Mihomo, sing-box, and Karing
// artifacts. It preserves the fixed URI and structured-document contracts,
// canonical order, stable routing references, deliberate omissions, safe
// encoding, IPv6, and normal TLS verification. Karing receives the validated
// five-Connection-Profile sing-box document; both representations explicitly
// report VLESS XHTTP as Not offered rather than substituting another Connection
// Profile. Caller-supplied pinned Mihomo and sing-box validators must accept the
// full documents. Rendering fails closed with a secret-safe error when
// validation or any required fact or Client Access Value is unavailable.
// Artifact bodies require explicit field access; ordinary Go formatting and
// JSON rendering remain redacted.
//
// The package does not serve subscriptions, read Desired State, mutate
// Connection Profiles, expose credentials through diagnostics, substitute an
// unsupported Connection Profile, or claim maintained-client or Owner Acceptance.
package subscriptionpublication
