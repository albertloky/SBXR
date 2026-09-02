---
status: accepted
---

# Permit a clean-install subscription repair release

On 2026-09-02 Albert approved a clean-install repair release after learning that
immutable `v3.1.0` cannot consume a recurring signed candidate. Add explicit
`subscription-clean-install-repair` support with empty incoming source lists.
This is a qualification-scope change, not an exception from live evidence.

Permit this scope only while the verified public Latest baseline is exactly
`albertloky/SBXR`, tag `v3.1.0`, sequence `83`, commit
`c0667a12ea914f2d0c86d73d52bfb8b40fea054a`, index SHA-256
`5e9b25cf2bd5b448c0a833b6420e165bd47a207144bb63330a62e0b9dafc3cd1`.
Bind its verified assets and release ID in the signed baseline. Require complete
release history and refuse another published stable repair release, changed baseline,
unknown history, or populated incoming sources. A failed attempt still burns its
identity; a fresh attempt may use the next unused identity while that baseline
remains unchanged. Revalidate at publication.

Reuse the clean-install scenario matrix and packaged lifecycle menu checks.
Incoming source upgrades and two-release update/recovery are explicitly Not
applicable, never Passed. Preserve every other automated, native, subscription,
Client Identity, certificate, removal, outside-network, secret-containment, and
final exact Karing obligation. Natural timer firing and naturally due renewal
remain Not observed; no multi-day wait is required. ADR-0017's live-evidence waiver
cannot apply to this scope.

An existing installation must use its exact release's reviewed Complete removal,
finish any interrupted removal, and prove Not installed before installing the
repair release. This means downtime, new credentials, and new client setup. Do
not edit old packages or protected authority, install over remaining state, or
call removal plus installation an upgrade. Subsequent releases return to normal
recurring qualification against the repaired source package. No stable release
is authorized merely by this decision; it must satisfy the retained gates.
