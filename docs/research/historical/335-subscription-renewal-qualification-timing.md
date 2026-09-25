# Subscription Link renewal qualification timing

Research for [Define Subscription Link Release Qualification evidence](https://github.com/albertloky/SBXR/issues/335), checked 2026-08-31. This note supplies facts for an Owner decision. It does not change the acceptance contract or prove any VPS behavior.

## Verified upstream behavior

- Let's Encrypt IP certificates use the `shortlived` profile and have a 160-hour validity period. Record the actual certificate `NotBefore` and `NotAfter`; an elapsed-time budget must name its origin. [Let's Encrypt announcement](https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability)
- Let's Encrypt recommends checking ACME Renewal Information (ARI) at least twice daily. ARI supplies the renewal window. Its recommended fallback for certificates shorter than 10 days is half their lifetime. [Integration Guide](https://letsencrypt.org/docs/integration-guide/#when-to-renew)
- Certbot 5.7.0 selects a random time inside the returned ARI window. That time is not an invariant 80-hour deadline. [ACME client implementation](https://github.com/certbot/certbot/blob/v5.7.0/acme/src/acme/client.py)
- Certbot 5.7.0 renews when its ARI-selected time has passed. It uses the half-lifetime fallback only when no ARI time and no explicit `renew_before_expiry` value applies. For a 160-hour certificate the fallback is `NotBefore + 80 hours`. ARI retry caching can skip a query and return no ARI time on that invocation; request errors also return no ARI time. A valid future ARI time suppresses the default fallback on that invocation. Noninteractive renewal adds a random sleep between 1 and 480 seconds before the first renewal's hooks. Force renewal and dry run bypass ordinary due selection. These facts are specific to the inspected release; verify the installed supported version. [Certbot renewal implementation](https://github.com/certbot/certbot/blob/v5.7.0/certbot/src/certbot/_internal/renewal.py)
- The official Certbot 5.7.0 snap defines `certbot -q renew` as a oneshot app with `timer: 00:00~24:00/2`, described as approximately twice daily with randomization. Do not treat this as an exact 12-hour interval. Two randomized half-day slots can be almost 24 hours apart. This last bound is a scheduling inference, not an availability guarantee. Inspect the generated timer on the Acceptance VPS. [Official snap definition](https://github.com/certbot/certbot/blob/v5.7.0/snap/snapcraft.yaml)
- Snap's timer launcher parses the schedule and checks whether the current time is included. Outside the schedule it returns success without running the application. This is a general guard; the Certbot all-day schedule must be evaluated as actually installed. A successful manual systemd start alone proves neither Certbot execution nor automatic timer activation. [Snap launcher source](https://github.com/canonical/snapd/blob/master/cmd/snapd/cli/cmd_run.go)

## Evidence boundaries

| Action | What it can establish | What it does not establish |
| --- | --- | --- |
| `certbot renew --dry-run` | Staging issuance with the selected renewal configuration; pre/post hooks normally execute. | Production replacement, natural due selection, or automatic timer activation. |
| Dry run with `--run-deploy-hooks` | Deploy-hook execution after successful simulation, using the current active certificate. | Activation of the temporary test certificate or a new production certificate. |
| Forced production renewal | Actual replacement and deployment, if separately verified. | The ordinary due decision or natural scheduler activation. |
| Manual start of the snap systemd service | Launcher and downstream execution, only if evidence with a verified origin proves they ran. | The timer firing by itself. |
| Natural scheduled renewal | Due selection, automatic activation, production issuance, and deployment, when each step has evidence. | Safe recovery from every injected failure. Those need separate scenarios. |

Dry-run behavior and hook semantics come from the [Certbot User Guide](https://eff-certbot.readthedocs.io/en/stable/using.html#testing). The distinctions in the last column are qualification inferences from those documented behaviors and the source above.

## Proposed policy, not an upstream promise

Require each unchanged candidate to complete one real, naturally due production renewal through the installed official snap schedule. This costs days of observation. No staging run, forced invocation, clock change, protected configuration edit, or hidden test mode can replace that proof.

Recommend a fixed cap at the original certificate's `NotBefore + 120 hours`, including post-renewal checks. This leaves 40 hours before a 160-hour certificate expires. A 144-hour cap gives 24 hours more observation but leaves only 16 hours before expiry. Neither value is guaranteed by ARI or the snap scheduler. The choice is an acceptance budget: failure to obtain the required proof within it fails qualification. Do not silently extend it when an ARI window or provider delay falls beyond it.

Start evidence collection at issuance; record the UTC deadline immediately. Keep the same candidate bytes and Release Identity. A renewal creates a new certificate but does not restart the qualification clock. Retain durable Renewal Attempt Evidence and secret-safe typed facts with verified origins: original fingerprint and validity times, Certbot version and snap revision, installed timer/service identity and relevant schedule facts, natural activation, renewal outcome, replacement fingerprint/validity, and outside HTTPS proof that the service presents the replacement. Verify the unchanged Subscription Link still works. Do not retain raw renewal logs or raw captures; journal entries alone do not prove the renewal outcome.

An unexpected renewal failure stops qualification under the existing candidate-failure rule. A later automatic retry cannot erase that failure. Whether a scheduled recovery after an intentionally injected failure belongs in a separate scenario is a distinct decision; it must not be confused with this uninterrupted success proof.

Remaining uncertainty: no Acceptance VPS or issued certificate was inspected. Its actual ARI responses, timer realization, snap revision, and supported Certbot behavior must be captured during qualification. This research does not predict a guaranteed renewal timestamp.
