# Certificate Lifecycle

Certificate Lifecycle owns two fixed certificate lineages:

- `sbxr-ip` certifies only the selected subscription IP with the required `shortlived` profile.
- `sbxr-domain` certifies only the committed Direct TLS Hostname with the required `tlsserver` profile.

`View` reports both lineages, active serving identifiers, validity and due facts, Certbot capability, scheduler status, HTTP-01 prerequisites, exact DNS agreement, effective CAA, and secret-safe health. `Plan` binds one reviewed Owner email, explicit subscriber-agreement approval, the current State revision, fresh observations, and four typed order contracts with staging before production. The Ubuntu Adapter alone converts those contracts to the fixed command shapes, so Plans contain no raw command arguments. This slice never orders a certificate or changes DNS, CAA, firewall, certificate, service, or State material.

The production Ubuntu Adapter accepts the recommended Snap package, including the official `/usr/local/bin/certbot` → `/snap/bin/certbot` symlink, and Certbot's supported pip alternative only inside a proved Python virtual environment. It requires version `5.4` or newer and checks for `--required-profile`, `--ip-address`, `--staging`, and the three isolation-directory flags. Ubuntu Server 24.04 Certbot `2.9.0`, `--preferred-profile`, another unproved distribution, malformed output, and missing capability fail closed.

Effective CAA may be empty or may authorize `letsencrypt.org` without a method restriction or with `validationmethods=http-01`. Another issuer, another method only, a critical unknown property, `SERVFAIL`, timeout, unavailable, or contradictory facts stop in `CERTIFICATE-CAA`. SBXR never changes CAA. Because HTTP-01 does not use `_acme-challenge`, unrelated CNAME, NS, and TXT records there are reported only as ignored facts.

Staging uses separate disposable account and lineage identities plus separate config, work, and log directories under `/var/lib/sbxr/certbot/staging`, `/run/sbxr/certbot`, and `/var/log/sbxr/certbot`. Staging cannot change the production configuration directory or ordinary trust stores.
