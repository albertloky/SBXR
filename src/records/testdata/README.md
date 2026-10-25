# Standard schema-1 compatibility fixture

`standard-schema1-go.json` is the exact newline-terminated output of the
preserved Go `newOwnershipRecord`, `recordResources`, and `ownershipBytes`
functions at commit `abbe4d7dbe9ca7de93afa6475975fc4cb35ef74a`.
An offline Go 1.26.6 test overlay generated and validated it without editing any
Go source. The generating overlay and log are retained under
`.scratch/acceptance/rust-durable/`. The release identity, configuration digest
and public IPv4 are synthetic test inputs; no credential/configuration is stored.
The Rust codec compares its complete output byte for byte against this fixture.
