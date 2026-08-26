# Software Lifecycle

Software Lifecycle is one of SBXR's two product Modules. Its Owner-facing Interface remains exactly:

```go
Status(context.Context) Result
Check(context.Context, ProgressReporter) Result
Update(context.Context, ProgressReporter) Result
Recover(context.Context, ProgressReporter) Result
```

The Module owns installed-state proof, GitHub's qualified Latest release, Release Sequence ordering, the mutation lock, two-checkpoint update, rollback, forward completion, and recovery. The V3 numbered terminal menu calls Proxy Installation directly.

The durable MVP paths are `/usr/local/bin/sbxr` and `/var/lib/sbxr/installed.json`. Transaction work stays under `/var/lib/sbxr` and is removed at a verified terminal result.

The public GitHub Adapter admits exactly four release assets and keeps `github.com/sigstore/sigstore-go` plus `github.com/klauspost/compress` behind that boundary. See [`../../acceptance/RELEASE.md`](../../acceptance/RELEASE.md) for release qualification.
