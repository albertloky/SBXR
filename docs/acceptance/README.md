# Acceptance documentation

## Current procedure

[MVP live acceptance](mvp-live-acceptance.md) is the current clean-install
procedure for `mvp-live-v1`. It covers the five normal journeys and the explicit
operator observation handoff. Use it with [ADR-0023](../adr/0023-mvp-live-acceptance.md).

## Historical material

[v4-operator-procedures.md](v4-operator-procedures.md) and the companion
`evidence-*.md` files describe the historical 25-scenario V4 protocol. They
remain useful when reading or repairing a named V4 attempt; they are not a
routine MVP rehearsal or live checklist. [v3-packaged-live.md](v3-packaged-live.md)
and the earlier dated procedure files also retain their named historical scope.
The V4 producer was retired from the working tree. Its exact source remains
available at [commit `0859e96`](https://github.com/albertloky/SBXR/tree/0859e964b66d10deb5768a372b09ca5903332553/.github/scripts/v3-operator),
while current Go readers and validators preserve historical-record meaning.

Files with release versions, dates, issue numbers, or `diagnostic` in their name
are reports of individual attempts. They do not prove current host state,
candidate readiness, or release acceptance.
