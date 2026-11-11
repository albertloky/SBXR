# Retained build 212 contract

The existing candidate-reservations policy/check interface gains exactly one fixed
member: signed-unqualified v3.1.138/212, source
13431bc29500bf20dc108dc325590403d0ca056c, run 41958829811, release 434759360.
Its manifest digest is
30bbbeb56f16bb16ebc6be0cb2dbfa305cc16e403d0c3a609dc0918ac2591b74;
its index and four asset bindings come from the authenticated unchanged candidate.

All ten records and explicit absent release/burn refs are required. No missing,
changed, unavailable, duplicated or published draft can pass. The reserved tag,
sequence or release ID cannot be used independently by another candidate or by
publication. The current-run draft allowance cannot exempt a reserved identity.
Next-sequence allocation includes the reserved sequence; candidate admission still
checks global current history. Historical signed facts retain their old meaning.

This is source-controlled preservation only. No draft/tag/asset mutation, burn,
finalizer rerun, live operation, cleanup or publication is performed by adoption.

## Approved build 213 extension — 2026-11-06

The current policy adds exactly signed-unqualified v3.1.139/213, release 435196915,
source f067ca24e9bb0d2bc3641ad6c96d44b41dcdb6f3, run 42023983739 (verified attempt 1).
The manifest SHA-256 is
`e0ce70ea6c28537a3f8e33b1f29a6af75f0037ff87b572eb5e0cd201ffa3bc4c`;
the release-index SHA-256 is
`be311736e8d780cc382772461570a2af540d593b21e9956707cee06885a49fcf`.

| Asset | ID | Bytes | SHA-256 |
|---|---:|---:|---|
| install.sh | 713400894 | 76781 | `b1d9a300b98cf4a9b43c091df7a4df389e0ec6e095a64220d39777d130156244` |
| release-index.json | 713400892 | 609 | `be311736e8d780cc382772461570a2af540d593b21e9956707cee06885a49fcf` |
| sbxr-linux-amd64.tar.gz | 713400881 | 6236661 | `b6863602a4c4aeaaaa9e4015b0fd784cfba40a4051b007118d59970a302dc8d5` |
| sbxr-linux-arm64.tar.gz | 713400886 | 5335640 | `667326fc04d4554fcfcf5fb86d314e04bc4e14f6a307a0d9a20c975ef3e4c7aa` |

All eleven records and twenty-two explicitly absent release/burn refs are now
required; the original ten-record paragraph above records the build-212 scope.
The same refusal, no-reuse/promotion, current-run allowance and historical replay
rules apply to the additional member. Previous ten record bytes remain unchanged.
Fresh next-sequence admission includes q213 but still depends on global history;
v3.1.140/214 is prospective, not an allocated candidate. Adoption preserves the
remote draft/body/assets/signature and failed outcome; it is not a metadata lock.

## Build 214 retention — 2026-11-08

The separately approved extension binds v3.1.140/214, release 437573394, source
`3c3735dcd3ebca409ccdaba277a0d50deb0b9432`, run 42370644704 attempt 1.
Signing state is `unknown`; omit qualification_manifest_sha256. Neither the
cancelled sign job nor its empty step list supplies formal unsigned proof.
The release-index SHA-256 is
`acbe7179311bd52e2b83f9a063747a6a515c0047e754002a4bef59cd80f5fb69`.

| Asset | ID | Bytes | SHA-256 |
|---|---:|---:|---|
| install.sh | 720694599 | 76781 | `3a9276acd48156aa72bec598c7cc73c7a2fb59ac5b20cc0f606b390e5a7ccf97` |
| release-index.json | 720694593 | 609 | `acbe7179311bd52e2b83f9a063747a6a515c0047e754002a4bef59cd80f5fb69` |
| sbxr-linux-amd64.tar.gz | 720694592 | 6236680 | `2744f7f9d2c5b5fcc79f061a5b0cff2e7d288a302a1847ee17ec50f2010d1923` |
| sbxr-linux-arm64.tar.gz | 720694600 | 5335593 | `842b39c302535f6a07927e678a25f05ba028a47f13cddf12c51cf84ebe7cc9df` |

The approved policy becomes twelve exact records, q203–214, with twenty-four
explicitly absent release/burn refs. Eleven previous records and all refusal,
current-candidate allowance and historical replay semantics remain unchanged.
The earlier prospective-214 statements describe their dated preparation only;
214 is now occupied and retained, not available for reuse. Prospective 215 still
requires fresh global admission. Preserve draft/body/assets/evidence; cancellation
is a separately approved run operation, not deletion, burn or qualification.
The exact record is implemented; focused checks and fresh observation replay
passed, as did full release-tool/root checks and vet with documented macOS skips.
Exact-source CI remains pending at this checkpoint.

## Build 215 retention — 2026-11-11

The approved thirteenth record preserves signed-unqualified v3.1.141/215,
release 438186606, source `84af948bc2a1d92607aa2e6b902512b648133c43`,
run 42470439088. Its authenticated manifest SHA-256 is
`8a9a38a86f2e12b92689c715021d02b51b7aab402a2735b3329231c1cad6f332`.

| Asset | ID | Bytes | SHA-256 |
|---|---:|---:|---|
| install.sh | 723667643 | 76781 | `ab42ff6477a5fd205580341837e5a1d07db7fd76c8e57052778ada51f49f9f66` |
| release-index.json | 723667644 | 609 | `07d718204039c8026b42157097aca1c8bf9c3ee537d6c3a4b25bf098c5e33d0b` |
| sbxr-linux-amd64.tar.gz | 723667639 | 6236654 | `382567563476de20bf3e48ce8a0038aeb191675fb5e4625585f546e973697ab7` |
| sbxr-linux-arm64.tar.gz | 723667642 | 5335609 | `1d59594041a9459355a8317a588b9dfa61e8614b886a3a98d4f07c44e8968fd2` |

All thirteen exact records and twenty-six absent release/burn refs are required.
Previous twelve records remain unchanged; all existing refusal and historical
replay rules apply. Prospective 216 needs fresh global admission. This extension
authorizes no draft mutation, burn, deletion, signing, live operation or publication.
