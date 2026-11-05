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
