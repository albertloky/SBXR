# Domain documentation

SBXR uses one [CONTEXT.md](../../CONTEXT.md) for its domain vocabulary. Read the
relevant terms before changing module behavior or describing a domain decision.
Use [the code map](code-map.md) to find the owning implementation and tests.

Read the [ADRs](../adr) relevant to the change. Their stated scope matters:
historical release policies and one-release exceptions do not automatically
apply to a current candidate. If a proposed change contradicts an accepted
decision, identify that conflict explicitly.

Use the glossary's names for domain concepts in code discussions, issues, and
refactor proposals. If a needed concept is missing, distinguish a terminology
gap from an implementation detail before changing the glossary. Module READMEs
describe source responsibilities; dated acceptance reports describe observed
runs and do not establish current host state.
