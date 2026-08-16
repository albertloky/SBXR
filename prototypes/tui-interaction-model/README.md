# SBXR staged Owner Console journey prototype

Throwaway prototype for [Prototype the staged Owner Console journeys](https://github.com/albertloky/SBXR/issues/206).

Question: which information structure makes the Cloudflare-free Installation result and the later atomic five-profile Cloudflare Profile Setup easiest for one Owner to understand at exact `80×24` and `120×36` terminal sizes?

Use the floating `A`, `B`, and `C` switcher or the left and right arrow keys to compare three structures. Use the browser-only selectors to change the terminal size and journey screen. The selectors and floating switcher are not part of the Owner Console.

- `A — Guided stages`: one current step and one main decision.
- `B — Checklist workspace`: the complete setup checklist stays visible.
- `C — Outcome first`: the target result and irreversible safety boundary stay visible.

Albert selected `A — Guided stages`. The accepted journey keeps a separate first-Installation result; a two-screen token guide with explicit broad-authority acknowledgment; one-step zone selection; fixed reviewed hostnames and ports unless a Correction Flow is required; an eight-section Plan; eight Owner-visible Apply stages; dedicated Correction Flows; explicit `Check again`; in-memory masked token preservation only while the Owner remains inside setup; Overview after rollback; and Access after a six-row completed result. Variants `B` and `C` remain only as rejected comparison evidence.

Run:

```sh
python3 -m http.server 4173 --directory prototypes/tui-interaction-model
```

Then open <http://127.0.0.1:4173/?variant=A&screen=install-success&size=minimum>.

This is read-only throwaway HTML. It uses fake domains and a fake token. It performs no VPS or Cloudflare action. Visible Cloudflare dashboard labels are planning inputs and still require release-time requalification.
