# SBXR TUI interaction prototype

Throwaway prototype for [Prototype the TUI interaction model](https://github.com/albertloky/SBXR/issues/7).

Question: which information structure makes SBXR's safety rules easiest for one Owner to understand and operate?

Albert selected Style A. The prototype renders its persistent-navigation design at the exact `80×24` minimum and a `120×36` large-terminal example using only terminal-achievable primitives. Client Access Values live in the `Access` menu instead of relying on `PgDn`. Large terminals add a second details column. Progress uses a measured bar for known totals, an animated spinner for unknown durations, or a step list with an animated current step and a bar when that step is measurable.

The browser dropdowns are explicitly outside the TUI. They switch terminal size and product scenario for review; the real TUI would read the current terminal dimensions automatically.

Run:

```sh
python3 -m http.server 4173 --directory prototypes/tui-interaction-model
```

Then open <http://127.0.0.1:4173/>.

This is read-only throwaway HTML. It contains no real credentials and performs no VPS action.
