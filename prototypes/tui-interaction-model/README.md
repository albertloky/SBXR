# SBXR TUI interaction prototype

Throwaway prototype for [Prototype the TUI interaction model](https://github.com/albertloky/SBXR/issues/7).

Question: which information structure makes SBXR's safety rules easiest for one Owner to understand and operate?

Albert selected Style A. The current prototype renders its persistent-navigation design as an exact `80×24` character grid using only terminal-achievable primitives. The browser dropdown is explicitly outside the TUI and switches dangerous product scenarios for review.

Run:

```sh
python3 -m http.server 4173 --directory prototypes/tui-interaction-model
```

Then open <http://127.0.0.1:4173/>.

This is read-only throwaway HTML. It contains no real credentials and performs no VPS action.
