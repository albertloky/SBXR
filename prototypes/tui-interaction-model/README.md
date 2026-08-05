# SBXR TUI interaction prototype

Throwaway prototype for [Prototype the TUI interaction model](https://github.com/albertloky/SBXR/issues/7).

Question: which information structure makes SBXR's safety rules easiest for one Owner to understand and operate?

Three variants share the same fake state and scenarios. Switch with `?variant=A`, `?variant=B`, or `?variant=C` and the floating bottom bar.

Run:

```sh
python3 -m http.server 4173 --directory prototypes/tui-interaction-model
```

Then open <http://127.0.0.1:4173/>.

This is read-only throwaway HTML. It contains no real credentials and performs no VPS action.
