# Go single-binary implementation stack

SBXR uses pinned Go to build pure-Go (`CGO_ENABLED=0`) single-executable archives for immutable GitHub Releases on `linux/amd64` and `linux/arm64`; the executable embeds schemas, migrations, systemd templates, and its Release Identity, opens the Owner TUI by default, and exposes only private system modes plus `sbxr version`.

All application code must be organized as deep Modules with small Interfaces; Bubble Tea v2, Lip Gloss v2, selected Bubbles controls, one maintained YAML library, and one reviewed QR library are the only pre-approved dependency categories, while the exact Module map is deferred to [Define the deep-module architecture](https://github.com/albertloky/SBXR/issues/6).

Go was selected over Python with Textual and Rust with Ratatui because it combines runtime-free installation and rollback with strong compile-time structure and lower maintenance complexity; clean Interfaces and Seams permit future per-Module replacement without adding a speculative plugin or multi-language framework.
