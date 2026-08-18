# Go single-binary implementation stack

SBXR uses pinned Go to build pure-Go (`CGO_ENABLED=0`) single-executable archives for immutable GitHub Releases on `linux/amd64` and `linux/arm64`; the executable embeds schemas, migrations, systemd templates, and its Release Identity, opens the Owner TUI by default, and exposes private system modes, `sbxr version`, and the public Package Qualification Command accepted by ADR-0012.

All application code must be organized as the deep Modules with small Interfaces established by [Define the deep-module architecture](https://github.com/albertloky/SBXR/issues/6#issuecomment-5174654886); Bubble Tea v2, Lip Gloss v2, selected Bubbles controls, one maintained YAML library, and one reviewed QR library are the only pre-approved dependency categories.

Go was selected over Python with Textual and Rust with Ratatui because it combines runtime-free installation and rollback with strong compile-time structure and lower maintenance complexity; clean Interfaces and Seams permit future per-Module replacement without adding a speculative plugin or multi-language framework.
