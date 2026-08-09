# Owner Console

Owner Console owns SBXR's sighted full-screen terminal presentation behind `Run`. Running `sbxr` with no private mode detects the attached terminal, refuses unsafe sessions before drawing, resets modes it owns, enters Bubble Tea's alternate screen, and restores the terminal on every manageable exit.

The Style A frame keeps persistent navigation beside one main work area. `80×24` is the minimum admitted size. At `120×36`, the same navigation remains in place and a second column adds relevant typed details. A later resize below the minimum pauses activation, reports the current and required dimensions, and resumes the same scenario and selection after the terminal is enlarged.

Navigation uses arrows or `Tab` and `Shift+Tab`; `Enter` or `Space` selects; `Esc` goes back only when Back is legal; and `Ctrl+C` opens the visible Exit SBXR confirmation. `Q` and `q` have no exit binding. Bracketed paste is handled as paste data rather than application shortcuts. Every screen has a contextual two-line shortcut bar; forward-only removal never advertises Back or cancellation.

Admission checks interactive input, interactive output, alternate-screen support, full-screen cursor addressing, readable text, standard keyboard input, and the current terminal size. It asks the attached terminal to report the required drawing modes rather than accepting a list of terminal product names. Unicode terminals receive Unicode separators; other admitted terminals receive ASCII separators. Bubble Tea and Lip Gloss use a reliably reported existing background, degrade to monochrome, and honor `NO_COLOR`; text and selection markers carry every meaning without color.

Before drawing, Owner Console records the terminal's reported screen, cursor, mouse, and paste modes, resets the modes it owns, and admits the full-screen frame only after the required drawing-mode replies arrive. A manageable exit restores the prior keyboard settings and every reported owned mode, including modes that were enabled before launch.

The sixteen approved Style A scenarios are typed presentation fixtures. They cover Overview, dedicated Access, limited mode, installation review, Cloudflare guidance, Correction Flow, truthful progress, cancellation, both Recovery Required branches, update review, both Complete-removal phases, and undersized pause at both approved sizes. They do not perform product work. Outcome Modules remain responsible for State, release verification, profiles, subscriptions, Cloudflare, certificates, diagnostics, Plans, mutation, rollback, recovery, and privileged operations.

Client Access Values are not emitted during terminal refusal or before the launch privacy choice. Infrastructure Secrets, arbitrary command output, provider responses, generated configurations, journals, and Rollback Snapshots never belong in this Module.

After a forced termination that prevented restoration, run the terminal's standard recovery command:

```sh
reset
```
