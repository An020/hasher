# projectmem - command tool

_Last updated: 2026-11-14_

## Project purpose
Replace this placeholder with a concise description of what this project does, who it serves, and the main technologies or runtime assumptions.

## Recent issues
- No issues logged yet.

## Decisions
- Dual-binary Rust 2024 crate (hasher GUI + hashcheck CLI) sharing buffered streaming engine and digest normalization core
- Derive algorithm pickers, CLI --algo parser, GUI ComboBox, and Windows Explorer verbs dynamically from HashAlgorithm::picker_order/all (src/algo.rs) and scripts/windows-config.json with zero hardcoding.

## Notes
- gotcha: tokless v1.0.13 writes forward slashes into C:/Users/nguye/.gemini/config/hooks.json on Windows which breaks cmd.exe hook invocations; keep double backslashes in hooks.json and do not re-run tokless init/doctor without --dry-run on Antigravity
- lesson: Check RawModeGuard::acquire() with stdin().is_terminal() before crossterm raw mode so piped input works, and route selection prompts to stderr when --json is active (src/terminal.rs).

## Key files
- `v1.0.13`
- `/Users/nguye/.gemini/config/hooks.json`
- `cmd.exe`
- `hooks.json`
- `src/algo.rs`
- `scripts/windows-config.json`
- `src/terminal.rs`

## Open questions
- None logged yet.
