# Hasher Implementation Plan

High-speed native Rust CLI and GUI file-hash verifier for Windows (`hashcheck.exe` and `hasher.exe`).

## 1. Architecture & Binary Layout

Build one Cargo package (`hasher`, Rust `edition = "2024"`, `rust-version = "1.85"`) containing a shared library core and two thin binaries:

- `src/lib.rs` (core library): streaming hashing engine, digest normalization, algorithm auto-identification, `.txt` / checksum file parsing, Windows clipboard/terminal helpers.
- `src/bin/hashcheck.rs` (console subsystem): fast CLI for CMD and PowerShell, interactive Explorer context-menu mode, batch checksum verification, watch mode, JSON output, and `--gui` launcher.
- `src/bin/hasher.rs` (Windows GUI subsystem via `#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]`): native desktop window with zero console flash.

### Why Two Binaries

A single Windows binary cannot act cleanly as both a terminal CLI and a double-click GUI app. A console-subsystem binary flashes a black console window when launched from Explorer or Start Menu; a GUI-subsystem binary detaches from CMD/PowerShell stdout and exit codes. Sharing one library crate across two small entrypoints avoids both problems with minimal code.

### Cargo & Lint Configuration

```toml
[package]
name = "hasher"
version = "0.1.0"
edition = "2024"
rust-version = "1.85"
default-run = "hasher"

[lints.rust]
unsafe_code = "warn"

[lints.clippy]
all = "warn"
pedantic = "warn"

[profile.release]
lto = "thin"
codegen-units = 1
strip = "symbols"
panic = "abort"
```

### Core Crates

| Purpose | Crate | Notes |
|---|---|---|
| Hashing (SHA-256/384/512) | `sha2` | Runtime CPU feature detection (SHA-NI / AVX2) |
| Hashing (SHA-1, MD5) | `sha1`, `md-5` | Legacy download checksum support |
| Hashing (CRC32, BLAKE3) | `crc32fast`, `blake3` | Fast CRC32 and modern 256-bit hashing |
| CLI parsing | `clap` (derive) | Type-safe args, subflags, help text |
| Terminal colors & key pause | `crossterm`, `anstream` | Works across CMD, PowerShell, Windows Terminal |
| CLI progress bar | `indicatif` | Shown on stderr for files >= 32 MiB |
| Native GUI | `eframe` / `egui` | Zero external runtime deps, 60fps, built-in drag-and-drop |
| Native Windows file picker | `rfd` | Native Windows Explorer Open File dialog |
| Clipboard | `arboard` | Read/write Windows clipboard in GUI and `--interactive` |
| Errors & serialization | `thiserror`, `anyhow`, `serde`, `serde_json` | Typed library errors, ergonomic CLI errors, `--json` |

## 2. Core Hashing & Parser Design (`src/`)

### Supported Algorithms & Auto-Identification

```rust
pub enum HashAlgorithm {
    Crc32,
    Md5,
    Sha1,
    Sha256,
    Sha384,
    Sha512,
    Blake3,
}
```

Auto-identification by normalized hex length:
- `8` hex chars (4 bytes): `CRC32`
- `32` hex chars (16 bytes): `MD5`
- `40` hex chars (20 bytes): `SHA-1`
- `64` hex chars (32 bytes): `SHA-256` (default for 64-char hashes; `BLAKE3` selectable via `--algo blake3`, `blake3:` prefix, or GUI dropdown)
- `96` hex chars (48 bytes): `SHA-384`
- `128` hex chars (64 bytes): `SHA-512`

### Digest Normalization (`ParsedDigest`)

Accepts messy copy-pasted strings and extracts a validated lowercase hex digest:
1. Trim whitespace and surrounding quotes (`"`, `'`).
2. Strip optional prefixes (`sha256:`, `sha-256:`, `sha512:`, `sha1:`, `md5:`, `crc32:`, `blake3:`, case-insensitive).
3. Extract digest from PowerShell/OpenSSL/GNU lines when pasted directly (e.g. `SHA256 (file.iso) = <hex>` or `<hex>  file.iso`).
4. Validate hex characters and exact byte length.

### `.txt` & Checksum File Parsing

Handles expected hashes stored in `.txt`, `.sha256`, `.sha512`, `.sha1`, `.md5`, `.sum`, or any UTF-8 text file:
- Enforce a 1 MiB read limit before reading a candidate hash file as text so large binary targets are never read into memory as text.
- Match rules when verifying a target file `target_path`:
  1. Look for checksum lines matching the target basename (`<hex>  <name>`, `<hex> *<name>`, `SHA256 (<name>) = <hex>`).
  2. Fallback: if the text file contains exactly one valid hex digest (ignoring `#` comments and blank lines), use that digest.
  3. Return a typed error (`DigestError::AmbiguousHashFile` or `DigestError::NoDigestFound`) when zero or multiple unmatched digests exist.

### Streaming Performance

- Use static dispatch (`enum HasherEngine`) inside the hashing loop to avoid virtual call overhead.
- Read files sequentially with a single reusable heap buffer of `4 MiB` (`vec![0u8; 4 * 1024 * 1024]`) instead of small default buffers.
- Report byte progress through a throttled callback or atomic counters (`AtomicU64` bytes read + `AtomicBool` cancel token) so both CLI and GUI display live `MB/s` and ETA without slowing down I/O.

## 3. CLI Design (`hashcheck.exe`)

### Command Forms

- `hashcheck <hash_or_hashfile> <file>`: primary check mode. Supports hex string or path to a `.txt`/checksum text file. Includes smart argument-swap fallback when `<file>` is passed before `<hash>` or `<hash.txt>`.
- `hashcheck <file>`: compute-only mode (computes `SHA-256` by default, or `--algo <algo>`).
- `hashcheck -c <checksum_file>` / `--check <checksum_file>`: batch-verify all entries listed in a checksum file relative to its directory.
- `hashcheck -i <file>` / `--interactive <file>`: Explorer context-menu workflow.
- `hashcheck --watch <hash_or_hashfile> <file>`: waits for a downloading file's size/mtime to stabilize (1.5s quiet window) or re-checks on change, then displays the result box.
- `hashcheck --gui [file] [hash]`: launches `hasher.exe` detached and returns immediately.

### Flags

- `--algo, -a <auto|crc32|md5|sha1|sha256|sha384|sha512|blake3>` (default: `auto`)
- `--hash-file, -f <path>`: explicitly treat input as a text hash file
- `--json`: emit structured JSON result (`status`, `identical`, `algorithm`, `expected`, `actual`, `file`, `bytes`, `elapsed_ms`, `throughput_mbps`)
- `--no-color`: disable ANSI colors (also honors `NO_COLOR`)
- `--pause`: wait for any keypress before exiting
- `--quiet, -q`: suppress banner; rely on exit code

### Terminal Output Boxes & Exit Codes

Enable Windows Virtual Terminal Processing on startup so ANSI colors render cleanly in both `cmd.exe` and `powershell.exe`:

- **Match (Exit Code `0`)**: large bright green ANSI box (`IDENTICAL`) followed by algorithm, file path, size, elapsed time, and `MB/s`.
- **Mismatch (Exit Code `1`)**: large bright red ANSI box (`NOT IDENTICAL. BE CAUTIOUS.`) followed by Expected vs Computed hashes.
- **Error (Exit Code `2`)**: concise error message to `stderr`.

### Explorer Context-Menu Interactive Workflow (`--interactive "%1"`)

Matches the browser download workflow:
1. User right-clicks downloaded file in Windows Explorer -> clicks **Verify Hash with Hasher**.
2. Terminal opens via `hashcheck.exe --interactive "%1"`, showing target filename and size.
3. Program checks Windows clipboard (`arboard`). If clipboard already holds a valid hash or `.txt` path, prompt shows `Paste hash / .txt path (Enter to use clipboard [<8-char preview>...]):`. Otherwise prompt shows `Paste expected hash (or .txt file path):`.
4. User presses Enter (if copied while downloading) or pastes hash and presses Enter.
5. Hasher computes digest with live progress bar and prints the big green `IDENTICAL` or red `NOT IDENTICAL. BE CAUTIOUS.` box.
6. Pause prompt appears: `Press any key to continue...` using raw key event reading (`crossterm::event::read()`) so any single keypress closes the terminal window.

## 4. Native GUI Design (`hasher.exe`)

Built with `eframe` / `egui` + `rfd` + `arboard`:

- **Startup args**: accepts optional `[file] [hash_or_hashfile]` so `hashcheck --gui` or dragging a file onto `hasher.exe` pre-fills inputs.
- **File selection**:
  - Editable **File Path** text field (automatically strips surrounding quotes from "Copy as path").
  - **Browse...** button launching native Windows File Explorer dialog (`rfd`).
  - Drag-and-drop file onto any part of the window.
- **Expected hash input**:
  - Editable **Expected Hash** text field (supports raw hex, `sha256:` prefixes, or copied checksum lines).
  - **Paste** button (from clipboard), **Load `.txt`...** button (file picker to extract hash from `.txt`/`.sha256`), and **Clear** button.
  - **Algorithm** dropdown (`Auto (by length)`, `SHA-256`, `SHA-512`, `SHA-1`, `MD5`, `CRC32`, `SHA-384`, `BLAKE3`).
- **Execution & progress**:
  - Runs hashing on a background `std::thread` so the UI never freezes.
  - Primary **Verify** button (and **Compute Only** when hash input is empty, with **Copy Hash** button on result).
  - Live progress bar showing `%`, processed bytes, `MB/s`, and **Cancel** button.
- **Result Banner**:
  - **Match**: full-width vivid green card displaying large bold `IDENTICAL` plus algorithm and digest confirmation.
  - **Mismatch**: full-width vivid red card displaying large bold `NOT IDENTICAL. BE CAUTIOUS.` plus side-by-side Expected vs Actual comparison.

## 5. Installation, PATH & Windows Integration (`scripts/`)

Provide `scripts/install.ps1` and `scripts/uninstall.ps1` (no administrator elevation required; all writes target user scope):

1. Build optimized binaries: `cargo build --release`.
2. Copy `target/release/hashcheck.exe` and `target/release/hasher.exe` into `%LOCALAPPDATA%\hasher\bin`.
3. Update `HKCU\Environment\Path` safely using .NET `[Environment]::GetEnvironmentVariable` / Registry API (preserving existing entries and avoiding `setx` 1024-character truncation) and broadcast `WM_SETTINGCHANGE` so new CMD and PowerShell windows resolve `hashcheck` and `hasher` from any working directory.
4. Create Start Menu shortcut at `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Hasher.lnk` pointing to `hasher.exe`.
5. Register Windows Explorer right-click entry under `HKCU\Software\Classes\*\shell\VerifyHashWithHasher`:
   - Default value: `Verify Hash with Hasher`
   - `Icon`: `"%LOCALAPPDATA%\hasher\bin\hasher.exe",0`
   - `command` default value: `"%LOCALAPPDATA%\hasher\bin\hashcheck.exe" --interactive "%1"`

## 6. Planned File Tree

```text
c:\Users\nguye\Desktop\Projects\command tool\
├── Cargo.toml
├── plan.md
├── scripts/
│   ├── install.ps1
│   └── uninstall.ps1
├── src/
│   ├── lib.rs
│   ├── algo.rs          # HashAlgorithm enum, auto-detection, streaming engine
│   ├── digest.rs        # ParsedDigest normalization + .txt / checksum file parser
│   ├── verify.rs        # Single verify, batch check (-c), watch mode, JSON model
│   ├── terminal.rs      # ANSI big green/red boxes, progress bar, raw key pause
│   └── bin/
│       ├── hashcheck.rs # CLI entrypoint
│       └── hasher.rs    # Native egui GUI entrypoint
└── tests/
    └── cli_integration.rs
```

## 7. Verification Plan

1. **Unit tests (`cargo test`)**:
   - Digest normalization (case, whitespace, quotes, prefixes, OpenSSL/GNU strings).
   - Auto-detection for lengths 8, 32, 40, 64, 96, 128 and explicit `BLAKE3` override.
   - `.txt` and checksum-file parsing (single hash, multi-line basename lookup, ambiguity errors, 1 MiB safety limit).
   - Smart argument-swap resolution (`<hash> <file>` vs `<file> <hash>` vs `<hash.txt> <file>`).
   - Known NIST/RFC test vectors across all 7 algorithms.
2. **CLI integration tests (`tests/cli_integration.rs`)**:
   - Exit code `0` and `IDENTICAL` output on matching hash and `.txt` hash file.
   - Exit code `1` and `NOT IDENTICAL. BE CAUTIOUS.` output on mismatch.
   - Exit code `2` on missing file or invalid hash.
   - Batch `-c` check, `--json` output, and compute-only single-arg mode.
3. **Static checks**:
   - `cargo clippy --all-targets -- -D warnings`
4. **End-to-end Windows checks (post-install)**:
   - Open fresh `cmd.exe` and `powershell.exe` in `C:\Windows\Temp` and run `hashcheck <hash> <file>` and `hasher`.
   - Right-click a test file in Windows Explorer -> click **Verify Hash with Hasher** -> verify clipboard prompt, big green/red box, and press-any-key close.
   - Open `hasher.exe` -> test typed path, Windows File Explorer picker, drag-and-drop, `.txt` load, and green/red status banners.

## 8. Environment Blocker Observed During Planning

During initial workspace inspection, `run_command` failed with:
`JSON hook "jsonhook__rtk_PreToolUse_0_0" failed: command failed: exit status 1, stderr: The system cannot find the path specified.`

All Rust source files and install scripts can be written directly, while running `cargo build`, `cargo test`, `cargo clippy`, and `scripts/install.ps1` via `run_command` requires resolving that missing PreToolUse hook executable/path (or executing the build and install commands manually in PowerShell).
