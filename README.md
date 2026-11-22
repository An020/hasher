# Hasher

Fast file hash verifier and digest calculator for Windows, written in Rust with both a terminal CLI (`hashcheck`), a native desktop GUI (`hasher`), and Windows Explorer context-menu integration.

## Features

- **Fast streaming I/O**: Reads files through a 4 MiB buffer with constant memory usage and shows a progress bar when file size reaches 32 MiB or larger.
- **Supported algorithms**: `SHA-256` (default), `SHA-512`, `SHA-384`, `SHA-1`, `MD5`, `CRC32`, and `BLAKE3`.
- **Auto-detection**: Infers algorithm by normalized digest length or algorithm prefix (`sha256:...`, `sha256-...` SRI, etc.; 64-character hex defaults to `SHA-256`, use `-a blake3` or `blake3:` for `BLAKE3`).
- **Unmistakable verdicts**: Displays `[ OK ]   IDENTICAL` in green on match (`exit 0`) and `[ !! ]   NOT IDENTICAL. BE CAUTIOUS.` in red with mismatched hex characters highlighted on mismatch (`exit 1`).
- **Single-pass multi-hash picker**: Compute one algorithm or all 7 in a single read pass and copy results directly to the Windows clipboard (`hashcheck -g <file>`).
- **Desktop GUI**: Native `eframe`/`egui` window (`hasher.exe`) supporting file dialogs, drag-and-drop, clipboard digest detection, progress bar, and cancellation.
- **Data-driven configuration**: Supported algorithm metadata lives in `HashAlgorithm` (`src/algo.rs`), and Windows installer/uninstaller behavior reads from `scripts/windows-config.json`.
- **Fixed GUI for batch-checking files**: You can choose folder in the file selection window, this will scan for its contents, even the hidden files. Each file entry will have hash paste box + progress bar + predicted hash.

## Install on Windows

Requires a Rust toolchain (`rust-version = "1.85"`) and Windows PowerShell. No administrator privileges are needed; everything installs into your user profile (`%LOCALAPPDATA%\hasher\bin`, User `PATH`, Start Menu `Hasher.lnk`, and `HKCU\Software\Classes\*\shell`).

```powershell
powershell -ExecutionPolicy Bypass -File scripts/install.ps1
```

To remove binaries, Start Menu shortcut, `PATH` entry, and Explorer context menu items:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/uninstall.ps1
```

## CLI Usage (`hashcheck`)

### Verify a file against a hash or hash file

Argument order between hash and file is detected automatically:

```powershell
hashcheck <hash> <file>
hashcheck <file> <hash>
hashcheck <file> checksum.sha256
```

### Compute a file hash

Defaults to `SHA-256`, or pass `-a <algo>` (`crc32`, `md5`, `sha1`, `sha256`, `sha384`, `sha512`, `blake3`):

```powershell
hashcheck <file>
hashcheck -a blake3 <file>
```

### Quick hash picker and clipboard copy

Opens an interactive algorithm picker (`Enter` selects `SHA-256`, `1`-`7` selects a single algorithm, `A` computes all 7 in a single streaming pass), copies single bare hex or `ALGO: digest` lines to the clipboard, and pauses before exit:

```powershell
hashcheck -g <file>
```

### Batch verify checksum manifests

Supports GNU (`sha256sum`) and OpenSSL-style checksum manifest files:

```powershell
hashcheck -c SHA256SUMS.txt
```

### Options and Exit Codes

- `-i`, `--interactive <FILE>`: Interactive verification flow (auto-probes clipboard for a copied digest).
- `-g`, `--get-hash <FILE>`: Quick algorithm picker with clipboard copy and pause.
- `-f`, `--hash-file`: Treat hash argument as a path to a digest text file.
- `--watch`: Wait for a 1.5 second quiet window before hashing active downloads.
- `--gui`: Launch `hasher.exe` detached and exit immediately.
- `--json`: Output structured JSON (picker prompt output moves to `stderr`).
- `--no-color`, `--pause`, `-q` / `--quiet`: Formatting and scripting flags.

Exit codes: `0` on match or clean compute/cancel, `1` on mismatch, `2` on invalid input or I/O error.

## Windows Explorer Context Menu

Installing adds two right-click entries for files in Windows Explorer:

- **Verify Hash with Hasher** (`hashcheck.exe --interactive "%1"`): Auto-detects a hash on your clipboard or lets you paste one or pick a `.txt` hash file.
- **Get Hash with Hasher** (`hashcheck.exe --get-hash "%1"`): Computes a chosen hash (`Enter` for `SHA-256`) or all 7 hashes (`A`), copies to clipboard, and pauses.

## Development

```powershell
cargo test --locked
cargo clippy --all-targets -- -D warnings
cargo build --release
```
