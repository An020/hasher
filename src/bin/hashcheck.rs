use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use crossterm::style::Stylize;
use serde::Serialize;

use hasher::algo::{DEFAULT_COMPUTE_ALGORITHM, HashAlgorithm};
use hasher::digest::{
    ParsedDigest, parse_checksum_manifest, parse_digest_from_file, parse_digest_str,
};
use hasher::terminal::{
    GetHashSelection, PromptStream, format_size, make_progress_bar, print_compute_box,
    print_multi_compute_box, print_verify_box, prompt_algorithm_selection_on, should_use_color,
    wait_for_any_key,
};
use hasher::verify::{
    VerifyReport, compute_many, compute_only, format_multi_clipboard_text, resolve_check_args,
    verify_target, wait_for_stable_file,
};

const WATCH_QUIET_WINDOW: Duration = Duration::from_millis(1500);
const PAUSE_PROMPT: &str = "Press any key to continue...";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AlgoArg(Option<HashAlgorithm>);

impl AlgoArg {
    const fn into_option(self) -> Option<HashAlgorithm> {
        self.0
    }
}

fn algo_value_parser() -> clap::builder::ValueParser {
    use clap::builder::{PossibleValuesParser, TypedValueParser as _};

    let values: Vec<&'static str> = std::iter::once("auto")
        .chain(HashAlgorithm::all().iter().map(HashAlgorithm::cli_name))
        .collect();
    clap::builder::ValueParser::new(PossibleValuesParser::new(values).map(|raw| {
        if raw.eq_ignore_ascii_case("auto") {
            AlgoArg(None)
        } else {
            AlgoArg(HashAlgorithm::from_alias(&raw))
        }
    }))
}

#[derive(Debug, Parser)]
#[command(
    name = "hashcheck",
    version,
    about = "Fast file hash verifier and digest calculator for Windows"
)]
#[allow(clippy::struct_excessive_bools)]
struct Cli {
    /// Hash algorithm (`auto` detects from digest length/prefix; compute-only defaults to `sha256`)
    #[arg(
        short = 'a',
        long,
        ignore_case = true,
        default_value = "auto",
        value_parser = algo_value_parser()
    )]
    algo: AlgoArg,

    /// Explicitly treat the hash argument as a path to a text hash file
    #[arg(short = 'f', long)]
    hash_file: bool,

    /// Batch-verify all entries listed in a checksum manifest file
    #[arg(short = 'c', long, value_name = "CHECKSUM_FILE")]
    check: Option<PathBuf>,

    /// Interactive Explorer context-menu mode for a target file
    #[arg(short = 'i', long, value_name = "FILE")]
    interactive: Option<PathBuf>,

    /// Explorer quick-hash mode: pick algorithm (or all), compute digest, and copy to clipboard
    #[arg(short = 'g', long, value_name = "FILE")]
    get_hash: Option<PathBuf>,

    /// Wait until the target file stops changing (1.5s quiet window) before hashing
    #[arg(long)]
    watch: bool,

    /// Launch the native desktop GUI (`hasher.exe`) detached and exit immediately
    #[arg(long)]
    gui: bool,

    /// Emit machine-readable JSON output
    #[arg(long)]
    json: bool,

    /// Disable ANSI terminal colors (also honors `NO_COLOR`)
    #[arg(long)]
    no_color: bool,

    /// Wait for any key press before exiting
    #[arg(long)]
    pause: bool,

    /// Suppress terminal banners and progress bars; rely on exit code
    #[arg(short = 'q', long)]
    quiet: bool,

    /// Expected hash / hash file, or target file in compute-only mode
    #[arg(value_name = "HASH_OR_FILE")]
    first: Option<String>,

    /// Target file, or expected hash / hash file (auto-detected)
    #[arg(value_name = "FILE_OR_HASH")]
    second: Option<String>,
}

#[derive(Serialize)]
struct JsonError<'a> {
    status: &'static str,
    error: &'a str,
}

#[derive(Serialize)]
struct BatchEntryError {
    file: String,
    error: String,
}

#[derive(Serialize)]
struct BatchJsonReport {
    status: &'static str,
    identical: bool,
    total: usize,
    matched: usize,
    mismatched: usize,
    errors: usize,
    results: Vec<VerifyReport>,
    failed_entries: Vec<BatchEntryError>,
}

#[derive(Serialize)]
struct GetHashJsonReport<'a, T> {
    #[serde(flatten)]
    report: &'a T,
    copied: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    clipboard_error: Option<String>,
}

#[derive(Serialize)]
struct CancelledJson {
    status: &'static str,
}

struct ClipboardCandidate {
    preview: String,
    parsed: ParsedDigest,
}

fn strip_outer_quotes(input: &str) -> &str {
    let trimmed = input.trim();
    if trimmed.len() >= 2
        && ((trimmed.starts_with('"') && trimmed.ends_with('"'))
            || (trimmed.starts_with('\'') && trimmed.ends_with('\'')))
    {
        &trimmed[1..trimmed.len() - 1]
    } else {
        trimmed
    }
}

fn validate_target_file(path: &Path) -> Result<(PathBuf, std::fs::Metadata), String> {
    let raw = path.to_string_lossy();
    let target = PathBuf::from(strip_outer_quotes(&raw));
    match std::fs::metadata(&target) {
        Ok(meta) if meta.is_file() => Ok((target, meta)),
        Ok(_) => Err(format!("'{}' is not a regular file", target.display())),
        Err(err) => Err(format!("cannot access '{}': {err}", target.display())),
    }
}

fn print_target_header(target: &Path, meta: &std::fs::Metadata) {
    let display_name = target
        .file_name()
        .map_or_else(|| target.to_string_lossy(), |name| name.to_string_lossy());
    anstream::println!("File : {display_name}");
    anstream::println!("Size : {}", format_size(meta.len()));
}

fn maybe_wait_for_stable(target: &Path, cli: &Cli) -> Result<(), String> {
    if !cli.watch {
        return Ok(());
    }
    if !cli.quiet && !cli.json {
        anstream::println!("Waiting for file to stabilize...");
    }
    wait_for_stable_file(target, WATCH_QUIET_WINDOW).map_err(|err| err.to_string())
}

fn emit_error(message: &str, json: bool) {
    if json {
        if let Ok(serialized) = serde_json::to_string(&JsonError {
            status: "ERROR",
            error: message,
        }) {
            eprintln!("{serialized}");
            return;
        }
    }
    eprintln!("Error: {message}");
}

fn print_report_json(report: &VerifyReport) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(report)?;
    println!("{json}");
    Ok(())
}

fn run_with_progress<T, F>(
    total_bytes: Option<u64>,
    show_progress: bool,
    action: F,
) -> anyhow::Result<T>
where
    F: FnOnce(Option<&mut dyn FnMut(u64, u64)>) -> anyhow::Result<T>,
{
    let pb = if show_progress {
        total_bytes.and_then(make_progress_bar)
    } else {
        None
    };

    let mut progress_cb = |read_bytes: u64, total: u64| {
        if let Some(ref bar) = pb {
            if bar.length() != Some(total) {
                bar.set_length(total);
            }
            bar.set_position(read_bytes);
        }
    };

    let cb_opt: Option<&mut dyn FnMut(u64, u64)> = if pb.is_some() {
        Some(&mut progress_cb)
    } else {
        None
    };

    let result = action(cb_opt);
    if let Some(ref bar) = pb {
        bar.finish_and_clear();
    }
    result
}

fn run_gui(cli: &Cli) -> u8 {
    if cli.check.is_some() {
        emit_error("--gui cannot be combined with --check", cli.json);
        return 2;
    }
    if cli.get_hash.is_some() {
        emit_error("--gui cannot be combined with --get-hash", cli.json);
        return 2;
    }

    let mut forward_args = Vec::new();
    if let Some(ref file) = cli.interactive {
        let raw = file.to_string_lossy();
        forward_args.push(strip_outer_quotes(&raw).to_owned());
    }
    if let Some(ref first) = cli.first {
        forward_args.push(strip_outer_quotes(first).to_owned());
    }
    if let Some(ref second) = cli.second {
        forward_args.push(strip_outer_quotes(second).to_owned());
    }

    let exe_name = if cfg!(windows) {
        "hasher.exe"
    } else {
        "hasher"
    };
    let gui_path = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join(exe_name)))
        .filter(|path| path.is_file())
        .unwrap_or_else(|| PathBuf::from(exe_name));

    match std::process::Command::new(&gui_path)
        .args(&forward_args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(_) => 0,
        Err(err) => {
            emit_error(
                &format!("failed to launch '{}': {err}", gui_path.display()),
                cli.json,
            );
            2
        }
    }
}

fn verify_batch_entry(
    target_path: &Path,
    expected: &ParsedDigest,
    cli: &Cli,
) -> Result<VerifyReport, String> {
    let meta = std::fs::metadata(target_path)
        .map_err(|err| format!("cannot access '{}': {err}", target_path.display()))?;
    let show_progress = !cli.quiet && !cli.json;
    run_with_progress(Some(meta.len()), show_progress, |cb| {
        verify_target(target_path, expected, None, None, cb)
    })
    .map_err(|err| format!("{}: {err}", target_path.display()))
}

fn run_batch_check(manifest_arg: &Path, cli: &Cli, use_color: bool) -> u8 {
    let manifest_raw = manifest_arg.to_string_lossy();
    let manifest_path = PathBuf::from(strip_outer_quotes(&manifest_raw));

    let entries = match parse_checksum_manifest(&manifest_path, cli.algo.into_option()) {
        Ok(list) => list,
        Err(err) => {
            emit_error(&err.to_string(), cli.json);
            return 2;
        }
    };

    if entries.is_empty() {
        emit_error(
            &format!(
                "no valid checksum entries found in '{}'",
                manifest_path.display()
            ),
            cli.json,
        );
        return 2;
    }

    let base_dir = manifest_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    let mut matched = 0usize;
    let mut mismatched = 0usize;
    let mut results = Vec::new();
    let mut failed_entries = Vec::new();

    for (rel_path, expected) in &entries {
        let target_path = base_dir.join(rel_path);
        match verify_batch_entry(&target_path, expected, cli) {
            Ok(report) => {
                if report.identical {
                    matched += 1;
                } else {
                    mismatched += 1;
                }
                if !cli.json && !cli.quiet {
                    print_batch_entry(&report, rel_path, use_color);
                }
                results.push(report);
            }
            Err(msg) => {
                if !cli.json {
                    emit_error(&msg, false);
                }
                failed_entries.push(BatchEntryError {
                    file: target_path.display().to_string(),
                    error: msg,
                });
            }
        }
    }

    let has_error = !failed_entries.is_empty();
    let has_mismatch = mismatched > 0;

    if cli.json {
        let status = if has_error {
            "ERROR"
        } else if has_mismatch {
            "MISMATCH"
        } else {
            "IDENTICAL"
        };
        let batch = BatchJsonReport {
            status,
            identical: !has_error && !has_mismatch,
            total: entries.len(),
            matched,
            mismatched,
            errors: failed_entries.len(),
            results,
            failed_entries,
        };
        if let Ok(json) = serde_json::to_string_pretty(&batch) {
            println!("{json}");
        }
    } else if !cli.quiet {
        print_batch_summary(entries.len(), matched, mismatched, failed_entries.len(), use_color);
    }

    if has_error {
        2
    } else {
        u8::from(has_mismatch)
    }
}

fn print_batch_entry(report: &VerifyReport, rel_path: &Path, use_color: bool) {
    let display = rel_path.display();
    if report.identical {
        if use_color {
            anstream::println!(
                "{} {display} ({}, {} ms)",
                "[IDENTICAL]".green().bold(),
                report.algorithm,
                report.elapsed_ms
            );
        } else {
            anstream::println!(
                "[IDENTICAL] {display} ({}, {} ms)",
                report.algorithm,
                report.elapsed_ms
            );
        }
    } else {
        let expected = report.expected.as_deref().unwrap_or("<none>");
        if use_color {
            anstream::println!(
                "{} {display} (expected {expected}, got {})",
                "[NOT IDENTICAL]".red().bold(),
                report.actual
            );
        } else {
            anstream::println!(
                "[NOT IDENTICAL] {display} (expected {expected}, got {})",
                report.actual
            );
        }
    }
}

fn print_batch_summary(
    total: usize,
    matched: usize,
    mismatched: usize,
    errors: usize,
    use_color: bool,
) {
    anstream::println!(
        "Checked {total} file(s): {matched} identical, {mismatched} mismatched, {errors} error(s)."
    );
    if mismatched > 0 {
        if use_color {
            anstream::println!("{}", "NOT IDENTICAL. BE CAUTIOUS.".red().bold());
        } else {
            anstream::println!("NOT IDENTICAL. BE CAUTIOUS.");
        }
    }
}

fn probe_clipboard(
    target: &Path,
    override_algo: Option<HashAlgorithm>,
) -> Option<ClipboardCandidate> {
    let text = arboard::Clipboard::new()
        .and_then(|mut cb| cb.get_text())
        .ok()?;
    let cleaned = strip_outer_quotes(&text);
    if cleaned.is_empty() {
        return None;
    }

    if !cleaned.contains('\n') && !cleaned.contains('\r') {
        let candidate_path = Path::new(cleaned);
        if candidate_path.is_file() {
            if let Ok(parsed) = parse_digest_from_file(candidate_path, Some(target), override_algo)
            {
                let preview: String = cleaned.chars().take(8).collect();
                return Some(ClipboardCandidate { preview, parsed });
            }
        }
    }

    if let Ok(parsed) = parse_digest_str(cleaned, override_algo) {
        let preview: String = parsed.hex.chars().take(8).collect();
        return Some(ClipboardCandidate { preview, parsed });
    }

    None
}

fn resolve_interactive_input(
    input: &str,
    target: &Path,
    force_hash_file: bool,
    override_algo: Option<HashAlgorithm>,
) -> anyhow::Result<ParsedDigest> {
    let candidate_path = Path::new(input);
    if force_hash_file || (!input.contains('\n') && candidate_path.is_file()) {
        return parse_digest_from_file(candidate_path, Some(target), override_algo).map_err(|err| {
            anyhow::anyhow!(
                "failed to parse hash file '{}': {err}",
                candidate_path.display()
            )
        });
    }

    parse_digest_str(input, override_algo)
        .map_err(|err| anyhow::anyhow!("invalid expected hash or file '{input}': {err}"))
}

fn run_interactive(target_arg: &Path, cli: &Cli, use_color: bool) -> u8 {
    let code = run_interactive_inner(target_arg, cli, use_color);
    wait_for_any_key(PAUSE_PROMPT);
    code
}

fn run_interactive_inner(target_arg: &Path, cli: &Cli, use_color: bool) -> u8 {
    let (target, initial_meta) = match validate_target_file(target_arg) {
        Ok(pair) => pair,
        Err(msg) => {
            emit_error(&msg, cli.json);
            return 2;
        }
    };

    if !cli.json {
        print_target_header(&target, &initial_meta);
    }

    if let Err(msg) = maybe_wait_for_stable(&target, cli) {
        emit_error(&msg, cli.json);
        return 2;
    }

    let clipboard = probe_clipboard(&target, cli.algo.into_option());
    if let Some(ref candidate) = clipboard {
        print!(
            "Paste hash / .txt path (Enter to use clipboard [{}...]): ",
            candidate.preview
        );
    } else {
        print!("Paste expected hash (or .txt file path): ");
    }
    let _ = std::io::stdout().flush();

    let mut line = String::new();
    if let Err(err) = std::io::stdin().read_line(&mut line) {
        emit_error(&format!("failed to read input: {err}"), cli.json);
        return 2;
    }

    let trimmed = strip_outer_quotes(&line);
    let expected = if trimmed.is_empty() {
        let Some(candidate) = clipboard else {
            emit_error("no expected hash provided", cli.json);
            return 2;
        };
        candidate.parsed
    } else {
        match resolve_interactive_input(trimmed, &target, cli.hash_file, cli.algo.into_option()) {
            Ok(parsed) => parsed,
            Err(err) => {
                emit_error(&err.to_string(), cli.json);
                return 2;
            }
        }
    };

    let total_bytes = std::fs::metadata(&target).map(|m| m.len()).ok();
    let show_progress = !cli.quiet && !cli.json;
    let report = match run_with_progress(total_bytes, show_progress, |cb| {
        verify_target(&target, &expected, None, None, cb)
    }) {
        Ok(rep) => rep,
        Err(err) => {
            emit_error(&err.to_string(), cli.json);
            return 2;
        }
    };

    if cli.json {
        if let Err(err) = print_report_json(&report) {
            emit_error(&err.to_string(), true);
            return 2;
        }
    } else if !cli.quiet {
        print_verify_box(&report, use_color);
    }

    u8::from(!report.identical)
}

fn copy_text_to_clipboard(text: &str) -> Result<(), String> {
    arboard::Clipboard::new()
        .and_then(|mut cb| cb.set_text(text.to_owned()))
        .map_err(|err| err.to_string())
}

fn finish_get_hash<T: Serialize>(
    report: &T,
    clipboard_text: &str,
    copied_message: &str,
    cli: &Cli,
    use_color: bool,
    print_box: impl FnOnce(&T, bool),
) -> u8 {
    let copy_result = copy_text_to_clipboard(clipboard_text);

    if cli.json {
        let payload = match copy_result {
            Ok(()) => GetHashJsonReport {
                report,
                copied: true,
                clipboard_error: None,
            },
            Err(err) => GetHashJsonReport {
                report,
                copied: false,
                clipboard_error: Some(err),
            },
        };
        match serde_json::to_string_pretty(&payload) {
            Ok(json) => {
                println!("{json}");
                return 0;
            }
            Err(err) => {
                emit_error(&err.to_string(), true);
                return 2;
            }
        }
    }

    if !cli.quiet {
        print_box(report, use_color);
    }

    match copy_result {
        Ok(()) => {
            if !cli.quiet {
                if use_color {
                    anstream::println!("{}", copied_message.green().bold());
                } else {
                    anstream::println!("{copied_message}");
                }
            }
        }
        Err(err) => {
            eprintln!("Warning: failed to copy hash to clipboard: {err}");
        }
    }

    0
}

fn run_get_hash(target_arg: &Path, cli: &Cli, use_color: bool) -> u8 {
    let code = run_get_hash_inner(target_arg, cli, use_color);
    if !cli.json {
        wait_for_any_key(PAUSE_PROMPT);
    }
    code
}

fn run_get_hash_inner(target_arg: &Path, cli: &Cli, use_color: bool) -> u8 {
    if cli.hash_file {
        emit_error("--get-hash cannot be combined with --hash-file", cli.json);
        return 2;
    }

    let (target, initial_meta) = match validate_target_file(target_arg) {
        Ok(pair) => pair,
        Err(msg) => {
            emit_error(&msg, cli.json);
            return 2;
        }
    };

    if !cli.json && !cli.quiet {
        print_target_header(&target, &initial_meta);
    }

    if let Err(msg) = maybe_wait_for_stable(&target, cli) {
        emit_error(&msg, cli.json);
        return 2;
    }

    let selection = if let Some(algo) = cli.algo.into_option() {
        GetHashSelection::Single(algo)
    } else {
        let prompt_stream = if cli.json {
            PromptStream::Stderr
        } else {
            PromptStream::Stdout
        };
        match prompt_algorithm_selection_on(
            HashAlgorithm::picker_order(),
            DEFAULT_COMPUTE_ALGORITHM,
            prompt_stream,
            cli.no_color,
        ) {
            Ok(Some(sel)) => sel,
            Ok(None) => {
                if cli.json {
                    if let Ok(json) =
                        serde_json::to_string_pretty(&CancelledJson { status: "CANCELLED" })
                    {
                        println!("{json}");
                    }
                } else if !cli.quiet {
                    anstream::println!("Cancelled.");
                }
                return 0;
            }
            Err(err) => {
                emit_error(&format!("algorithm selection failed: {err}"), cli.json);
                return 2;
            }
        }
    };

    let total_bytes = std::fs::metadata(&target)
        .map(|m| m.len())
        .ok()
        .or(Some(initial_meta.len()));
    let show_progress = !cli.quiet && !cli.json;

    match selection {
        GetHashSelection::Single(algo) => {
            let report = match run_with_progress(total_bytes, show_progress, |cb| {
                compute_only(&target, algo, None, None, cb)
            }) {
                Ok(rep) => rep,
                Err(err) => {
                    emit_error(&err.to_string(), cli.json);
                    return 2;
                }
            };
            let copied_message = format!("Copied {} hash to clipboard.", report.algorithm);
            finish_get_hash(
                &report,
                &report.actual,
                &copied_message,
                cli,
                use_color,
                print_compute_box,
            )
        }
        GetHashSelection::All => {
            let report = match run_with_progress(total_bytes, show_progress, |cb| {
                compute_many(&target, HashAlgorithm::picker_order(), None, None, cb)
            }) {
                Ok(rep) => rep,
                Err(err) => {
                    emit_error(&err.to_string(), cli.json);
                    return 2;
                }
            };
            let clipboard_text = format_multi_clipboard_text(&report);
            let copied_message =
                format!("Copied all {} hashes to clipboard.", report.digests.len());
            finish_get_hash(
                &report,
                &clipboard_text,
                &copied_message,
                cli,
                use_color,
                print_multi_compute_box,
            )
        }
    }
}

fn run_single_verify(first: &str, second: &str, cli: &Cli, use_color: bool) -> u8 {
    let resolved = match resolve_check_args(first, second, cli.hash_file, cli.algo.into_option()) {
        Ok(res) => res,
        Err(err) => {
            emit_error(&err.to_string(), cli.json);
            return 2;
        }
    };

    if cli.watch {
        if let Err(err) = wait_for_stable_file(&resolved.target_file, WATCH_QUIET_WINDOW) {
            emit_error(&err.to_string(), cli.json);
            return 2;
        }
    }

    let total_bytes = std::fs::metadata(&resolved.target_file)
        .map(|m| m.len())
        .ok();
    let show_progress = !cli.quiet && !cli.json;

    let report = match run_with_progress(total_bytes, show_progress, |cb| {
        verify_target(&resolved.target_file, &resolved.expected, None, None, cb)
    }) {
        Ok(rep) => rep,
        Err(err) => {
            emit_error(&err.to_string(), cli.json);
            return 2;
        }
    };

    if cli.json {
        if let Err(err) = print_report_json(&report) {
            emit_error(&err.to_string(), true);
            return 2;
        }
    } else if !cli.quiet {
        print_verify_box(&report, use_color);
    }

    u8::from(!report.identical)
}

fn run_compute(target_arg: &str, cli: &Cli, use_color: bool) -> u8 {
    if cli.hash_file {
        emit_error(
            "--hash-file requires both a hash file and a target file",
            cli.json,
        );
        return 2;
    }

    let target = PathBuf::from(strip_outer_quotes(target_arg));
    if cli.watch {
        if let Err(err) = wait_for_stable_file(&target, WATCH_QUIET_WINDOW) {
            emit_error(&err.to_string(), cli.json);
            return 2;
        }
    }

    let algo = cli.algo.into_option().unwrap_or(DEFAULT_COMPUTE_ALGORITHM);
    let total_bytes = std::fs::metadata(&target).map(|m| m.len()).ok();
    let show_progress = !cli.quiet && !cli.json;

    let report = match run_with_progress(total_bytes, show_progress, |cb| {
        compute_only(&target, algo, None, None, cb)
    }) {
        Ok(rep) => rep,
        Err(err) => {
            emit_error(&err.to_string(), cli.json);
            return 2;
        }
    };

    if cli.json {
        if let Err(err) = print_report_json(&report) {
            emit_error(&err.to_string(), true);
            return 2;
        }
    } else if !cli.quiet {
        print_compute_box(&report, use_color);
    }

    0
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let use_color = should_use_color(cli.no_color);

    if cli.gui {
        return ExitCode::from(run_gui(&cli));
    }

    if let Some(ref manifest) = cli.check {
        if cli.interactive.is_some()
            || cli.get_hash.is_some()
            || cli.first.is_some()
            || cli.second.is_some()
        {
            emit_error(
                "--check cannot be combined with positional arguments, --interactive, or --get-hash",
                cli.json,
            );
            return ExitCode::from(2);
        }
        let code = run_batch_check(manifest, &cli, use_color);
        if cli.pause {
            wait_for_any_key(PAUSE_PROMPT);
        }
        return ExitCode::from(code);
    }

    if let Some(ref target) = cli.interactive {
        if cli.get_hash.is_some() || cli.first.is_some() || cli.second.is_some() {
            emit_error(
                "--interactive cannot be combined with positional arguments or --get-hash",
                cli.json,
            );
            if !cli.json {
                wait_for_any_key(PAUSE_PROMPT);
            }
            return ExitCode::from(2);
        }
        return ExitCode::from(run_interactive(target, &cli, use_color));
    }

    if let Some(ref target) = cli.get_hash {
        if cli.first.is_some() || cli.second.is_some() {
            emit_error(
                "--get-hash cannot be combined with positional arguments",
                cli.json,
            );
            return ExitCode::from(2);
        }
        return ExitCode::from(run_get_hash(target, &cli, use_color));
    }

    let code = match (&cli.first, &cli.second) {
        (Some(first), Some(second)) => run_single_verify(first, second, &cli, use_color),
        (Some(first), None) => run_compute(first, &cli, use_color),
        (None, Some(_)) => {
            emit_error("unexpected second argument without first argument", cli.json);
            2
        }
        (None, None) => {
            emit_error(
                "missing input: provide <file>, <hash> <file>, -c <checksum_file>, -i <file>, -g <file>, or --gui",
                cli.json,
            );
            2
        }
    };

    if cli.pause {
        wait_for_any_key(PAUSE_PROMPT);
    }

    ExitCode::from(code)
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory as _, Parser as _};
    use tempfile::TempDir;

    use super::{Cli, validate_target_file};
    use hasher::algo::HashAlgorithm;

    #[test]
    fn cli_parses_dynamic_algorithms_and_get_hash() {
        Cli::command().debug_assert();

        let default_cli = Cli::try_parse_from(["hashcheck", "file.bin"]).expect("parse default");
        assert_eq!(default_cli.algo.into_option(), None);

        let auto_cli =
            Cli::try_parse_from(["hashcheck", "--algo", "auto", "file.bin"]).expect("parse auto");
        assert_eq!(auto_cli.algo.into_option(), None);

        for &algo in HashAlgorithm::all() {
            let parsed = Cli::try_parse_from(["hashcheck", "-a", algo.cli_name(), "file.bin"])
                .expect("parse dynamic algo");
            assert_eq!(parsed.algo.into_option(), Some(algo));
        }

        let get_hash_cli =
            Cli::try_parse_from(["hashcheck", "-g", "target.iso"]).expect("parse get-hash");
        assert_eq!(
            get_hash_cli.get_hash.as_deref(),
            Some(std::path::Path::new("target.iso"))
        );

        assert!(Cli::try_parse_from(["hashcheck", "--algo", "not-an-algo", "file.bin"]).is_err());
    }

    #[test]
    fn validate_target_file_accepts_file_and_rejects_dir_or_missing() {
        let dir = TempDir::new().expect("tempdir");
        let file_path = dir.path().join("payload.bin");
        std::fs::write(&file_path, b"hello").expect("write payload");

        let quoted = format!("\"{}\"", file_path.display());
        let (resolved, meta) =
            validate_target_file(std::path::Path::new(&quoted)).expect("valid file");
        assert_eq!(resolved, file_path);
        assert_eq!(meta.len(), 5);

        let dir_err = validate_target_file(dir.path()).expect_err("directory must fail");
        assert!(dir_err.contains("not a regular file"));

        let missing = dir.path().join("missing.bin");
        let missing_err = validate_target_file(&missing).expect_err("missing must fail");
        assert!(missing_err.contains("cannot access"));
    }
}
