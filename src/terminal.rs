use std::fmt::Write as _;
use std::io::{IsTerminal, Write as _};

use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::style::Stylize;
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};

use crate::algo::HashAlgorithm;
use crate::verify::{MultiComputeReport, VerifyReport};

/// File size threshold (`32 MiB`) above which a progress bar is displayed on `stderr`.
pub const PROGRESS_THRESHOLD_BYTES: u64 = 32 * 1024 * 1024;

const BANNER_INNER_WIDTH: usize = 74;
const DEFAULT_LABEL_WIDTH: usize = 9;

/// Selection returned by [`prompt_algorithm_selection`] for `--get-hash` mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GetHashSelection {
    /// Compute a single selected hash algorithm.
    Single(HashAlgorithm),
    /// Compute all supported algorithms in a single streaming pass.
    All,
}

/// Output stream for interactive selection prompts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptStream {
    /// Render prompt UI on `stdout`.
    Stdout,
    /// Render prompt UI on `stderr` so `stdout` stays reserved for `--json` output.
    Stderr,
}

struct RawModeGuard;

impl RawModeGuard {
    fn acquire() -> Option<Self> {
        if std::io::stdin().is_terminal() && crossterm::terminal::enable_raw_mode().is_ok() {
            Some(Self)
        } else {
            None
        }
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = crossterm::terminal::disable_raw_mode();
    }
}

fn next_key_press() -> std::io::Result<KeyEvent> {
    loop {
        if let Event::Key(key) = crossterm::event::read()? {
            if key.kind == KeyEventKind::Press {
                return Ok(key);
            }
        }
    }
}

fn should_use_color_for_stream(no_color_flag: bool, stream: PromptStream) -> bool {
    let is_tty = match stream {
        PromptStream::Stdout => {
            let _ = anstream::stdout();
            std::io::stdout().is_terminal()
        }
        PromptStream::Stderr => {
            let _ = anstream::stderr();
            std::io::stderr().is_terminal()
        }
    };
    !no_color_flag && std::env::var_os("NO_COLOR").is_none() && is_tty
}

/// Enable Windows Virtual Terminal / ANSI handling cleanly via `anstream` and
/// return whether colorized output should be emitted on `stdout`.
#[must_use]
pub fn should_use_color(no_color_flag: bool) -> bool {
    should_use_color_for_stream(no_color_flag, PromptStream::Stdout)
}

/// Format an unsigned integer with comma thousands separators.
#[must_use]
pub fn format_with_commas(value: u64) -> String {
    let digits = value.to_string();
    let mut reversed = String::with_capacity(digits.len() + digits.len() / 3);
    for (idx, ch) in digits.chars().rev().enumerate() {
        if idx > 0 && idx % 3 == 0 {
            reversed.push(',');
        }
        reversed.push(ch);
    }
    reversed.chars().rev().collect()
}

/// Format a byte count into human-readable binary units paired with exact bytes.
#[must_use]
#[allow(clippy::cast_precision_loss)]
pub fn format_size(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
    const TIB: f64 = 1024.0 * 1024.0 * 1024.0 * 1024.0;

    let exact = format_with_commas(bytes);
    let b = bytes as f64;
    if b >= TIB {
        format!("{:.2} TiB ({exact} bytes)", b / TIB)
    } else if b >= GIB {
        format!("{:.2} GiB ({exact} bytes)", b / GIB)
    } else if b >= MIB {
        format!("{:.2} MiB ({exact} bytes)", b / MIB)
    } else if b >= KIB {
        format!("{:.2} KiB ({exact} bytes)", b / KIB)
    } else if bytes == 1 {
        "1 byte".to_owned()
    } else {
        format!("{exact} bytes")
    }
}

fn format_elapsed(elapsed_ms: u128) -> String {
    if elapsed_ms >= 1000 {
        let secs = elapsed_ms / 1000;
        let rem_ms = elapsed_ms % 1000;
        format!("{secs}.{rem_ms:03} s ({elapsed_ms} ms)")
    } else {
        format!("{elapsed_ms} ms")
    }
}

fn center_line(text: &str, width: usize) -> String {
    let len = text.chars().count();
    if len >= width {
        return text.to_owned();
    }
    let left = (width - len) / 2;
    let right = width - len - left;
    format!("{}{text}{}", " ".repeat(left), " ".repeat(right))
}

fn print_banner(title: &str, identical: bool, use_color: bool) {
    let horiz = "═".repeat(BANNER_INNER_WIDTH);
    let blank = " ".repeat(BANNER_INNER_WIDTH);
    let centered = center_line(title, BANNER_INNER_WIDTH);

    let top = format!("╔{horiz}╗");
    let pad = format!("║{blank}║");
    let mid = format!("║{centered}║");
    let bot = format!("╚{horiz}╝");

    if !use_color {
        anstream::println!("{top}");
        anstream::println!("{pad}");
        anstream::println!("{mid}");
        anstream::println!("{pad}");
        anstream::println!("{bot}");
        return;
    }

    if identical {
        let pad_styled = pad.as_str().black().on_green().bold();
        anstream::println!("{}", top.green().bold());
        anstream::println!("{pad_styled}");
        anstream::println!("{}", mid.black().on_green().bold());
        anstream::println!("{pad_styled}");
        anstream::println!("{}", bot.green().bold());
    } else {
        let pad_styled = pad.as_str().white().on_red().bold();
        anstream::println!("{}", top.red().bold());
        anstream::println!("{pad_styled}");
        anstream::println!("{}", mid.white().on_red().bold());
        anstream::println!("{pad_styled}");
        anstream::println!("{}", bot.red().bold());
    }
}

#[derive(Clone, Copy)]
enum FooterTone {
    Green,
    Red,
    Cyan,
}

fn format_field_label_width(label: &str, width: usize, use_color: bool) -> String {
    let padded = format!("  {label:<width$} :");
    if use_color {
        format!("{}", padded.bold())
    } else {
        padded
    }
}

fn format_field_label(label: &str, use_color: bool) -> String {
    format_field_label_width(label, DEFAULT_LABEL_WIDTH, use_color)
}

fn print_panel_header(title: &str, use_color: bool) {
    let horiz = "─".repeat(BANNER_INNER_WIDTH);
    let centered = center_line(title, BANNER_INNER_WIDTH);
    let top = format!("┌{horiz}┐");
    let mid = format!("│{centered}│");
    let bot = format!("└{horiz}┘");

    if use_color {
        anstream::println!("{}", top.cyan().bold());
        anstream::println!("{}", mid.cyan().bold());
        anstream::println!("{}", bot.cyan().bold());
    } else {
        anstream::println!("{top}");
        anstream::println!("{mid}");
        anstream::println!("{bot}");
    }
}

fn print_panel_footer(tone: FooterTone, use_color: bool) {
    let footer = "─".repeat(BANNER_INNER_WIDTH + 2);
    if !use_color {
        anstream::println!("{footer}");
        return;
    }
    match tone {
        FooterTone::Green => anstream::println!("{}", footer.green()),
        FooterTone::Red => anstream::println!("{}", footer.red()),
        FooterTone::Cyan => anstream::println!("{}", footer.cyan()),
    }
}

fn print_metrics_rows(
    bytes: u64,
    elapsed_ms: u128,
    throughput_mbps: f64,
    label_width: usize,
    use_color: bool,
) {
    let size_text = format_size(bytes);
    let time_text = format_elapsed(elapsed_ms);
    let speed_text = format!("{throughput_mbps:.2} MB/s");

    anstream::println!(
        "{} {size_text}",
        format_field_label_width("Size", label_width, use_color)
    );
    anstream::println!(
        "{} {time_text}",
        format_field_label_width("Time", label_width, use_color)
    );
    anstream::println!(
        "{} {speed_text}",
        format_field_label_width("Speed", label_width, use_color)
    );
}

fn format_mismatch_actual(expected: &str, actual: &str, use_color: bool) -> String {
    if !use_color {
        return actual.to_owned();
    }
    if expected.chars().count() != actual.chars().count() {
        return format!("{}", actual.red().bold());
    }

    let mut out = String::new();
    let mut run = String::new();
    let mut run_is_diff: Option<bool> = None;

    for (exp_ch, act_ch) in expected.chars().zip(actual.chars()) {
        let is_diff = !exp_ch.eq_ignore_ascii_case(&act_ch);
        if run_is_diff.is_some_and(|prev| prev != is_diff) {
            flush_diff_run(&mut out, &run, !is_diff);
            run.clear();
        }
        run_is_diff = Some(is_diff);
        run.push(act_ch);
    }

    if let Some(is_diff) = run_is_diff {
        flush_diff_run(&mut out, &run, is_diff);
    }

    out
}

fn flush_diff_run(out: &mut String, run: &str, is_diff: bool) {
    if is_diff {
        let _ = write!(out, "{}", run.white().on_red().bold());
    } else {
        let _ = write!(out, "{}", run.red());
    }
}

/// Print the verification result banner (`IDENTICAL` or `NOT IDENTICAL. BE CAUTIOUS.`)
/// followed by algorithm, file metadata, and hashes.
pub fn print_verify_box(report: &VerifyReport, use_color: bool) {
    if report.identical {
        print_banner("[ OK ]   IDENTICAL", true, use_color);
        anstream::println!(
            "{} {}",
            format_field_label("Algorithm", use_color),
            report.algorithm
        );
        anstream::println!(
            "{} {}",
            format_field_label("File", use_color),
            report.file
        );
        print_metrics_rows(
            report.bytes,
            report.elapsed_ms,
            report.throughput_mbps,
            DEFAULT_LABEL_WIDTH,
            use_color,
        );

        let expected_display = report.expected.as_deref().unwrap_or(report.actual.as_str());
        if use_color {
            anstream::println!(
                "{} {}",
                format_field_label("Expected", true),
                expected_display.green()
            );
            anstream::println!(
                "{} {}",
                format_field_label("Computed", true),
                report.actual.as_str().green().bold()
            );
        } else {
            anstream::println!(
                "{} {expected_display}",
                format_field_label("Expected", false)
            );
            anstream::println!(
                "{} {}",
                format_field_label("Computed", false),
                report.actual
            );
        }
    } else {
        print_banner("[ !! ]   NOT IDENTICAL. BE CAUTIOUS.", false, use_color);
        anstream::println!(
            "{} {}",
            format_field_label("Algorithm", use_color),
            report.algorithm
        );
        anstream::println!(
            "{} {}",
            format_field_label("File", use_color),
            report.file
        );

        let expected_display = report.expected.as_deref().unwrap_or("<none>");
        let computed_display = format_mismatch_actual(expected_display, &report.actual, use_color);
        if use_color {
            anstream::println!(
                "{} {}",
                format_field_label("Expected", true),
                expected_display.cyan()
            );
        } else {
            anstream::println!(
                "{} {expected_display}",
                format_field_label("Expected", false)
            );
        }
        anstream::println!(
            "{} {computed_display}",
            format_field_label("Computed", use_color)
        );
        print_metrics_rows(
            report.bytes,
            report.elapsed_ms,
            report.throughput_mbps,
            DEFAULT_LABEL_WIDTH,
            use_color,
        );
    }

    print_panel_footer(
        if report.identical {
            FooterTone::Green
        } else {
            FooterTone::Red
        },
        use_color,
    );
}

/// Print a clean panel showing a computed file digest (when no expected hash was provided).
pub fn print_compute_box(report: &VerifyReport, use_color: bool) {
    print_panel_header("COMPUTED FILE DIGEST", use_color);

    anstream::println!(
        "{} {}",
        format_field_label("Algorithm", use_color),
        report.algorithm
    );
    if use_color {
        anstream::println!(
            "{} {}",
            format_field_label("Digest", true),
            report.actual.as_str().cyan().bold()
        );
    } else {
        anstream::println!("{} {}", format_field_label("Digest", false), report.actual);
    }
    anstream::println!(
        "{} {}",
        format_field_label("File", use_color),
        report.file
    );
    print_metrics_rows(
        report.bytes,
        report.elapsed_ms,
        report.throughput_mbps,
        DEFAULT_LABEL_WIDTH,
        use_color,
    );
    print_panel_footer(FooterTone::Cyan, use_color);
}

/// Print a clean panel showing all digests computed in a single-pass multi-algorithm run.
pub fn print_multi_compute_box(report: &MultiComputeReport, use_color: bool) {
    let title = format!("COMPUTED FILE DIGESTS ({})", report.digests.len());
    print_panel_header(&title, use_color);

    let label_width = report
        .digests
        .iter()
        .map(|item| item.algorithm.chars().count())
        .max()
        .unwrap_or(0)
        .max(DEFAULT_LABEL_WIDTH);

    anstream::println!(
        "{} {}",
        format_field_label_width("File", label_width, use_color),
        report.file
    );
    print_metrics_rows(
        report.bytes,
        report.elapsed_ms,
        report.throughput_mbps,
        label_width,
        use_color,
    );

    for item in &report.digests {
        let label = format_field_label_width(&item.algorithm, label_width, use_color);
        if use_color {
            anstream::println!("{label} {}", item.digest.as_str().cyan().bold());
        } else {
            anstream::println!("{label} {}", item.digest);
        }
    }

    print_panel_footer(FooterTone::Cyan, use_color);
}

fn format_algorithm_menu(
    choices: &[HashAlgorithm],
    default_algo: HashAlgorithm,
    use_color: bool,
) -> String {
    let mut out = String::from("Select hash algorithm:\n");
    let mut default_index = None;

    for (idx, &algo) in choices.iter().enumerate() {
        let num = idx + 1;
        if algo == default_algo {
            default_index = Some(num);
            if use_color {
                let key_tag = format!("[{num}]").cyan().bold();
                let def_tag = format!("(default) [Enter / {num}]").green().bold();
                let _ = writeln!(out, "  {key_tag} {algo} {def_tag}");
            } else {
                let _ = writeln!(out, "  [{num}] {algo} (default) [Enter / {num}]");
            }
        } else if use_color {
            let key_tag = format!("[{num}]").cyan();
            let _ = writeln!(out, "  {key_tag} {algo}");
        } else {
            let _ = writeln!(out, "  [{num}] {algo}");
        }
    }

    let total = choices.len();
    if use_color {
        let all_tag = "[A]".yellow().bold();
        let cancel_tag = "[Esc / Ctrl+C]".dark_grey();
        let _ = writeln!(out, "  {all_tag} All algorithms ({total} in single pass)");
        let _ = writeln!(out, "  {cancel_tag} Cancel");
    } else {
        let _ = writeln!(out, "  [A] All algorithms ({total} in single pass)");
        let _ = writeln!(out, "  [Esc / Ctrl+C] Cancel");
    }

    match default_index {
        Some(num) => {
            let _ = write!(out, "Choice [Enter / {num}]: ");
        }
        None => {
            let _ = write!(out, "Choice [Enter = {default_algo}]: ");
        }
    }

    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyAction {
    Selected(GetHashSelection),
    Cancelled,
    Ignore,
}

fn parse_selection_key(
    key: KeyEvent,
    choices: &[HashAlgorithm],
    default_algo: HashAlgorithm,
) -> KeyAction {
    if key.kind != KeyEventKind::Press {
        return KeyAction::Ignore;
    }

    match key.code {
        KeyCode::Enter => KeyAction::Selected(GetHashSelection::Single(default_algo)),
        KeyCode::Esc => KeyAction::Cancelled,
        KeyCode::Char('c' | 'C') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            KeyAction::Cancelled
        }
        KeyCode::Char('a' | 'A')
            if !key
                .modifiers
                .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
        {
            KeyAction::Selected(GetHashSelection::All)
        }
        KeyCode::Char(ch)
            if !key
                .modifiers
                .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
        {
            let Some(digit) = ch.to_digit(10) else {
                return KeyAction::Ignore;
            };
            let Ok(one_based) = usize::try_from(digit) else {
                return KeyAction::Ignore;
            };
            let Some(idx) = one_based.checked_sub(1) else {
                return KeyAction::Ignore;
            };
            choices
                .get(idx)
                .copied()
                .map_or(KeyAction::Ignore, |algo| {
                    KeyAction::Selected(GetHashSelection::Single(algo))
                })
        }
        _ => KeyAction::Ignore,
    }
}

fn parse_selection_input(
    raw: &str,
    choices: &[HashAlgorithm],
    default_algo: HashAlgorithm,
) -> std::io::Result<GetHashSelection> {
    if choices.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "no hash algorithms available",
        ));
    }

    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(GetHashSelection::Single(default_algo));
    }
    if trimmed.eq_ignore_ascii_case("a") || trimmed.eq_ignore_ascii_case("all") {
        return Ok(GetHashSelection::All);
    }
    if let Ok(one_based) = trimmed.parse::<usize>() {
        return one_based
            .checked_sub(1)
            .and_then(|idx| choices.get(idx).copied())
            .map(GetHashSelection::Single)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("selection out of range: '{trimmed}'"),
                )
            });
    }
    if let Some(algo) = HashAlgorithm::from_alias(trimmed) {
        return Ok(GetHashSelection::Single(algo));
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!("invalid algorithm selection: '{trimmed}'"),
    ))
}

fn run_selection_prompt<W: std::io::Write>(
    writer: &mut W,
    choices: &[HashAlgorithm],
    default_algo: HashAlgorithm,
    use_color: bool,
) -> std::io::Result<Option<GetHashSelection>> {
    let menu = format_algorithm_menu(choices, default_algo, use_color);
    writer.write_all(menu.as_bytes())?;
    writer.flush()?;

    if let Some(guard) = RawModeGuard::acquire() {
        let selection = loop {
            let key = next_key_press()?;
            match parse_selection_key(key, choices, default_algo) {
                KeyAction::Selected(sel) => break Some(sel),
                KeyAction::Cancelled => break None,
                KeyAction::Ignore => {}
            }
        };
        drop(guard);
        let _ = writeln!(writer);
        let _ = writer.flush();
        return Ok(selection);
    }

    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let _ = writeln!(writer);
    let _ = writer.flush();
    parse_selection_input(&line, choices, default_algo).map(Some)
}

/// Prompt the user to select a single algorithm from `choices` or all algorithms in one pass,
/// routing the menu to `stream` and respecting `no_color_flag`.
///
/// Uses raw single-key input when `stdin` is an interactive terminal (`Enter` selects
/// `default_algo`, `1..=choices.len()` selects an item, `A` selects all, and `Esc`/`Ctrl+C`
/// cancels returning `Ok(None)`). Falls back to line-based parsing when `stdin` is piped.
///
/// # Errors
///
/// Returns an `io::Error` if `choices` is empty, terminal I/O fails, or piped input cannot be
/// mapped to a valid selection (`ErrorKind::InvalidInput`).
pub fn prompt_algorithm_selection_on(
    choices: &[HashAlgorithm],
    default_algo: HashAlgorithm,
    stream: PromptStream,
    no_color_flag: bool,
) -> std::io::Result<Option<GetHashSelection>> {
    if choices.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "no hash algorithms available",
        ));
    }

    let use_color = should_use_color_for_stream(no_color_flag, stream);
    match stream {
        PromptStream::Stdout => {
            let mut stdout = anstream::stdout();
            run_selection_prompt(&mut stdout, choices, default_algo, use_color)
        }
        PromptStream::Stderr => {
            let mut stderr = anstream::stderr();
            run_selection_prompt(&mut stderr, choices, default_algo, use_color)
        }
    }
}

/// Prompt the user to select a single algorithm from `choices` or all algorithms in one pass
/// on `stdout`.
///
/// # Errors
///
/// Returns an `io::Error` if `choices` is empty, terminal I/O fails, or piped input cannot be
/// mapped to a valid selection (`ErrorKind::InvalidInput`).
pub fn prompt_algorithm_selection(
    choices: &[HashAlgorithm],
    default_algo: HashAlgorithm,
) -> std::io::Result<Option<GetHashSelection>> {
    prompt_algorithm_selection_on(choices, default_algo, PromptStream::Stdout, false)
}

/// Create an `indicatif` progress bar on `stderr` only when `total_bytes >= 32 MiB`.
#[must_use]
pub fn make_progress_bar(total_bytes: u64) -> Option<ProgressBar> {
    if total_bytes < PROGRESS_THRESHOLD_BYTES {
        return None;
    }

    let pb = ProgressBar::new(total_bytes);
    pb.set_draw_target(ProgressDrawTarget::stderr());
    let style = ProgressStyle::with_template(
        "{spinner:.green} [{elapsed_precise}] [{bar:36.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, ETA {eta})",
    )
    .unwrap_or_else(|_| ProgressStyle::default_bar())
    .progress_chars("#>-");
    pb.set_style(style);
    Some(pb)
}

/// Print `prompt`, flush `stdout`, and wait for a single key press event.
///
/// Falls back to reading a line (or returning on EOF) if `stdin` is not a TTY
/// or raw mode cannot be enabled. Always restores terminal mode via a `Drop` guard.
pub fn wait_for_any_key(prompt: &str) {
    let mut stdout = std::io::stdout();
    let _ = stdout.write_all(prompt.as_bytes());
    let _ = stdout.flush();

    let Some(guard) = RawModeGuard::acquire() else {
        let mut fallback = String::new();
        let _ = std::io::stdin().read_line(&mut fallback);
        return;
    };

    let _ = next_key_press();
    drop(guard);

    let _ = writeln!(stdout);
    let _ = stdout.flush();
}

#[cfg(test)]
mod tests {
    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};

    use super::{
        GetHashSelection, KeyAction, PROGRESS_THRESHOLD_BYTES, center_line, format_algorithm_menu,
        format_mismatch_actual, format_size, format_with_commas, make_progress_bar,
        parse_selection_input, parse_selection_key,
    };
    use crate::algo::{DEFAULT_COMPUTE_ALGORITHM, HashAlgorithm};

    fn key_press(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent {
            code,
            modifiers,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    #[test]
    fn commas_format_correctly() {
        assert_eq!(format_with_commas(0), "0");
        assert_eq!(format_with_commas(999), "999");
        assert_eq!(format_with_commas(1_000), "1,000");
        assert_eq!(format_with_commas(1_048_576), "1,048,576");
    }

    #[test]
    fn size_formats_human_and_exact_bytes() {
        assert_eq!(format_size(0), "0 bytes");
        assert_eq!(format_size(1), "1 byte");
        assert_eq!(format_size(2048), "2.00 KiB (2,048 bytes)");
        assert_eq!(
            format_size(32 * 1024 * 1024),
            "32.00 MiB (33,554,432 bytes)"
        );
    }

    #[test]
    fn progress_bar_obeys_32_mib_threshold() {
        assert!(make_progress_bar(0).is_none());
        assert!(make_progress_bar(PROGRESS_THRESHOLD_BYTES - 1).is_none());
        let pb = make_progress_bar(PROGRESS_THRESHOLD_BYTES);
        assert!(pb.is_some());
        if let Some(bar) = pb {
            bar.finish_and_clear();
        }
    }

    #[test]
    fn center_line_preserves_exact_width() {
        let line = center_line("IDENTICAL", 21);
        assert_eq!(line.chars().count(), 21);
        assert_eq!(line.trim(), "IDENTICAL");
    }

    #[test]
    fn plain_mismatch_digest_is_verbatim() {
        let actual = "abcdef0123456789";
        assert_eq!(
            format_mismatch_actual("0000000000000000", actual, false),
            actual
        );
    }

    #[test]
    fn algorithm_menu_renders_dynamically() {
        let choices = HashAlgorithm::picker_order();
        let menu = format_algorithm_menu(choices, DEFAULT_COMPUTE_ALGORITHM, false);
        for (idx, algo) in choices.iter().enumerate() {
            let num = idx + 1;
            let expected_prefix = format!("[{num}] {algo}");
            assert!(menu.contains(&expected_prefix), "missing {expected_prefix}");
        }
        assert!(menu.contains("(default)"));
        assert!(menu.contains("[Enter / 1]"));
        assert!(menu.contains(&format!(
            "[A] All algorithms ({} in single pass)",
            choices.len()
        )));
        assert!(menu.contains("[Esc / Ctrl+C] Cancel"));

        let subset = [
            HashAlgorithm::Md5,
            HashAlgorithm::Sha384,
            HashAlgorithm::Blake3,
        ];
        let subset_menu = format_algorithm_menu(&subset, HashAlgorithm::Sha384, false);
        assert!(subset_menu.contains("[2] SHA-384 (default) [Enter / 2]"));
        assert!(subset_menu.contains("[A] All algorithms (3 in single pass)"));
    }

    #[test]
    fn line_parser_handles_all_branches() {
        let choices = HashAlgorithm::picker_order();
        let default = DEFAULT_COMPUTE_ALGORITHM;

        assert_eq!(
            parse_selection_input("", choices, default).expect("empty uses default"),
            GetHashSelection::Single(default)
        );
        assert_eq!(
            parse_selection_input("  \r\n", choices, default).expect("whitespace uses default"),
            GetHashSelection::Single(default)
        );

        for (idx, &algo) in choices.iter().enumerate() {
            let input = format!("{}", idx + 1);
            assert_eq!(
                parse_selection_input(&input, choices, default).expect("numeric index"),
                GetHashSelection::Single(algo)
            );
        }

        for all_token in ["a", "A", "all", "ALL", " All "] {
            assert_eq!(
                parse_selection_input(all_token, choices, default).expect("all token"),
                GetHashSelection::All
            );
        }

        for &algo in HashAlgorithm::all() {
            assert_eq!(
                parse_selection_input(algo.cli_name(), choices, default).expect("cli alias"),
                GetHashSelection::Single(algo)
            );
            assert_eq!(
                parse_selection_input(algo.as_str(), choices, default).expect("display alias"),
                GetHashSelection::Single(algo)
            );
        }

        let zero_err = parse_selection_input("0", choices, default).expect_err("0 out of range");
        assert_eq!(zero_err.kind(), std::io::ErrorKind::InvalidInput);

        let high_err =
            parse_selection_input(&(choices.len() + 1).to_string(), choices, default)
                .expect_err("index beyond len");
        assert_eq!(high_err.kind(), std::io::ErrorKind::InvalidInput);

        let bad_err =
            parse_selection_input("not-an-algo", choices, default).expect_err("invalid string");
        assert_eq!(bad_err.kind(), std::io::ErrorKind::InvalidInput);

        let empty_choices_err =
            parse_selection_input("", &[], default).expect_err("empty choices invalid");
        assert_eq!(empty_choices_err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn key_parser_handles_press_cancel_and_ignored_keys() {
        let choices = HashAlgorithm::picker_order();
        let default = DEFAULT_COMPUTE_ALGORITHM;

        assert_eq!(
            parse_selection_key(
                key_press(KeyCode::Enter, KeyModifiers::NONE),
                choices,
                default
            ),
            KeyAction::Selected(GetHashSelection::Single(default))
        );
        assert_eq!(
            parse_selection_key(
                key_press(KeyCode::Char('a'), KeyModifiers::NONE),
                choices,
                default
            ),
            KeyAction::Selected(GetHashSelection::All)
        );
        assert_eq!(
            parse_selection_key(
                key_press(KeyCode::Char('A'), KeyModifiers::SHIFT),
                choices,
                default
            ),
            KeyAction::Selected(GetHashSelection::All)
        );
        assert_eq!(
            parse_selection_key(
                key_press(KeyCode::Char('2'), KeyModifiers::NONE),
                choices,
                default
            ),
            KeyAction::Selected(GetHashSelection::Single(choices[1]))
        );
        assert_eq!(
            parse_selection_key(key_press(KeyCode::Esc, KeyModifiers::NONE), choices, default),
            KeyAction::Cancelled
        );
        assert_eq!(
            parse_selection_key(
                key_press(KeyCode::Char('c'), KeyModifiers::CONTROL),
                choices,
                default
            ),
            KeyAction::Cancelled
        );
        assert_eq!(
            parse_selection_key(
                key_press(KeyCode::Char('0'), KeyModifiers::NONE),
                choices,
                default
            ),
            KeyAction::Ignore
        );
        assert_eq!(
            parse_selection_key(
                key_press(KeyCode::Char('9'), KeyModifiers::NONE),
                choices,
                default
            ),
            KeyAction::Ignore
        );
        assert_eq!(
            parse_selection_key(key_press(KeyCode::Tab, KeyModifiers::NONE), choices, default),
            KeyAction::Ignore
        );

        let release = KeyEvent {
            code: KeyCode::Enter,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Release,
            state: KeyEventState::NONE,
        };
        assert_eq!(
            parse_selection_key(release, choices, default),
            KeyAction::Ignore
        );
    }
}
