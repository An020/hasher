#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use std::collections::{HashSet, VecDeque};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arboard::Clipboard;
use eframe::egui::{
    self, Align, Align2, CollapsingHeader, Color32, ComboBox, CornerRadius, FontFamily, FontId,
    Frame, Id, Key, Label, LayerId, Layout, Margin, Order, ProgressBar, RichText, ScrollArea,
    Stroke, StrokeKind, TextEdit, TopBottomPanel, Vec2, ViewportBuilder,
};
use hasher::algo::HashAlgorithm;
use hasher::batch::{
    BatchTargetRef, bounded_parallel_workers, canonical_path_key, hash_file_dialog_extensions,
    is_dedicated_checksum_extension, is_text_or_checksum_extension, natural_cmp,
    plan_manifest_assignments, scan_folder_for_batch, should_warn_large_parallel_batch,
};
use hasher::digest::{
    MAX_HASH_FILE_BYTES, ParsedDigest, parse_digest_entries_from_file,
    parse_digest_entries_from_str, parse_digest_from_file, parse_digest_str,
};
use hasher::verify::{VerifyReport, compute_only, verify_target};
use rfd::FileDialog;

const BYTES_PER_MIB: f64 = 1024.0 * 1024.0;

fn main() -> eframe::Result {
    let native_options = eframe::NativeOptions {
        viewport: ViewportBuilder::default()
            .with_title("Hasher - File Hash Verifier")
            .with_inner_size([880.0, 620.0])
            .with_min_inner_size([640.0, 440.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Hasher",
        native_options,
        Box::new(|cc| Ok(Box::new(HasherApp::new(cc)))),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveTab {
    SingleFile,
    BatchCheck,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AlgorithmChoice {
    Auto,
    Specific(HashAlgorithm),
}

impl AlgorithmChoice {
    fn dropdown_options() -> impl Iterator<Item = Self> {
        std::iter::once(Self::Auto).chain(
            HashAlgorithm::picker_order()
                .iter()
                .copied()
                .map(Self::Specific),
        )
    }

    fn label(self) -> &'static str {
        match self {
            Self::Auto => "Auto (by length)",
            Self::Specific(algo) => algo.as_str(),
        }
    }

    fn to_override(self) -> Option<HashAlgorithm> {
        match self {
            Self::Auto => None,
            Self::Specific(algo) => Some(algo),
        }
    }

    fn compute_algorithm(self) -> HashAlgorithm {
        match self {
            Self::Auto => HashAlgorithm::DEFAULT_COMPUTE_ALGORITHM,
            Self::Specific(algo) => algo,
        }
    }
}

enum JobMode {
    Verify(ParsedDigest),
    ComputeOnly(HashAlgorithm),
}

struct RunningJob {
    bytes_read: Arc<AtomicU64>,
    total_bytes: u64,
    cancel_flag: Arc<AtomicBool>,
    started_at: Instant,
    receiver: Receiver<Result<VerifyReport, String>>,
}

enum AppOutcome {
    Report(VerifyReport),
    Error(String),
}

enum BatchRowState {
    Idle,
    Queued,
    Running {
        bytes_read: Arc<AtomicU64>,
        total_bytes: u64,
        started_at: Instant,
    },
    Finished(VerifyReport),
    Cancelled,
    Error(String),
}

struct BatchRow {
    id: u64,
    path: PathBuf,
    canonical_key: PathBuf,
    relative_label: String,
    size_bytes: u64,
    expected_input: String,
    algo_choice: AlgorithmChoice,
    state: BatchRowState,
}

struct BatchTask {
    row_id: u64,
    path: PathBuf,
    expected: ParsedDigest,
    total_bytes: u64,
}

enum BatchWorkerMsg {
    Started {
        row_id: u64,
        bytes_read: Arc<AtomicU64>,
        total_bytes: u64,
        started_at: Instant,
    },
    Finished {
        row_id: u64,
        result: Result<VerifyReport, String>,
    },
    AllDone,
}

struct BatchRun {
    cancel_flag: Arc<AtomicBool>,
    receiver: Receiver<BatchWorkerMsg>,
}

enum PendingBatchConfirm {
    MissingHashes {
        missing_count: usize,
        filled_count: usize,
    },
    LargeParallelBatch {
        file_count: usize,
        total_bytes: u64,
    },
}

#[derive(Default)]
struct BatchState {
    folder_input: String,
    include_subfolders: bool,
    rows: Vec<BatchRow>,
    next_row_id: u64,
    running: Option<BatchRun>,
    pending_confirm: Option<PendingBatchConfirm>,
    info_message: Option<String>,
    error_message: Option<String>,
}

struct HasherApp {
    active_tab: ActiveTab,
    file_path: String,
    expected_input: String,
    algo_choice: AlgorithmChoice,
    running: Option<RunningJob>,
    outcome: Option<AppOutcome>,
    info_message: Option<String>,
    copied_until: Option<Instant>,
    cached_target_size: (String, Option<u64>),
    batch: BatchState,
}

impl HasherApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        cc.egui_ctx.style_mut(|style| {
            style.spacing.item_spacing = Vec2::new(8.0, 8.0);
        });
        Self::from_args(std::env::args().skip(1))
    }

    fn from_args<I>(args: I) -> Self
    where
        I: IntoIterator<Item = String>,
    {
        let raw_args: Vec<String> = args
            .into_iter()
            .map(|arg| strip_surrounding_quotes(&arg))
            .filter(|arg| !arg.is_empty())
            .collect();

        let mut app = Self {
            active_tab: ActiveTab::SingleFile,
            file_path: String::new(),
            expected_input: String::new(),
            algo_choice: AlgorithmChoice::Auto,
            running: None,
            outcome: None,
            info_message: None,
            copied_until: None,
            cached_target_size: (String::new(), None),
            batch: BatchState::default(),
        };

        let paths: Vec<PathBuf> = raw_args.iter().map(PathBuf::from).collect();
        let has_dir = paths.iter().any(|p| p.is_dir());
        let non_checksum_count = paths
            .iter()
            .filter(|p| p.is_file() && !is_text_or_checksum_extension(p))
            .count();
        if has_dir || non_checksum_count >= 2 || raw_args.len() > 2 {
            app.active_tab = ActiveTab::BatchCheck;
            app.import_batch_selection(&paths);
            return app;
        }

        let mut iter = raw_args.into_iter().take(2);
        let first_raw = iter.next();
        let second_raw = iter.next();

        let (file_arg, hash_arg) = match (first_raw, second_raw) {
            (Some(first), Some(second)) => resolve_startup_pair(first, second),
            (Some(first), None) => (first, String::new()),
            (None, _) => (String::new(), String::new()),
        };

        app.file_path = file_arg;
        app.refresh_target_size();

        if !hash_arg.is_empty() {
            let hash_path = Path::new(&hash_arg);
            if hash_path.is_file() {
                app.load_expected_from_file(hash_path);
            } else {
                app.expected_input = hash_arg;
            }
        }

        app
    }

    fn clean_file_path(&self) -> String {
        strip_surrounding_quotes(&self.file_path)
    }

    fn refresh_target_size(&mut self) {
        let cleaned = self.clean_file_path();
        if cleaned == self.cached_target_size.0 && !cleaned.is_empty() {
            return;
        }
        let size = if cleaned.is_empty() {
            None
        } else {
            std::fs::metadata(&cleaned)
                .ok()
                .filter(std::fs::Metadata::is_file)
                .map(|meta| meta.len())
        };
        self.cached_target_size = (cleaned, size);
    }

    fn set_target_file(&mut self, path: &Path) {
        self.file_path = path.to_string_lossy().into_owned();
        self.outcome = None;
        self.info_message = None;
        self.refresh_target_size();
    }

    fn load_expected_from_file(&mut self, hash_file: &Path) {
        let cleaned_target = self.clean_file_path();
        let target_opt = (!cleaned_target.is_empty()).then(|| Path::new(&cleaned_target));
        let override_algo = self.algo_choice.to_override();

        match parse_digest_from_file(hash_file, target_opt, override_algo) {
            Ok(parsed) => {
                self.expected_input = parsed.hex;
                if parsed.explicit_algo && self.algo_choice == AlgorithmChoice::Auto {
                    self.algo_choice = AlgorithmChoice::Specific(parsed.algorithm);
                }
                self.outcome = None;
                let file_label = hash_file.file_name().map_or_else(
                    || hash_file.display().to_string(),
                    |name| name.to_string_lossy().into_owned(),
                );
                let algo_name = parsed.algorithm.as_str();
                self.info_message = Some(format!("Loaded {algo_name} hash from {file_label}."));
            }
            Err(err) => {
                let file_display = hash_file.display();
                self.info_message = None;
                self.outcome = Some(AppOutcome::Error(format!(
                    "Could not extract hash from {file_display}: {err}"
                )));
            }
        }
    }

    fn paste_expected_from_clipboard(&mut self) {
        match read_clipboard_digest_or_raw(self.algo_choice.to_override()) {
            Ok((text, explicit_algo)) => {
                self.expected_input = text;
                if let Some(algo) = explicit_algo
                    && self.algo_choice == AlgorithmChoice::Auto
                {
                    self.algo_choice = AlgorithmChoice::Specific(algo);
                }
                self.outcome = None;
                self.info_message = if self.expected_input.is_empty() {
                    Some("Clipboard text is empty.".to_owned())
                } else if let Some(algo) = explicit_algo {
                    Some(format!("Pasted {} hash from clipboard.", algo.as_str()))
                } else {
                    Some("Pasted hash from clipboard.".to_owned())
                };
            }
            Err(err) => {
                self.info_message = None;
                self.outcome = Some(AppOutcome::Error(err));
            }
        }
    }

    fn pick_target_file(&mut self) {
        if let Some(path) = FileDialog::new().pick_file() {
            self.set_target_file(&path);
        }
    }

    fn pick_hash_file(&mut self) {
        let exts = hash_file_dialog_extensions();
        let picked = FileDialog::new()
            .add_filter("Checksum / Text Files", &exts)
            .add_filter("All Files", &["*"])
            .pick_file();

        if let Some(path) = picked {
            self.load_expected_from_file(&path);
        }
    }

    fn start_verification(&mut self, ctx: &egui::Context) {
        let cleaned = self.clean_file_path();
        if cleaned.is_empty() {
            self.outcome = Some(AppOutcome::Error(
                "Select or enter a target file path first.".to_owned(),
            ));
            return;
        }

        let target_path = PathBuf::from(&cleaned);
        let total_bytes = match std::fs::metadata(&target_path) {
            Ok(meta) if meta.is_file() => meta.len(),
            Ok(_) => {
                self.outcome = Some(AppOutcome::Error(
                    "Selected path is not a regular file.".to_owned(),
                ));
                return;
            }
            Err(err) => {
                self.outcome = Some(AppOutcome::Error(format!("Cannot access file: {err}")));
                return;
            }
        };
        self.cached_target_size = (cleaned, Some(total_bytes));

        let trimmed_expected = self.expected_input.trim();
        let mode = if trimmed_expected.is_empty() {
            JobMode::ComputeOnly(self.algo_choice.compute_algorithm())
        } else {
            match parse_digest_str(trimmed_expected, self.algo_choice.to_override()) {
                Ok(parsed) => JobMode::Verify(parsed),
                Err(err) => {
                    self.outcome = Some(AppOutcome::Error(format!("Invalid expected hash: {err}")));
                    return;
                }
            }
        };

        let bytes_read = Arc::new(AtomicU64::new(0));
        let cancel_flag = Arc::new(AtomicBool::new(false));
        let (sender, receiver) = mpsc::channel::<Result<VerifyReport, String>>();

        let worker_ctx = ctx.clone();
        let worker_bytes = Arc::clone(&bytes_read);
        let worker_cancel = Arc::clone(&cancel_flag);

        std::thread::spawn(move || {
            let mut on_chunk = |_read: u64, _total: u64| {
                worker_ctx.request_repaint();
            };
            let result = match mode {
                JobMode::Verify(expected) => verify_target(
                    &target_path,
                    &expected,
                    Some(&worker_bytes),
                    Some(&worker_cancel),
                    Some(&mut on_chunk),
                ),
                JobMode::ComputeOnly(algo) => compute_only(
                    &target_path,
                    algo,
                    Some(&worker_bytes),
                    Some(&worker_cancel),
                    Some(&mut on_chunk),
                ),
            };
            let mapped = result.map_err(|err| err.to_string());
            let _ = sender.send(mapped);
            worker_ctx.request_repaint();
        });

        self.outcome = None;
        self.info_message = None;
        self.running = Some(RunningJob {
            bytes_read,
            total_bytes,
            cancel_flag,
            started_at: Instant::now(),
            receiver,
        });
    }

    fn poll_worker(&mut self, ctx: &egui::Context) {
        let Some(ref job) = self.running else {
            return;
        };

        match job.receiver.try_recv() {
            Ok(Ok(report)) => {
                self.running = None;
                self.outcome = Some(AppOutcome::Report(report));
            }
            Ok(Err(err_msg)) => {
                let was_cancelled = job.cancel_flag.load(Ordering::Relaxed);
                self.running = None;
                let message = if was_cancelled {
                    "Verification cancelled.".to_owned()
                } else {
                    err_msg
                };
                self.outcome = Some(AppOutcome::Error(message));
            }
            Err(TryRecvError::Disconnected) => {
                self.running = None;
                self.outcome = Some(AppOutcome::Error(
                    "Background hashing thread terminated unexpectedly.".to_owned(),
                ));
            }
            Err(TryRecvError::Empty) => {
                ctx.request_repaint_after(Duration::from_millis(50));
            }
        }
    }

    fn handle_dropped_files(&mut self, ctx: &egui::Context) {
        let dropped = ctx.input(|input| input.raw.dropped_files.clone());
        if dropped.is_empty() {
            return;
        }

        if self.running.is_some() || self.batch.running.is_some() {
            let msg = "Cancel the current operation before dropping new files.".to_owned();
            if self.active_tab == ActiveTab::BatchCheck {
                self.batch.info_message = Some(msg);
            } else {
                self.info_message = Some(msg);
            }
            return;
        }

        let paths: Vec<PathBuf> = dropped.into_iter().filter_map(|file| file.path).collect();
        if paths.is_empty() {
            return;
        }

        let has_dir = paths.iter().any(|p| p.is_dir());
        let non_checksum_count = paths
            .iter()
            .filter(|p| p.is_file() && !is_text_or_checksum_extension(p))
            .count();

        if self.active_tab == ActiveTab::BatchCheck
            || has_dir
            || non_checksum_count >= 2
            || paths.len() > 2
        {
            self.active_tab = ActiveTab::BatchCheck;
            self.import_batch_selection(&paths);
            return;
        }

        if paths.len() >= 2 {
            let first = &paths[0];
            let second = &paths[1];
            if is_small_regular_file(first)
                && is_text_or_checksum_extension(first)
                && !is_text_or_checksum_extension(second)
            {
                self.set_target_file(second);
                self.load_expected_from_file(first);
            } else {
                self.set_target_file(first);
                if is_small_regular_file(second) && is_text_or_checksum_extension(second) {
                    self.load_expected_from_file(second);
                }
            }
            return;
        }

        let dropped_path = &paths[0];
        let has_target = !self.file_path.trim().is_empty();
        if has_target
            && is_small_regular_file(dropped_path)
            && is_dedicated_checksum_extension(dropped_path)
        {
            self.load_expected_from_file(dropped_path);
        } else {
            self.set_target_file(dropped_path);
        }
    }

    fn copy_to_clipboard(&mut self, text: &str) {
        match Clipboard::new().and_then(|mut clipboard| clipboard.set_text(text.to_owned())) {
            Ok(()) => {
                self.copied_until = Some(Instant::now() + Duration::from_secs(2));
                let msg = "Copied hash to clipboard.".to_owned();
                if self.active_tab == ActiveTab::BatchCheck {
                    self.batch.info_message = Some(msg);
                } else {
                    self.info_message = Some(msg);
                }
            }
            Err(err) => {
                let msg = format!("Clipboard copy failed: {err}");
                if self.active_tab == ActiveTab::BatchCheck {
                    self.batch.error_message = Some(msg);
                } else {
                    self.info_message = Some(msg);
                }
            }
        }
    }

    fn import_batch_paths(&mut self, paths: &[PathBuf], base_dir: Option<&Path>) -> (usize, usize) {
        let mut seen: HashSet<PathBuf> = self
            .batch
            .rows
            .iter()
            .map(|row| row.canonical_key.clone())
            .collect();
        let mut added = 0usize;
        let mut skipped_dups = 0usize;

        for path in paths {
            let Ok(meta) = std::fs::metadata(path) else {
                continue;
            };
            if !meta.is_file() {
                continue;
            }
            let key = canonical_path_key(path);
            if !seen.insert(key.clone()) {
                skipped_dups += 1;
                continue;
            }

            let relative_label = base_dir
                .and_then(|root| path.strip_prefix(root).ok())
                .map_or_else(
                    || {
                        path.file_name().map_or_else(
                            || path.display().to_string(),
                            |name| name.to_string_lossy().into_owned(),
                        )
                    },
                    |rel| rel.to_string_lossy().into_owned(),
                );

            self.batch.next_row_id += 1;
            self.batch.rows.push(BatchRow {
                id: self.batch.next_row_id,
                path: path.clone(),
                canonical_key: key,
                relative_label,
                size_bytes: meta.len(),
                expected_input: String::new(),
                algo_choice: AlgorithmChoice::Auto,
                state: BatchRowState::Idle,
            });
            added += 1;
        }

        (added, skipped_dups)
    }

    fn import_batch_folder(&mut self, dir: &Path) {
        self.batch.pending_confirm = None;
        self.batch.error_message = None;
        self.batch.folder_input = dir.display().to_string();

        match scan_folder_for_batch(dir, self.batch.include_subfolders) {
            Ok(scan) => {
                let (added, dups) = self.import_batch_paths(&scan.target_files, Some(dir));
                let mut note = format!("Added {added} file(s) from {}", dir.display());
                if dups > 0 {
                    let _ = write!(note, " ({dups} already listed)");
                }
                note.push('.');

                if scan.checksum_files.len() == 1 {
                    let cs_path = &scan.checksum_files[0];
                    if let Ok(entries) = parse_digest_entries_from_file(cs_path, None) {
                        let label = cs_path.file_name().map_or_else(
                            || cs_path.display().to_string(),
                            |n| n.to_string_lossy().into_owned(),
                        );
                        let summary = self.apply_batch_entries(&entries, &label);
                        self.batch.info_message = Some(format!("{note} {summary}"));
                        return;
                    }
                } else if scan.checksum_files.len() > 1 {
                    let _ = write!(
                        note,
                        " Found {} .txt/checksum files; click Load .txt... to choose one.",
                        scan.checksum_files.len()
                    );
                }

                self.batch.info_message = Some(note);
            }
            Err(err) => {
                self.batch.error_message = Some(format!("Failed to scan folder: {err}"));
            }
        }
    }

    fn import_batch_selection(&mut self, paths: &[PathBuf]) {
        self.batch.pending_confirm = None;
        self.batch.error_message = None;

        let mut dirs = Vec::new();
        let mut target_files = Vec::new();
        let mut checksum_files = Vec::new();

        for path in paths {
            if path.is_dir() {
                dirs.push(path.clone());
            } else if path.is_file() {
                if is_text_or_checksum_extension(path) {
                    checksum_files.push(path.clone());
                } else {
                    target_files.push(path.clone());
                }
            }
        }

        target_files.sort_by(|a, b| {
            let na = a.file_name().unwrap_or_default().to_string_lossy();
            let nb = b.file_name().unwrap_or_default().to_string_lossy();
            natural_cmp(&na, &nb)
        });

        let mut messages = Vec::new();
        for dir in dirs {
            self.import_batch_folder(&dir);
            if let Some(msg) = self.batch.info_message.take() {
                messages.push(msg);
            }
        }

        if !target_files.is_empty() {
            let (added, dups) = self.import_batch_paths(&target_files, None);
            let mut msg = format!("Added {added} file(s).");
            if dups > 0 {
                msg = format!("Added {added} file(s) ({dups} already listed).");
            }
            messages.push(msg);
        }

        for cs_path in checksum_files {
            self.load_batch_hashes_from_file(&cs_path);
            if let Some(msg) = self.batch.info_message.take() {
                messages.push(msg);
            }
        }

        if !messages.is_empty() {
            self.batch.info_message = Some(messages.join(" "));
        }
    }

    fn apply_batch_entries(
        &mut self,
        entries: &[(Option<String>, ParsedDigest)],
        source_label: &str,
    ) -> String {
        self.batch.pending_confirm = None;
        if self.batch.rows.is_empty() {
            let msg = format!(
                "Loaded {} hash entry(s) from {source_label}, but no target files are imported yet.",
                entries.len()
            );
            self.batch.error_message = Some(msg.clone());
            return msg;
        }

        let plan = {
            let targets: Vec<BatchTargetRef<'_>> = self
                .batch
                .rows
                .iter()
                .map(|row| BatchTargetRef {
                    path: &row.path,
                    relative_label: &row.relative_label,
                })
                .collect();
            plan_manifest_assignments(&targets, entries)
        };

        for (idx, parsed) in &plan.assignments {
            if let Some(row) = self.batch.rows.get_mut(*idx) {
                row.expected_input.clone_from(&parsed.hex);
                row.algo_choice = if parsed.explicit_algo {
                    AlgorithmChoice::Specific(parsed.algorithm)
                } else {
                    AlgorithmChoice::Auto
                };
                row.state = BatchRowState::Idle;
            }
        }

        let filled_total = self
            .batch
            .rows
            .iter()
            .filter(|r| !r.expected_input.trim().is_empty())
            .count();
        let remaining_blank = self.batch.rows.len().saturating_sub(filled_total);

        let mut summary = format!(
            "Auto-filled {} hash(es) from {source_label} ({} matched by path, {} positional).",
            plan.assignments.len(),
            plan.matched_by_path,
            plan.matched_positionally
        );
        if plan.unmatched_entries > 0 {
            let _ = write!(
                summary,
                " {} extra/unmatched entry(s) ignored.",
                plan.unmatched_entries
            );
        }
        if remaining_blank > 0 {
            let _ = write!(summary, " {remaining_blank} row(s) still need hashes.");
        }

        self.batch.error_message = None;
        self.batch.info_message = Some(summary.clone());
        summary
    }

    fn load_batch_hashes_from_file(&mut self, path: &Path) {
        let label = path.file_name().map_or_else(
            || path.display().to_string(),
            |name| name.to_string_lossy().into_owned(),
        );
        match parse_digest_entries_from_file(path, None) {
            Ok(entries) => {
                self.apply_batch_entries(&entries, &label);
            }
            Err(err) => {
                self.batch.error_message =
                    Some(format!("Could not load hashes from {label}: {err}"));
            }
        }
    }

    fn paste_batch_hash_list(&mut self) {
        self.batch.pending_confirm = None;
        match Clipboard::new().and_then(|mut cb| cb.get_text()) {
            Ok(text) => {
                let entries = parse_digest_entries_from_str(&text, None);
                if entries.is_empty() {
                    self.batch.error_message =
                        Some("Clipboard does not contain any valid hash lines.".to_owned());
                } else {
                    self.apply_batch_entries(&entries, "clipboard");
                }
            }
            Err(err) => {
                self.batch.error_message = Some(format!("Clipboard read failed: {err}"));
            }
        }
    }

    fn paste_into_batch_row(&mut self, row_id: u64) {
        let Some(row) = self.batch.rows.iter_mut().find(|r| r.id == row_id) else {
            return;
        };
        match read_clipboard_digest_or_raw(row.algo_choice.to_override()) {
            Ok((text, explicit_algo)) => {
                if text.is_empty() {
                    self.batch.info_message = Some("Clipboard text is empty.".to_owned());
                    return;
                }
                row.expected_input = text;
                if let Some(algo) = explicit_algo
                    && row.algo_choice == AlgorithmChoice::Auto
                {
                    row.algo_choice = AlgorithmChoice::Specific(algo);
                }
                row.state = BatchRowState::Idle;
                self.batch.pending_confirm = None;
                self.batch.error_message = None;
            }
            Err(err) => {
                self.batch.error_message = Some(err);
            }
        }
    }

    fn pick_batch_folder(&mut self) {
        if let Some(dir) = FileDialog::new().pick_folder() {
            self.import_batch_folder(&dir);
        }
    }

    fn pick_batch_files(&mut self) {
        if let Some(paths) = FileDialog::new().pick_files() {
            self.import_batch_selection(&paths);
        }
    }

    fn pick_batch_hash_file(&mut self) {
        let exts = hash_file_dialog_extensions();
        if let Some(path) = FileDialog::new()
            .add_filter("Checksum / Text Files", &exts)
            .add_filter("All Files", &["*"])
            .pick_file()
        {
            self.load_batch_hashes_from_file(&path);
        }
    }

    fn start_single_batch_row(&mut self, row_id: u64, ctx: &egui::Context) {
        if self.batch.running.is_some() {
            return;
        }
        self.batch.pending_confirm = None;
        self.batch.error_message = None;

        let Some(row) = self.batch.rows.iter_mut().find(|r| r.id == row_id) else {
            return;
        };
        let trimmed = row.expected_input.trim();
        if trimmed.is_empty() {
            row.state = BatchRowState::Error("Enter an expected hash first.".to_owned());
            return;
        }
        let parsed = match parse_digest_str(trimmed, row.algo_choice.to_override()) {
            Ok(p) => p,
            Err(err) => {
                row.state = BatchRowState::Error(format!("Invalid expected hash: {err}"));
                return;
            }
        };
        let total_bytes = match std::fs::metadata(&row.path) {
            Ok(meta) if meta.is_file() => {
                row.size_bytes = meta.len();
                meta.len()
            }
            Ok(_) => {
                row.state = BatchRowState::Error("Target path is not a regular file.".to_owned());
                return;
            }
            Err(err) => {
                row.state = BatchRowState::Error(format!("Cannot access file: {err}"));
                return;
            }
        };

        row.state = BatchRowState::Queued;
        let task = BatchTask {
            row_id: row.id,
            path: row.path.clone(),
            expected: parsed,
            total_bytes,
        };
        self.launch_batch_tasks(vec![task], 1, ctx);
    }

    fn request_check_all(&mut self, ctx: &egui::Context) {
        if self.batch.running.is_some() || self.batch.rows.is_empty() {
            return;
        }
        self.batch.error_message = None;
        self.batch.pending_confirm = None;

        let filled_count = self
            .batch
            .rows
            .iter()
            .filter(|r| !r.expected_input.trim().is_empty())
            .count();
        if filled_count == 0 {
            self.batch.error_message = Some(
                "Enter or load at least one expected hash before running Check All.".to_owned(),
            );
            return;
        }

        let missing_count = self.batch.rows.len().saturating_sub(filled_count);
        if missing_count > 0 {
            self.batch.pending_confirm = Some(PendingBatchConfirm::MissingHashes {
                missing_count,
                filled_count,
            });
            return;
        }

        self.proceed_check_all_after_missing_check(ctx);
    }

    fn proceed_check_all_after_missing_check(&mut self, ctx: &egui::Context) {
        self.batch.pending_confirm = None;
        let (file_count, total_bytes) = self
            .batch
            .rows
            .iter()
            .filter(|r| !r.expected_input.trim().is_empty())
            .fold((0usize, 0u64), |(cnt, sum), r| {
                let bytes = std::fs::metadata(&r.path).map_or(r.size_bytes, |m| m.len());
                (cnt + 1, sum.saturating_add(bytes))
            });

        if should_warn_large_parallel_batch(file_count, total_bytes) {
            self.batch.pending_confirm = Some(PendingBatchConfirm::LargeParallelBatch {
                file_count,
                total_bytes,
            });
            return;
        }

        let workers = bounded_parallel_workers(total_bytes);
        self.execute_check_all(workers, ctx);
    }

    fn execute_check_all(&mut self, max_workers: usize, ctx: &egui::Context) {
        self.batch.pending_confirm = None;
        self.batch.error_message = None;
        let mut tasks = Vec::new();

        for row in &mut self.batch.rows {
            let trimmed = row.expected_input.trim();
            if trimmed.is_empty() {
                if !matches!(row.state, BatchRowState::Finished(_)) {
                    row.state = BatchRowState::Idle;
                }
                continue;
            }

            let parsed = match parse_digest_str(trimmed, row.algo_choice.to_override()) {
                Ok(p) => p,
                Err(err) => {
                    row.state = BatchRowState::Error(format!("Invalid expected hash: {err}"));
                    continue;
                }
            };

            let total_bytes = match std::fs::metadata(&row.path) {
                Ok(meta) if meta.is_file() => {
                    row.size_bytes = meta.len();
                    meta.len()
                }
                Ok(_) => {
                    row.state = BatchRowState::Error("Path is not a regular file.".to_owned());
                    continue;
                }
                Err(err) => {
                    row.state = BatchRowState::Error(format!("Cannot access file: {err}"));
                    continue;
                }
            };

            row.state = BatchRowState::Queued;
            tasks.push(BatchTask {
                row_id: row.id,
                path: row.path.clone(),
                expected: parsed,
                total_bytes,
            });
        }

        if tasks.is_empty() {
            if self.batch.error_message.is_none() {
                self.batch.error_message = Some("No valid rows are ready to verify.".to_owned());
            }
            return;
        }

        self.launch_batch_tasks(tasks, max_workers, ctx);
    }

    fn launch_batch_tasks(
        &mut self,
        tasks: Vec<BatchTask>,
        max_workers: usize,
        ctx: &egui::Context,
    ) {
        let task_count = tasks.len();
        let worker_count = max_workers.min(task_count).max(1);
        let cancel_flag = Arc::new(AtomicBool::new(false));
        let (sender, receiver) = mpsc::channel::<BatchWorkerMsg>();
        let queue = Arc::new(Mutex::new(VecDeque::from(tasks)));

        let worker_ctx = ctx.clone();
        let batch_cancel = Arc::clone(&cancel_flag);

        std::thread::spawn(move || {
            std::thread::scope(|scope| {
                for _ in 0..worker_count {
                    let q = Arc::clone(&queue);
                    let tx = sender.clone();
                    let cancel = Arc::clone(&batch_cancel);
                    let repaint_ctx = worker_ctx.clone();
                    scope.spawn(move || {
                        run_batch_worker_loop(&q, &tx, &cancel, &repaint_ctx);
                    });
                }
            });
            let _ = sender.send(BatchWorkerMsg::AllDone);
            worker_ctx.request_repaint();
        });

        self.batch.running = Some(BatchRun {
            cancel_flag,
            receiver,
        });
    }

    fn poll_batch_worker(&mut self, ctx: &egui::Context) {
        let mut finished = false;
        let was_cancelled = self
            .batch
            .running
            .as_ref()
            .is_some_and(|run| run.cancel_flag.load(Ordering::Relaxed));

        if let Some(ref run) = self.batch.running {
            loop {
                match run.receiver.try_recv() {
                    Ok(BatchWorkerMsg::Started {
                        row_id,
                        bytes_read,
                        total_bytes,
                        started_at,
                    }) => {
                        if let Some(row) = self.batch.rows.iter_mut().find(|r| r.id == row_id) {
                            row.state = BatchRowState::Running {
                                bytes_read,
                                total_bytes,
                                started_at,
                            };
                        }
                    }
                    Ok(BatchWorkerMsg::Finished { row_id, result }) => {
                        if let Some(row) = self.batch.rows.iter_mut().find(|r| r.id == row_id) {
                            row.state = match result {
                                Ok(report) => BatchRowState::Finished(report),
                                Err(_) if was_cancelled => BatchRowState::Cancelled,
                                Err(err) => BatchRowState::Error(err),
                            };
                        }
                    }
                    Ok(BatchWorkerMsg::AllDone) | Err(TryRecvError::Disconnected) => {
                        finished = true;
                        break;
                    }
                    Err(TryRecvError::Empty) => break,
                }
            }
        }

        if finished {
            self.batch.running = None;
            for row in &mut self.batch.rows {
                if matches!(
                    row.state,
                    BatchRowState::Queued | BatchRowState::Running { .. }
                ) {
                    row.state = if was_cancelled {
                        BatchRowState::Cancelled
                    } else {
                        BatchRowState::Idle
                    };
                }
            }
        } else if self.batch.running.is_some() {
            ctx.request_repaint_after(Duration::from_millis(50));
        }
    }

    fn render_header(ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("Hasher").size(20.0).strong());
            ui.label(
                RichText::new("Fast File Hash Verifier")
                    .size(13.0)
                    .color(ui.visuals().weak_text_color()),
            );
        });
        ui.separator();
    }

    fn render_file_section(&mut self, ui: &mut egui::Ui, running: bool) -> bool {
        let mut enter_pressed = false;
        ui.horizontal(|ui| {
            ui.label(RichText::new("File Path").strong());
            if let Some(size) = self.cached_target_size.1 {
                let formatted = format_bytes(size);
                ui.label(
                    RichText::new(format!("({formatted})"))
                        .size(12.0)
                        .color(ui.visuals().weak_text_color()),
                );
            }
        });

        ui.horizontal(|ui| {
            let edit_width = (ui.available_width() - 92.0).max(140.0);
            let response = ui.add_enabled(
                !running,
                TextEdit::singleline(&mut self.file_path)
                    .hint_text("Drop a file here, browse, or paste path...")
                    .desired_width(edit_width),
            );
            if response.changed() {
                if let Some(unquoted) = unquote_pasted_path(&self.file_path) {
                    self.file_path = unquoted;
                }
                self.outcome = None;
                self.info_message = None;
                self.refresh_target_size();
            }
            if response.lost_focus() && ui.input(|input| input.key_pressed(Key::Enter)) {
                enter_pressed = true;
            }

            if ui
                .add_enabled(
                    !running,
                    egui::Button::new("Browse...").min_size(Vec2::new(84.0, 24.0)),
                )
                .clicked()
            {
                self.pick_target_file();
            }
        });

        ui.label(
            RichText::new("Tip: Drag and drop any file onto this window to select it.")
                .size(11.5)
                .color(ui.visuals().weak_text_color()),
        );

        enter_pressed
    }

    fn render_expected_section(&mut self, ui: &mut egui::Ui, running: bool) -> bool {
        let mut enter_pressed = false;
        ui.label(RichText::new("Expected Hash").strong());

        let response = ui.add_enabled(
            !running,
            TextEdit::singleline(&mut self.expected_input)
                .font(FontId::new(13.0, FontFamily::Monospace))
                .hint_text("Paste hex hash, sha256:..., or GNU/OpenSSL checksum line (leave blank to compute)")
                .desired_width(f32::INFINITY),
        );
        if response.changed() {
            self.outcome = None;
            self.info_message = None;
        }
        if response.lost_focus() && ui.input(|input| input.key_pressed(Key::Enter)) {
            enter_pressed = true;
        }

        ui.horizontal(|ui| {
            if ui
                .add_enabled(!running, egui::Button::new("Paste"))
                .clicked()
            {
                self.paste_expected_from_clipboard();
            }
            if ui
                .add_enabled(!running, egui::Button::new("Load .txt..."))
                .clicked()
            {
                self.pick_hash_file();
            }
            if ui
                .add_enabled(!running, egui::Button::new("Clear"))
                .clicked()
            {
                self.expected_input.clear();
                self.outcome = None;
                self.info_message = None;
            }

            ui.separator();
            ui.label("Algorithm:");
            let previous_algo = self.algo_choice;
            ui.add_enabled_ui(!running, |ui| {
                ComboBox::from_id_salt("algo_dropdown")
                    .selected_text(self.algo_choice.label())
                    .width(150.0)
                    .show_ui(ui, |ui| {
                        for option in AlgorithmChoice::dropdown_options() {
                            ui.selectable_value(&mut self.algo_choice, option, option.label());
                        }
                    });
            });
            if self.algo_choice != previous_algo {
                self.outcome = None;
            }
        });

        self.render_digest_hint(ui);
        enter_pressed
    }

    fn render_digest_hint(&self, ui: &mut egui::Ui) {
        let trimmed = self.expected_input.trim();
        if trimmed.is_empty() {
            let algo_name = self.algo_choice.compute_algorithm().as_str();
            ui.label(
                RichText::new(format!(
                    "Expected Hash is empty - will compute {algo_name} digest."
                ))
                .size(11.5)
                .color(ui.visuals().weak_text_color()),
            );
            return;
        }

        match parse_digest_str(trimmed, self.algo_choice.to_override()) {
            Ok(parsed) => {
                let algo_name = parsed.algorithm.as_str();
                let hex_len = parsed.hex.len();
                ui.label(
                    RichText::new(format!("Detected: {algo_name} ({hex_len} hex chars)"))
                        .size(11.5)
                        .color(Color32::from_rgb(22, 163, 74)),
                );
            }
            Err(err) => {
                ui.label(
                    RichText::new(format!("Digest preview: {err}"))
                        .size(11.5)
                        .color(Color32::from_rgb(217, 119, 6)),
                );
            }
        }
    }

    fn render_action_bar(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, running: bool) {
        let action_label = if self.expected_input.trim().is_empty() {
            "Compute Only"
        } else {
            "Verify"
        };

        let primary_button = egui::Button::new(
            RichText::new(action_label)
                .size(15.0)
                .strong()
                .color(Color32::WHITE),
        )
        .fill(Color32::from_rgb(37, 99, 235))
        .corner_radius(CornerRadius::same(6))
        .min_size(Vec2::new(140.0, 34.0));

        if ui.add_enabled(!running, primary_button).clicked() {
            self.start_verification(ctx);
        }
    }

    fn render_progress(&self, ui: &mut egui::Ui) {
        let Some(ref job) = self.running else {
            return;
        };

        let read = job.bytes_read.load(Ordering::Relaxed);
        let total = job.total_bytes;
        let fraction = progress_fraction(read, total);
        let percent = fraction * 100.0;
        let read_mib = bytes_to_mib(read);
        let total_mib = bytes_to_mib(total);
        let elapsed_secs = job.started_at.elapsed().as_secs_f64().max(1e-6);
        let live_mbps = if read > 0 {
            read_mib / elapsed_secs
        } else {
            0.0
        };

        ui.horizontal(|ui| {
            let bar_width = (ui.available_width() - 98.0).max(120.0);
            ui.add(
                ProgressBar::new(fraction)
                    .text(format!("{percent:.1}%"))
                    .desired_width(bar_width),
            );

            let is_cancelling = job.cancel_flag.load(Ordering::Relaxed);
            let cancel_text = if is_cancelling {
                "Cancelling..."
            } else {
                "Cancel"
            };
            let cancel_btn = egui::Button::new(cancel_text).min_size(Vec2::new(90.0, 22.0));
            if ui.add_enabled(!is_cancelling, cancel_btn).clicked() {
                job.cancel_flag.store(true, Ordering::Relaxed);
            }
        });

        ui.label(
            RichText::new(format!(
                "{read_mib:.1} / {total_mib:.1} MiB   |   {live_mbps:.1} MB/s"
            ))
            .size(12.0)
            .monospace(),
        );
    }

    fn render_outcome(&mut self, ui: &mut egui::Ui) {
        let copy_label = if self
            .copied_until
            .is_some_and(|until| Instant::now() < until)
        {
            "Copied!"
        } else {
            "Copy Hash"
        };

        let mut copy_requested: Option<String> = None;

        if let Some(ref outcome) = self.outcome {
            match outcome {
                AppOutcome::Report(report) => match report.expected.as_deref() {
                    Some(_) if report.identical => {
                        let style = DigestCardStyle {
                            title: "IDENTICAL",
                            title_size: 26.0,
                            fill: Color32::from_rgb(22, 163, 74),
                            border: Color32::from_rgb(21, 128, 61),
                            subtext: Color32::from_rgb(240, 253, 244),
                        };
                        if render_single_digest_card(ui, report, copy_label, style) {
                            copy_requested = Some(report.actual.clone());
                        }
                    }
                    Some(expected_hex) => {
                        if render_mismatch_card(ui, report, expected_hex, copy_label) {
                            copy_requested = Some(report.actual.clone());
                        }
                    }
                    None => {
                        let algo = &report.algorithm;
                        let title = format!("COMPUTED ({algo})");
                        let style = DigestCardStyle {
                            title: &title,
                            title_size: 20.0,
                            fill: Color32::from_rgb(30, 58, 138),
                            border: Color32::from_rgb(59, 130, 246),
                            subtext: Color32::from_rgb(226, 232, 240),
                        };
                        if render_single_digest_card(ui, report, copy_label, style) {
                            copy_requested = Some(report.actual.clone());
                        }
                    }
                },
                AppOutcome::Error(message) => {
                    render_error_card(ui, message);
                }
            }
        }

        if let Some(hash) = copy_requested {
            self.copy_to_clipboard(&hash);
        }
    }

    fn render_single_tab(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, running: bool) {
        ScrollArea::vertical().show(ui, |ui| {
            Frame::new().inner_margin(Margin::same(6)).show(ui, |ui| {
                let file_enter = self.render_file_section(ui, running);
                ui.add_space(8.0);
                let hash_enter = self.render_expected_section(ui, running);
                ui.add_space(10.0);
                self.render_action_bar(ui, ctx, running);

                if !running && (file_enter || hash_enter) {
                    self.start_verification(ctx);
                }

                if self.running.is_some() {
                    ui.add_space(10.0);
                    self.render_progress(ui);
                }

                if let Some(ref info) = self.info_message {
                    ui.add_space(6.0);
                    ui.label(
                        RichText::new(info)
                            .size(12.0)
                            .color(ui.visuals().weak_text_color()),
                    );
                }

                if self.outcome.is_some() {
                    ui.add_space(10.0);
                    self.render_outcome(ui);
                }
            });
        });
    }

    fn render_batch_toolbar(&mut self, ui: &mut egui::Ui, batch_running: bool) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("Folder").strong());
            let edit_width = (ui.available_width() - 325.0).max(160.0);
            let resp = ui.add_enabled(
                !batch_running,
                TextEdit::singleline(&mut self.batch.folder_input)
                    .hint_text("Enter or drop containing folder path...")
                    .desired_width(edit_width),
            );
            if resp.changed() {
                if let Some(unquoted) = unquote_pasted_path(&self.batch.folder_input) {
                    self.batch.folder_input = unquoted;
                }
            }
            let enter_import = resp.lost_focus() && ui.input(|input| input.key_pressed(Key::Enter));

            let import_clicked = ui
                .add_enabled(
                    !batch_running && !self.batch.folder_input.trim().is_empty(),
                    egui::Button::new("Import Folder"),
                )
                .clicked();
            if !batch_running && (enter_import || import_clicked) {
                let cleaned = strip_surrounding_quotes(&self.batch.folder_input);
                if !cleaned.is_empty() {
                    let dir = PathBuf::from(cleaned);
                    self.import_batch_folder(&dir);
                }
            }

            if ui
                .add_enabled(!batch_running, egui::Button::new("Browse Folder..."))
                .clicked()
            {
                self.pick_batch_folder();
            }

            ui.add_enabled_ui(!batch_running, |ui| {
                ui.checkbox(&mut self.batch.include_subfolders, "Include subfolders");
            });
        });

        ui.add_space(4.0);
        ui.horizontal(|ui| {
            if ui
                .add_enabled(!batch_running, egui::Button::new("Select Files..."))
                .clicked()
            {
                self.pick_batch_files();
            }
            if ui
                .add_enabled(!batch_running, egui::Button::new("Load .txt..."))
                .clicked()
            {
                self.pick_batch_hash_file();
            }
            if ui
                .add_enabled(!batch_running, egui::Button::new("Paste List"))
                .clicked()
            {
                self.paste_batch_hash_list();
            }
            if ui
                .add_enabled(
                    !batch_running && !self.batch.rows.is_empty(),
                    egui::Button::new("Clear All"),
                )
                .clicked()
            {
                self.batch.rows.clear();
                self.batch.pending_confirm = None;
                self.batch.error_message = None;
                self.batch.info_message = Some("Cleared batch file list.".to_owned());
            }

            ui.label(
                RichText::new("Tip: Drag files, folders, or hash .txt manifests here.")
                    .size(11.5)
                    .color(ui.visuals().weak_text_color()),
            );
        });
    }

    fn render_batch_confirm(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let Some(confirm) = self.batch.pending_confirm.take() else {
            return;
        };
        let mut next_confirm: Option<PendingBatchConfirm> = Some(confirm);

        Frame::new()
            .fill(Color32::from_rgb(120, 53, 15))
            .stroke(Stroke::new(1.5_f32, Color32::from_rgb(245, 158, 11)))
            .corner_radius(CornerRadius::same(6))
            .inner_margin(Margin::same(10))
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                match next_confirm {
                    Some(PendingBatchConfirm::MissingHashes {
                        missing_count,
                        filled_count,
                    }) => {
                        ui.label(
                            RichText::new(format!(
                                "{missing_count} file(s) are missing hashes and will be skipped ({filled_count} file(s) ready). Continue anyway?"
                            ))
                            .strong()
                            .color(Color32::WHITE),
                        );
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            if ui.button("Skip Empty & Check").clicked() {
                                next_confirm = None;
                                self.proceed_check_all_after_missing_check(ctx);
                            }
                            if ui.button("Cancel").clicked() {
                                next_confirm = None;
                            }
                        });
                    }
                    Some(PendingBatchConfirm::LargeParallelBatch {
                        file_count,
                        total_bytes,
                    }) => {
                        let size_text = format_bytes(total_bytes);
                        let cap = bounded_parallel_workers(total_bytes);
                        ui.label(
                            RichText::new(format!(
                                "{file_count} files totaling {size_text} (> 2.00 GiB) queued. Parallel hashing can saturate disk I/O and slow throughput."
                            ))
                            .strong()
                            .color(Color32::WHITE),
                        );
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            if ui.button("Run Sequentially (Recommended for >2 GiB)").clicked() {
                                next_confirm = None;
                                self.execute_check_all(1, ctx);
                            }
                            if ui
                                .button(format!("Run Bounded Parallel (Max {cap})"))
                                .clicked()
                            {
                                next_confirm = None;
                                self.execute_check_all(cap, ctx);
                            }
                            if ui.button("Cancel").clicked() {
                                next_confirm = None;
                            }
                        });
                    }
                    None => {}
                }
            });

        if self.batch.pending_confirm.is_none() {
            self.batch.pending_confirm = next_confirm;
        }
    }

    fn render_batch_footer(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, batch_running: bool) {
        let total = self.batch.rows.len();
        let mut identical = 0usize;
        let mut mismatch = 0usize;
        let mut errors = 0usize;
        for row in &self.batch.rows {
            match &row.state {
                BatchRowState::Finished(rep) if rep.identical => identical += 1,
                BatchRowState::Finished(_) => mismatch += 1,
                BatchRowState::Error(_) => errors += 1,
                _ => {}
            }
        }
        let pending = total.saturating_sub(identical + mismatch + errors);

        Frame::new()
            .inner_margin(Margin::symmetric(8, 6))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(format!("Total: {total}")).strong());
                    ui.separator();
                    let id_color = if identical > 0 {
                        Color32::from_rgb(22, 163, 74)
                    } else {
                        ui.visuals().text_color()
                    };
                    ui.label(RichText::new(format!("Identical: {identical}")).color(id_color));
                    ui.separator();
                    let mis_color = if mismatch > 0 {
                        Color32::from_rgb(220, 38, 38)
                    } else {
                        ui.visuals().text_color()
                    };
                    ui.label(RichText::new(format!("Mismatch: {mismatch}")).color(mis_color));
                    ui.separator();
                    ui.label(format!("Pending: {pending}"));
                    if errors > 0 {
                        ui.separator();
                        ui.label(
                            RichText::new(format!("Errors: {errors}"))
                                .color(Color32::from_rgb(217, 119, 6)),
                        );
                    }

                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        let check_btn = egui::Button::new(
                            RichText::new("Check All")
                                .size(14.5)
                                .strong()
                                .color(Color32::WHITE),
                        )
                        .fill(Color32::from_rgb(37, 99, 235))
                        .corner_radius(CornerRadius::same(6))
                        .min_size(Vec2::new(136.0, 32.0));

                        if ui
                            .add_enabled(!batch_running && !self.batch.rows.is_empty(), check_btn)
                            .clicked()
                        {
                            self.request_check_all(ctx);
                        }

                        if let Some(ref run) = self.batch.running {
                            let cancelling = run.cancel_flag.load(Ordering::Relaxed);
                            let label = if cancelling {
                                "Cancelling..."
                            } else {
                                "Cancel"
                            };
                            let cancel_btn =
                                egui::Button::new(label).min_size(Vec2::new(92.0, 32.0));
                            if ui.add_enabled(!cancelling, cancel_btn).clicked() {
                                run.cancel_flag.store(true, Ordering::Relaxed);
                            }
                        }
                    });
                });
            });
    }

    fn render_batch_tab(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, batch_running: bool) {
        Frame::new().inner_margin(Margin::same(6)).show(ui, |ui| {
            self.render_batch_toolbar(ui, batch_running);

            if let Some(ref err) = self.batch.error_message {
                ui.add_space(4.0);
                ui.label(
                    RichText::new(err)
                        .size(12.0)
                        .color(Color32::from_rgb(239, 68, 68)),
                );
            } else if let Some(ref info) = self.batch.info_message {
                ui.add_space(4.0);
                ui.label(
                    RichText::new(info)
                        .size(12.0)
                        .color(ui.visuals().weak_text_color()),
                );
            }

            if self.batch.pending_confirm.is_some() {
                ui.add_space(6.0);
                self.render_batch_confirm(ui, ctx);
            }

            ui.add_space(6.0);
            ui.separator();
            ui.add_space(4.0);

            if self.batch.rows.is_empty() {
                ui.vertical_centered(|ui| {
                    ui.add_space(40.0);
                    ui.label(RichText::new("No files imported yet.").size(15.0).strong());
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new(
                            "Import a folder, use Select Files..., or drag & drop files here.",
                        )
                        .color(ui.visuals().weak_text_color()),
                    );
                });
                return;
            }

            let mut deferred_action: Option<BatchRowAction> = None;
            ScrollArea::vertical()
                .id_salt("batch_rows_scroll")
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for row in &mut self.batch.rows {
                        if let Some(act) = render_batch_row(ui, row, batch_running) {
                            deferred_action = Some(act);
                        }
                        ui.add_space(6.0);
                    }
                });

            if let Some(action) = deferred_action {
                match action {
                    BatchRowAction::Paste(id) => self.paste_into_batch_row(id),
                    BatchRowAction::Check(id) => self.start_single_batch_row(id, ctx),
                    BatchRowAction::Remove(id) => {
                        self.batch.rows.retain(|row| row.id != id);
                        self.batch.pending_confirm = None;
                    }
                    BatchRowAction::Copy(text) => self.copy_to_clipboard(&text),
                }
            }
        });
    }
}

impl Drop for HasherApp {
    fn drop(&mut self) {
        if let Some(ref job) = self.running {
            job.cancel_flag.store(true, Ordering::Relaxed);
        }
        if let Some(ref batch) = self.batch.running {
            batch.cancel_flag.store(true, Ordering::Relaxed);
        }
    }
}

impl eframe::App for HasherApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_worker(ctx);
        self.poll_batch_worker(ctx);
        self.handle_dropped_files(ctx);

        if let Some(until) = self.copied_until {
            if Instant::now() >= until {
                self.copied_until = None;
            } else {
                ctx.request_repaint_after(Duration::from_millis(250));
            }
        }

        let running = self.running.is_some();
        let batch_running = self.batch.running.is_some();

        TopBottomPanel::top("hasher_top_bar").show(ctx, |ui| {
            Frame::new()
                .inner_margin(Margin::symmetric(8, 6))
                .show(ui, |ui| {
                    Self::render_header(ui);
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        ui.selectable_value(
                            &mut self.active_tab,
                            ActiveTab::SingleFile,
                            "Single File",
                        );
                        let batch_label = if self.batch.rows.is_empty() {
                            "Batch Check".to_owned()
                        } else {
                            format!("Batch Check ({})", self.batch.rows.len())
                        };
                        ui.selectable_value(
                            &mut self.active_tab,
                            ActiveTab::BatchCheck,
                            batch_label,
                        );
                    });
                });
        });

        if self.active_tab == ActiveTab::BatchCheck {
            TopBottomPanel::bottom("batch_footer").show(ctx, |ui| {
                self.render_batch_footer(ui, ctx, batch_running);
            });
        }

        egui::CentralPanel::default().show(ctx, |ui| match self.active_tab {
            ActiveTab::SingleFile => self.render_single_tab(ui, ctx, running),
            ActiveTab::BatchCheck => self.render_batch_tab(ui, ctx, batch_running),
        });

        let hovering_files = ctx.input(|input| !input.raw.hovered_files.is_empty());
        if hovering_files {
            render_drop_overlay(ctx);
        }
    }
}

enum BatchRowAction {
    Paste(u64),
    Check(u64),
    Remove(u64),
    Copy(String),
}

fn read_clipboard_digest_or_raw(
    override_algo: Option<HashAlgorithm>,
) -> Result<(String, Option<HashAlgorithm>), String> {
    let text = Clipboard::new()
        .and_then(|mut cb| cb.get_text())
        .map_err(|err| format!("Clipboard read failed: {err}"))?;
    let trimmed = text.trim();
    if (trimmed.contains('\n') || trimmed.contains('\r'))
        && let Ok(parsed) = parse_digest_str(trimmed, override_algo)
    {
        let detected = parsed.explicit_algo.then_some(parsed.algorithm);
        return Ok((parsed.hex, detected));
    }
    Ok((trimmed.to_owned(), None))
}

fn run_batch_worker_loop(
    queue: &Arc<Mutex<VecDeque<BatchTask>>>,
    sender: &mpsc::Sender<BatchWorkerMsg>,
    cancel: &Arc<AtomicBool>,
    repaint_ctx: &egui::Context,
) {
    loop {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let task = {
            let Ok(mut guard) = queue.lock() else {
                break;
            };
            guard.pop_front()
        };
        let Some(task) = task else {
            break;
        };

        let bytes_read = Arc::new(AtomicU64::new(0));
        let started_at = Instant::now();
        let _ = sender.send(BatchWorkerMsg::Started {
            row_id: task.row_id,
            bytes_read: Arc::clone(&bytes_read),
            total_bytes: task.total_bytes,
            started_at,
        });
        repaint_ctx.request_repaint();

        let mut on_chunk = |_read: u64, _total: u64| {
            repaint_ctx.request_repaint();
        };
        let result = verify_target(
            &task.path,
            &task.expected,
            Some(&bytes_read),
            Some(cancel),
            Some(&mut on_chunk),
        )
        .map_err(|err| err.to_string());
        let _ = sender.send(BatchWorkerMsg::Finished {
            row_id: task.row_id,
            result,
        });
        repaint_ctx.request_repaint();
    }
}

fn render_batch_row(
    ui: &mut egui::Ui,
    row: &mut BatchRow,
    batch_running: bool,
) -> Option<BatchRowAction> {
    let mut action: Option<BatchRowAction> = None;
    let row_locked = batch_running
        || matches!(
            row.state,
            BatchRowState::Queued | BatchRowState::Running { .. }
        );

    Frame::new()
        .fill(ui.visuals().faint_bg_color)
        .stroke(Stroke::new(
            1.0_f32,
            ui.visuals().widgets.noninteractive.bg_stroke.color,
        ))
        .corner_radius(CornerRadius::same(6))
        .inner_margin(Margin::same(8))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            if let Some(ctrl_act) = render_batch_row_controls(ui, row, row_locked) {
                action = Some(ctrl_act);
            }
            render_batch_row_hint(ui, row);
            ui.add_space(4.0);
            if let Some(copy_act) = render_batch_row_progress(ui, row) {
                action = Some(copy_act);
            }
        });

    action
}

fn render_batch_row_controls(
    ui: &mut egui::Ui,
    row: &mut BatchRow,
    row_locked: bool,
) -> Option<BatchRowAction> {
    let mut action: Option<BatchRowAction> = None;
    ui.horizontal(|ui| {
        let file_title = format!("{} ({})", row.relative_label, format_bytes(row.size_bytes));
        let file_resp = ui.add_sized(
            [220.0, 22.0],
            Label::new(RichText::new(file_title).strong()).truncate(),
        );
        file_resp.on_hover_text(row.path.display().to_string());

        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if ui
                .add_enabled(!row_locked, egui::Button::new("X"))
                .on_hover_text("Remove file")
                .clicked()
            {
                action = Some(BatchRowAction::Remove(row.id));
            }
            if ui
                .add_enabled(!row_locked, egui::Button::new("Check"))
                .clicked()
            {
                action = Some(BatchRowAction::Check(row.id));
            }
            if ui
                .add_enabled(!row_locked, egui::Button::new("Paste"))
                .clicked()
            {
                action = Some(BatchRowAction::Paste(row.id));
            }

            let prev_algo = row.algo_choice;
            ui.add_enabled_ui(!row_locked, |ui| {
                ComboBox::from_id_salt(("batch_algo", row.id))
                    .selected_text(row.algo_choice.label())
                    .width(105.0)
                    .show_ui(ui, |ui| {
                        for option in AlgorithmChoice::dropdown_options() {
                            ui.selectable_value(&mut row.algo_choice, option, option.label());
                        }
                    });
            });
            if row.algo_choice != prev_algo {
                row.state = BatchRowState::Idle;
            }

            let hash_width = ui.available_width().max(120.0);
            let hash_resp = ui.add_enabled(
                !row_locked,
                TextEdit::singleline(&mut row.expected_input)
                    .font(FontId::new(12.5, FontFamily::Monospace))
                    .hint_text("Paste hash for this file...")
                    .desired_width(hash_width),
            );
            if hash_resp.changed() {
                row.state = BatchRowState::Idle;
            }
            if !row_locked && hash_resp.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter)) {
                action = Some(BatchRowAction::Check(row.id));
            }
        });
    });
    action
}

fn render_batch_row_hint(ui: &mut egui::Ui, row: &BatchRow) {
    let trimmed = row.expected_input.trim();
    if trimmed.is_empty() || !matches!(row.state, BatchRowState::Idle | BatchRowState::Cancelled) {
        return;
    }

    match parse_digest_str(trimmed, row.algo_choice.to_override()) {
        Ok(parsed) => {
            let algo_name = parsed.algorithm.as_str();
            let hex_len = parsed.hex.len();
            ui.label(
                RichText::new(format!("Detected: {algo_name} ({hex_len} hex chars)"))
                    .size(11.0)
                    .color(Color32::from_rgb(22, 163, 74)),
            );
        }
        Err(err) => {
            ui.label(
                RichText::new(format!("Digest preview: {err}"))
                    .size(11.0)
                    .color(Color32::from_rgb(217, 119, 6)),
            );
        }
    }
}

fn render_batch_row_progress(ui: &mut egui::Ui, row: &BatchRow) -> Option<BatchRowAction> {
    let bar_width = ui.available_width();

    match &row.state {
        BatchRowState::Idle => {
            ui.add(
                ProgressBar::new(0.0)
                    .text("Ready")
                    .desired_width(bar_width)
                    .desired_height(20.0),
            );
        }
        BatchRowState::Queued => {
            ui.add(
                ProgressBar::new(0.0)
                    .text("Queued...")
                    .desired_width(bar_width)
                    .desired_height(20.0),
            );
        }
        BatchRowState::Running {
            bytes_read,
            total_bytes,
            started_at,
        } => {
            let read = bytes_read.load(Ordering::Relaxed);
            let fraction = progress_fraction(read, *total_bytes);
            let percent = fraction * 100.0;
            let read_mib = bytes_to_mib(read);
            let total_mib = bytes_to_mib(*total_bytes);
            let secs = started_at.elapsed().as_secs_f64().max(1e-6);
            let mbps = if read > 0 { read_mib / secs } else { 0.0 };
            ui.add(
                ProgressBar::new(fraction)
                    .text(format!(
                        "{percent:.1}%   {read_mib:.1} / {total_mib:.1} MiB   |   {mbps:.1} MB/s"
                    ))
                    .desired_width(bar_width)
                    .desired_height(20.0),
            );
        }
        BatchRowState::Finished(report) => {
            return render_batch_row_finished(ui, report, row.id, bar_width);
        }
        BatchRowState::Cancelled => {
            ui.add(
                ProgressBar::new(0.0)
                    .text("Cancelled")
                    .desired_width(bar_width)
                    .desired_height(20.0),
            );
        }
        BatchRowState::Error(msg) => {
            ui.add(
                ProgressBar::new(1.0)
                    .fill(Color32::from_rgb(180, 83, 9))
                    .text(
                        RichText::new(format!("Error: {msg}"))
                            .color(Color32::WHITE)
                            .strong(),
                    )
                    .desired_width(bar_width)
                    .desired_height(22.0),
            );
        }
    }

    None
}

fn render_batch_row_finished(
    ui: &mut egui::Ui,
    report: &VerifyReport,
    row_id: u64,
    bar_width: f32,
) -> Option<BatchRowAction> {
    let mut action = None;
    if report.identical {
        let label = format!(
            "100%   IDENTICAL   ({}  |  {} ms  |  {:.1} MB/s)",
            report.algorithm, report.elapsed_ms, report.throughput_mbps
        );
        ui.horizontal(|ui| {
            let pb_width = (bar_width - 96.0).max(120.0);
            ui.add(
                ProgressBar::new(1.0)
                    .fill(Color32::from_rgb(22, 163, 74))
                    .text(RichText::new(label).color(Color32::WHITE).strong())
                    .desired_width(pb_width)
                    .desired_height(22.0),
            );
            if ui.button("Copy Hash").clicked() {
                action = Some(BatchRowAction::Copy(report.actual.clone()));
            }
        });
        return action;
    }

    let label = format!(
        "100%   NOT IDENTICAL. BE CAUTIOUS.   ({}  |  {} ms)",
        report.algorithm, report.elapsed_ms
    );
    ui.horizontal(|ui| {
        let pb_width = (bar_width - 102.0).max(120.0);
        ui.add(
            ProgressBar::new(1.0)
                .fill(Color32::from_rgb(220, 38, 38))
                .text(RichText::new(label).color(Color32::WHITE).strong())
                .desired_width(pb_width)
                .desired_height(22.0),
        );
        if ui.button("Copy Actual").clicked() {
            action = Some(BatchRowAction::Copy(report.actual.clone()));
        }
    });
    CollapsingHeader::new("Mismatch details (Expected vs Actual)")
        .id_salt(("batch_mismatch", row_id))
        .default_open(true)
        .show(ui, |ui| {
            let expected = report.expected.as_deref().unwrap_or("<none>");
            ui.label(
                RichText::new(format!("Expected: {expected}"))
                    .monospace()
                    .size(11.5),
            );
            ui.label(
                RichText::new(format!("Actual  : {}", report.actual))
                    .monospace()
                    .size(11.5)
                    .color(Color32::from_rgb(248, 113, 113)),
            );
        });
    action
}

#[derive(Clone, Copy)]
struct DigestCardStyle<'a> {
    title: &'a str,
    title_size: f32,
    fill: Color32,
    border: Color32,
    subtext: Color32,
}

fn render_single_digest_card(
    ui: &mut egui::Ui,
    report: &VerifyReport,
    copy_label: &str,
    style: DigestCardStyle<'_>,
) -> bool {
    let mut copy_clicked = false;

    Frame::new()
        .fill(style.fill)
        .stroke(Stroke::new(1.5_f32, style.border))
        .corner_radius(CornerRadius::same(8))
        .inner_margin(Margin::same(14))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(style.title)
                        .size(style.title_size)
                        .strong()
                        .color(Color32::WHITE),
                );
                ui.add_space(8.0);
                if ui.add(banner_copy_button(copy_label)).clicked() {
                    copy_clicked = true;
                }
            });
            ui.add_space(6.0);
            render_card_details(ui, report, style.subtext);
            ui.add_space(6.0);
            Frame::new()
                .fill(Color32::from_rgba_unmultiplied(0, 0, 0, 48))
                .corner_radius(CornerRadius::same(6))
                .inner_margin(Margin::same(8))
                .show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    ui.label(
                        RichText::new("Digest")
                            .size(11.5)
                            .strong()
                            .color(style.subtext),
                    );
                    ui.add(
                        Label::new(
                            RichText::new(&report.actual)
                                .monospace()
                                .size(13.0)
                                .color(Color32::WHITE),
                        )
                        .wrap(),
                    );
                });
        });

    copy_clicked
}

fn render_mismatch_card(
    ui: &mut egui::Ui,
    report: &VerifyReport,
    expected_hex: &str,
    copy_label: &str,
) -> bool {
    let mut copy_clicked = false;
    let soft_white = Color32::from_rgb(254, 242, 242);

    Frame::new()
        .fill(Color32::from_rgb(220, 38, 38))
        .stroke(Stroke::new(1.5_f32, Color32::from_rgb(185, 28, 28)))
        .corner_radius(CornerRadius::same(8))
        .inner_margin(Margin::same(14))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new("NOT IDENTICAL. BE CAUTIOUS.")
                        .size(21.0)
                        .strong()
                        .color(Color32::WHITE),
                );
                ui.add_space(8.0);
                if ui.add(banner_copy_button(copy_label)).clicked() {
                    copy_clicked = true;
                }
            });
            ui.add_space(6.0);
            render_card_details(ui, report, soft_white);
            ui.add_space(6.0);
            Frame::new()
                .fill(Color32::from_rgba_unmultiplied(0, 0, 0, 55))
                .corner_radius(CornerRadius::same(6))
                .inner_margin(Margin::same(10))
                .show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    ui.label(
                        RichText::new("Expected")
                            .size(11.5)
                            .strong()
                            .color(soft_white),
                    );
                    ui.add(
                        Label::new(
                            RichText::new(expected_hex)
                                .monospace()
                                .size(13.0)
                                .color(Color32::WHITE),
                        )
                        .wrap(),
                    );
                    ui.add_space(6.0);
                    ui.label(
                        RichText::new("Actual")
                            .size(11.5)
                            .strong()
                            .color(soft_white),
                    );
                    ui.add(
                        Label::new(
                            RichText::new(&report.actual)
                                .monospace()
                                .size(13.0)
                                .color(Color32::from_rgb(254, 240, 138)),
                        )
                        .wrap(),
                    );
                });
        });

    copy_clicked
}

fn render_error_card(ui: &mut egui::Ui, message: &str) {
    Frame::new()
        .fill(Color32::from_rgb(120, 53, 15))
        .stroke(Stroke::new(1.5_f32, Color32::from_rgb(245, 158, 11)))
        .corner_radius(CornerRadius::same(8))
        .inner_margin(Margin::same(12))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.label(
                RichText::new("Error")
                    .size(15.0)
                    .strong()
                    .color(Color32::from_rgb(254, 243, 199)),
            );
            ui.add_space(4.0);
            ui.add(Label::new(RichText::new(message).size(13.0).color(Color32::WHITE)).wrap());
        });
}

fn render_card_details(ui: &mut egui::Ui, report: &VerifyReport, text_color: Color32) {
    let algo = &report.algorithm;
    let file = &report.file;
    let size_human = format_bytes(report.bytes);
    let bytes = report.bytes;
    let elapsed_ms = report.elapsed_ms;
    let mbps = report.throughput_mbps;

    ui.add(
        Label::new(
            RichText::new(format!("Algorithm: {algo}   |   File: {file}"))
                .size(12.5)
                .color(text_color),
        )
        .wrap(),
    );
    ui.label(
        RichText::new(format!(
            "Size: {size_human} ({bytes} bytes)   |   Time: {elapsed_ms} ms   |   Speed: {mbps:.2} MB/s"
        ))
        .size(12.5)
        .color(text_color),
    );
}

fn banner_copy_button(label: &str) -> egui::Button<'_> {
    egui::Button::new(RichText::new(label).color(Color32::WHITE).strong())
        .fill(Color32::from_rgba_unmultiplied(0, 0, 0, 75))
        .stroke(Stroke::new(
            1.0_f32,
            Color32::from_rgba_unmultiplied(255, 255, 255, 175),
        ))
        .corner_radius(CornerRadius::same(5))
}

fn render_drop_overlay(ctx: &egui::Context) {
    let rect = ctx.screen_rect().shrink(12.0);
    let painter = ctx.layer_painter(LayerId::new(Order::Foreground, Id::new("drop_overlay")));
    painter.rect_filled(
        rect,
        CornerRadius::same(10),
        Color32::from_rgba_unmultiplied(15, 23, 42, 205),
    );
    painter.rect_stroke(
        rect,
        CornerRadius::same(10),
        Stroke::new(2.5_f32, Color32::from_rgb(96, 165, 250)),
        StrokeKind::Inside,
    );
    painter.text(
        rect.center(),
        Align2::CENTER_CENTER,
        "Drop files, folder, or checksum .txt to verify",
        FontId::proportional(20.0),
        Color32::WHITE,
    );
}

fn resolve_startup_pair(first: String, second: String) -> (String, String) {
    let first_path = Path::new(&first);
    let second_path = Path::new(&second);

    if !first_path.is_file() && second_path.is_file() && parse_digest_str(&first, None).is_ok() {
        return (second, first);
    }

    if first_path.is_file()
        && second_path.is_file()
        && is_small_regular_file(first_path)
        && is_text_or_checksum_extension(first_path)
        && !is_text_or_checksum_extension(second_path)
    {
        return (second, first);
    }

    (first, second)
}

fn unquote_pasted_path(raw: &str) -> Option<String> {
    raw.trim()
        .strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .map(|inner| inner.trim().to_owned())
}

fn strip_surrounding_quotes(raw: &str) -> String {
    unquote_pasted_path(raw).unwrap_or_else(|| raw.trim().to_owned())
}

fn is_small_regular_file(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|meta| meta.is_file() && meta.len() <= MAX_HASH_FILE_BYTES)
}

#[allow(clippy::cast_precision_loss)]
fn bytes_to_mib(bytes: u64) -> f64 {
    bytes as f64 / BYTES_PER_MIB
}

#[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
fn progress_fraction(read: u64, total: u64) -> f32 {
    if total == 0 {
        return 1.0;
    }
    (read as f64 / total as f64).clamp(0.0, 1.0) as f32
}

#[allow(clippy::cast_precision_loss)]
fn format_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;

    let value = bytes as f64;
    if bytes < 1024 {
        format!("{bytes} B")
    } else if value < MIB {
        let kib = value / KIB;
        format!("{kib:.1} KiB")
    } else if value < GIB {
        let mib = value / MIB;
        format!("{mib:.2} MiB")
    } else {
        let gib = value / GIB;
        format!("{gib:.2} GiB")
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ActiveTab, AlgorithmChoice, BatchRow, BatchRowState, HasherApp, PendingBatchConfirm,
        format_bytes, progress_fraction, strip_surrounding_quotes,
    };
    use hasher::algo::{HashAlgorithm, hash_bytes};
    use hasher::batch::{
        PARALLEL_LARGE_BATCH_BYTES, PARALLEL_WARN_FILE_COUNT, is_dedicated_checksum_extension,
        is_text_or_checksum_extension,
    };
    use std::path::{Path, PathBuf};
    use tempfile::TempDir;

    #[test]
    fn quotes_stripped_cleanly() {
        assert_eq!(
            strip_surrounding_quotes(r#"  "C:\Users\me\archive.iso"  "#),
            r"C:\Users\me\archive.iso"
        );
        assert_eq!(strip_surrounding_quotes(r"C:\plain.bin"), r"C:\plain.bin");
        assert_eq!(strip_surrounding_quotes(r#""""#), "");
    }

    #[test]
    fn algorithm_choice_defaults_and_overrides() {
        assert_eq!(
            AlgorithmChoice::Auto.compute_algorithm(),
            HashAlgorithm::DEFAULT_COMPUTE_ALGORITHM
        );
        assert_eq!(AlgorithmChoice::Auto.to_override(), None);
        assert_eq!(
            AlgorithmChoice::Specific(HashAlgorithm::Blake3).compute_algorithm(),
            HashAlgorithm::Blake3
        );
        assert_eq!(
            AlgorithmChoice::Specific(HashAlgorithm::Blake3).to_override(),
            Some(HashAlgorithm::Blake3)
        );
    }

    #[test]
    fn dropdown_options_sync_with_picker_order() {
        let options: Vec<AlgorithmChoice> = AlgorithmChoice::dropdown_options().collect();
        let expected: Vec<AlgorithmChoice> = std::iter::once(AlgorithmChoice::Auto)
            .chain(
                HashAlgorithm::picker_order()
                    .iter()
                    .copied()
                    .map(AlgorithmChoice::Specific),
            )
            .collect();
        assert_eq!(options, expected);
        assert_eq!(options.len(), 1 + HashAlgorithm::picker_order().len());
    }

    #[test]
    fn progress_and_byte_formatting() {
        assert!((progress_fraction(0, 0) - 1.0).abs() < f32::EPSILON);
        assert!((progress_fraction(50, 100) - 0.5).abs() < f32::EPSILON);
        assert!((progress_fraction(150, 100) - 1.0).abs() < f32::EPSILON);
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024 * 1024), "1.00 MiB");
    }

    #[test]
    fn checksum_extensions_detected() {
        assert!(is_dedicated_checksum_extension(Path::new("file.SHA256")));
        assert!(!is_dedicated_checksum_extension(Path::new("notes.txt")));
        assert!(is_text_or_checksum_extension(Path::new("notes.txt")));
        assert!(!is_text_or_checksum_extension(Path::new("installer.exe")));
    }

    #[test]
    fn batch_folder_import_dedups_and_auto_loads_single_mixed_manifest() {
        let dir = TempDir::new().expect("tempdir");
        let f1 = dir.path().join("prog1.exe");
        let f2 = dir.path().join("prog2.exe");
        let f10 = dir.path().join("prog10.exe");
        std::fs::write(&f1, b"payload1").expect("write");
        std::fs::write(&f2, b"payload2").expect("write");
        std::fs::write(&f10, b"payload10").expect("write");

        let h1 = hash_bytes(b"payload1", HashAlgorithm::Sha256);
        let h2 = hash_bytes(b"payload2", HashAlgorithm::Md5);
        let h10 = hash_bytes(b"payload10", HashAlgorithm::Blake3);
        let manifest = dir.path().join("hashes.txt");
        std::fs::write(
            &manifest,
            format!("{h1} ./prog1.exe\n{h2} ./prog2.exe\nblake3:{h10} ./prog10.exe\n"),
        )
        .expect("write manifest");

        let mut app = HasherApp::from_args(std::iter::empty::<String>());
        app.import_batch_folder(dir.path());

        assert_eq!(app.batch.rows.len(), 3);
        let names: Vec<&str> = app
            .batch
            .rows
            .iter()
            .map(|r| r.relative_label.as_str())
            .collect();
        assert_eq!(names, vec!["prog1.exe", "prog2.exe", "prog10.exe"]);
        assert_eq!(app.batch.rows[0].expected_input, h1);
        assert_eq!(app.batch.rows[0].algo_choice, AlgorithmChoice::Auto);
        assert_eq!(app.batch.rows[1].expected_input, h2);
        assert_eq!(
            app.batch.rows[2].algo_choice,
            AlgorithmChoice::Specific(HashAlgorithm::Blake3)
        );

        app.batch.rows[0].expected_input = "custom-edited".to_owned();
        app.import_batch_paths(&[f1], Some(dir.path()));
        assert_eq!(app.batch.rows.len(), 3);
        assert_eq!(app.batch.rows[0].expected_input, "custom-edited");
    }

    #[test]
    fn batch_preflight_warns_on_missing_hashes_and_large_parallel_batches() {
        let mut app = HasherApp::from_args(std::iter::empty::<String>());
        let ctx = eframe::egui::Context::default();
        let per_file = (PARALLEL_LARGE_BATCH_BYTES / 5) + 1024;

        for idx in 0..PARALLEL_WARN_FILE_COUNT {
            let p = PathBuf::from(format!("missing_disk_payload_{idx}.bin"));
            app.batch.rows.push(BatchRow {
                id: u64::try_from(idx + 1).expect("id"),
                path: p.clone(),
                canonical_key: p,
                relative_label: format!("file_{idx}.bin"),
                size_bytes: per_file,
                expected_input: if idx == 0 {
                    String::new()
                } else {
                    "00000000".to_owned()
                },
                algo_choice: AlgorithmChoice::Auto,
                state: BatchRowState::Idle,
            });
        }

        app.request_check_all(&ctx);
        assert!(matches!(
            app.batch.pending_confirm,
            Some(PendingBatchConfirm::MissingHashes {
                missing_count: 1,
                filled_count: 4
            })
        ));

        app.batch.rows[0].expected_input = "00000000".to_owned();
        app.batch.pending_confirm = None;
        app.request_check_all(&ctx);
        assert!(matches!(
            app.batch.pending_confirm,
            Some(PendingBatchConfirm::LargeParallelBatch { file_count: 5, .. })
        ));
    }

    #[test]
    fn startup_directory_or_multi_file_args_open_batch_tab() {
        let dir = TempDir::new().expect("tempdir");
        let a = dir.path().join("a.bin");
        let b = dir.path().join("b.bin");
        std::fs::write(&a, b"1").expect("write");
        std::fs::write(&b, b"2").expect("write");

        let dir_app = HasherApp::from_args([dir.path().display().to_string()]);
        assert_eq!(dir_app.active_tab, ActiveTab::BatchCheck);
        assert_eq!(dir_app.batch.rows.len(), 2);

        let multi_app = HasherApp::from_args([a.display().to_string(), b.display().to_string()]);
        assert_eq!(multi_app.active_tab, ActiveTab::BatchCheck);
        assert_eq!(multi_app.batch.rows.len(), 2);
    }
}
