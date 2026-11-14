#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::{Duration, Instant};

use arboard::Clipboard;
use eframe::egui::{
    self, Align2, Color32, ComboBox, CornerRadius, FontFamily, FontId, Frame, Id, Key, Label,
    LayerId, Margin, Order, ProgressBar, RichText, ScrollArea, Stroke, StrokeKind, TextEdit, Vec2,
    ViewportBuilder,
};
use hasher::algo::HashAlgorithm;
use hasher::digest::{ParsedDigest, parse_digest_from_file, parse_digest_str};
use hasher::verify::{VerifyReport, compute_only, verify_target};
use rfd::FileDialog;

const MAX_HASH_FILE_BYTES: u64 = 1024 * 1024;
const BYTES_PER_MIB: f64 = 1024.0 * 1024.0;

fn main() -> eframe::Result {
    let native_options = eframe::NativeOptions {
        viewport: ViewportBuilder::default()
            .with_title("Hasher - File Hash Verifier")
            .with_inner_size([680.0, 540.0])
            .with_min_inner_size([520.0, 420.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Hasher",
        native_options,
        Box::new(|cc| Ok(Box::new(HasherApp::new(cc)))),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AlgorithmChoice {
    Auto,
    Specific(HashAlgorithm),
}

impl AlgorithmChoice {
    fn dropdown_options() -> impl Iterator<Item = Self> {
        std::iter::once(Self::Auto)
            .chain(HashAlgorithm::picker_order().iter().copied().map(Self::Specific))
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

struct HasherApp {
    file_path: String,
    expected_input: String,
    algo_choice: AlgorithmChoice,
    running: Option<RunningJob>,
    outcome: Option<AppOutcome>,
    info_message: Option<String>,
    copied_until: Option<Instant>,
    cached_target_size: (String, Option<u64>),
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
        let mut iter = args.into_iter().take(2);
        let first_raw = iter.next().map(|arg| strip_surrounding_quotes(&arg));
        let second_raw = iter.next().map(|arg| strip_surrounding_quotes(&arg));

        let (file_arg, hash_arg) = match (first_raw, second_raw) {
            (Some(first), Some(second)) => resolve_startup_pair(first, second),
            (Some(first), None) => (first, String::new()),
            (None, _) => (String::new(), String::new()),
        };

        let mut app = Self {
            file_path: file_arg,
            expected_input: String::new(),
            algo_choice: AlgorithmChoice::Auto,
            running: None,
            outcome: None,
            info_message: None,
            copied_until: None,
            cached_target_size: (String::new(), None),
        };
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
        match Clipboard::new().and_then(|mut clipboard| clipboard.get_text()) {
            Ok(text) => {
                let trimmed = text.trim();
                let parsed_multiline = (trimmed.contains('\n') || trimmed.contains('\r'))
                    .then(|| parse_digest_str(trimmed, self.algo_choice.to_override()))
                    .and_then(Result::ok);
                if let Some(parsed) = parsed_multiline {
                    self.expected_input = parsed.hex;
                    if parsed.explicit_algo && self.algo_choice == AlgorithmChoice::Auto {
                        self.algo_choice = AlgorithmChoice::Specific(parsed.algorithm);
                    }
                    self.outcome = None;
                    let algo_name = parsed.algorithm.as_str();
                    self.info_message = Some(format!("Pasted {algo_name} hash from clipboard."));
                    return;
                }
                trimmed.clone_into(&mut self.expected_input);
                self.outcome = None;
                self.info_message = if self.expected_input.is_empty() {
                    Some("Clipboard text is empty.".to_owned())
                } else {
                    Some("Pasted hash from clipboard.".to_owned())
                };
            }
            Err(err) => {
                self.info_message = None;
                self.outcome = Some(AppOutcome::Error(format!("Clipboard read failed: {err}")));
            }
        }
    }

    fn pick_target_file(&mut self) {
        if let Some(path) = FileDialog::new().pick_file() {
            self.set_target_file(&path);
        }
    }

    fn pick_hash_file(&mut self) {
        let picked = FileDialog::new()
            .add_filter(
                "Checksum / Text Files",
                &["txt", "sha256", "sha512", "sha384", "sha1", "md5", "sum"],
            )
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

        if self.running.is_some() {
            self.info_message =
                Some("Cancel the current operation before dropping a new file.".to_owned());
            return;
        }

        let paths: Vec<PathBuf> = dropped.into_iter().filter_map(|file| file.path).collect();
        if paths.is_empty() {
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
                self.info_message = Some("Copied hash to clipboard.".to_owned());
            }
            Err(err) => {
                self.info_message = Some(format!("Clipboard copy failed: {err}"));
            }
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
            if ui.add_enabled(!running, egui::Button::new("Paste")).clicked() {
                self.paste_expected_from_clipboard();
            }
            if ui
                .add_enabled(!running, egui::Button::new("Load .txt..."))
                .clicked()
            {
                self.pick_hash_file();
            }
            if ui.add_enabled(!running, egui::Button::new("Clear")).clicked() {
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
        let live_mbps = if read > 0 { read_mib / elapsed_secs } else { 0.0 };

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
        let copy_label = if self.copied_until.is_some_and(|until| Instant::now() < until) {
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
}

impl Drop for HasherApp {
    fn drop(&mut self) {
        if let Some(ref job) = self.running {
            job.cancel_flag.store(true, Ordering::Relaxed);
        }
    }
}

impl eframe::App for HasherApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_worker(ctx);
        self.handle_dropped_files(ctx);

        if let Some(until) = self.copied_until {
            if Instant::now() >= until {
                self.copied_until = None;
            } else {
                ctx.request_repaint_after(Duration::from_millis(250));
            }
        }

        let running = self.running.is_some();

        egui::CentralPanel::default().show(ctx, |ui| {
            ScrollArea::vertical().show(ui, |ui| {
                Frame::new().inner_margin(Margin::same(6)).show(ui, |ui| {
                    Self::render_header(ui);
                    ui.add_space(6.0);
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
        });

        let hovering_files = ctx.input(|input| !input.raw.hovered_files.is_empty());
        if hovering_files {
            render_drop_overlay(ctx);
        }
    }
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
            ui.add(
                Label::new(
                    RichText::new(message)
                        .size(13.0)
                        .color(Color32::WHITE),
                )
                .wrap(),
            );
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
        .stroke(Stroke::new(1.0_f32, Color32::from_rgba_unmultiplied(255, 255, 255, 175)))
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
        "Drop file to verify or load checksum",
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

fn is_dedicated_checksum_extension(path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(|value| value.to_str()) else {
        return false;
    };
    matches!(
        ext.to_ascii_lowercase().as_str(),
        "sha256" | "sha512" | "sha384" | "sha1" | "md5" | "sum" | "blake3"
    )
}

fn is_text_or_checksum_extension(path: &Path) -> bool {
    if is_dedicated_checksum_extension(path) {
        return true;
    }
    path.extension()
        .and_then(|value| value.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("txt"))
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
        AlgorithmChoice, format_bytes, is_dedicated_checksum_extension,
        is_text_or_checksum_extension, progress_fraction, strip_surrounding_quotes,
    };
    use hasher::algo::HashAlgorithm;
    use std::path::Path;

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
}
