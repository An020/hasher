//! Batch import, checksum extension helpers, manifest auto-fill planning, and concurrency guards.

use std::cmp::Ordering;
use std::collections::HashSet;
use std::fmt::Write as _;
use std::io;
use std::path::{Path, PathBuf};

use crate::algo::HashAlgorithm;
use crate::digest::{ParsedDigest, basenames_match};

/// Combined queued size threshold above which multi-file parallel runs trigger a storage warning (`2 GiB`).
pub const PARALLEL_LARGE_BATCH_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// Minimum queued file count alongside [`PARALLEL_LARGE_BATCH_BYTES`] to trigger a parallel I/O warning.
pub const PARALLEL_WARN_FILE_COUNT: usize = 5;

const MANIFEST_CONTAINER_EXTS: &[&str] = &["sum", "sums", "sfv", "hash", "digest", "b3"];

/// Files discovered when scanning a folder for batch verification.
#[derive(Debug, Clone, Default)]
pub struct FolderScanResult {
    /// Non-checksum target payload files ordered naturally by relative path.
    pub target_files: Vec<PathBuf>,
    /// Detected `.txt` or checksum manifest files ordered naturally by relative path.
    pub checksum_files: Vec<PathBuf>,
}

/// Minimal row reference used when mapping manifest entries to imported batch targets.
#[derive(Debug, Clone, Copy)]
pub struct BatchTargetRef<'a> {
    /// Full file path on disk.
    pub path: &'a Path,
    /// Relative display path from imported base folder, or basename when dropped directly.
    pub relative_label: &'a str,
}

/// Assignment summary produced when mapping parsed digest entries onto batch rows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ManifestApplyPlan {
    /// `(row_index, parsed_digest)` pairs matched by path, basename, or line position.
    pub assignments: Vec<(usize, ParsedDigest)>,
    /// Number of entries matched using an explicit filepath token.
    pub matched_by_path: usize,
    /// Number of bare digest lines assigned positionally in order.
    pub matched_positionally: usize,
    /// Number of parsed entries that could not match any unique or remaining row.
    pub unmatched_entries: usize,
}

/// Returns `true` when `path` uses a dedicated checksum extension derived from [`HashAlgorithm`]
/// metadata or standard checksum container formats.
#[must_use]
pub fn is_dedicated_checksum_extension(path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(std::ffi::OsStr::to_str) else {
        return false;
    };
    HashAlgorithm::all()
        .iter()
        .any(|algo| ext.eq_ignore_ascii_case(algo.cli_name()))
        || MANIFEST_CONTAINER_EXTS
            .iter()
            .any(|cand| ext.eq_ignore_ascii_case(cand))
}

/// Returns `true` when `path` is either a dedicated checksum file or a `.txt` digest file.
#[must_use]
pub fn is_text_or_checksum_extension(path: &Path) -> bool {
    if is_dedicated_checksum_extension(path) {
        return true;
    }
    path.extension()
        .and_then(std::ffi::OsStr::to_str)
        .is_some_and(|ext| ext.eq_ignore_ascii_case("txt"))
}

/// Returns file-picker filter extensions derived dynamically from supported algorithms plus `txt`/`sum`.
#[must_use]
pub fn hash_file_dialog_extensions() -> Vec<&'static str> {
    let mut exts = Vec::with_capacity(HashAlgorithm::all().len() + 2);
    exts.push("txt");
    for algo in HashAlgorithm::all() {
        exts.push(algo.cli_name());
    }
    exts.push("sum");
    exts
}

fn strip_leading_ascii_zeros(digits: &[u8]) -> &[u8] {
    let first_nonzero = digits
        .iter()
        .position(|&b| b != b'0')
        .unwrap_or(digits.len().saturating_sub(1));
    &digits[first_nonzero..]
}

/// Compares two filenames/paths using case-insensitive natural ordering (`file2` before `file10`).
#[must_use]
pub fn natural_cmp(a: &str, b: &str) -> Ordering {
    let mut ia = a.as_bytes();
    let mut ib = b.as_bytes();

    while !ia.is_empty() && !ib.is_empty() {
        if ia[0].is_ascii_digit() && ib[0].is_ascii_digit() {
            let len_a = ia.iter().take_while(|byte| byte.is_ascii_digit()).count();
            let len_b = ib.iter().take_while(|byte| byte.is_ascii_digit()).count();
            let (digits_a, rest_a) = ia.split_at(len_a);
            let (digits_b, rest_b) = ib.split_at(len_b);

            let trim_a = strip_leading_ascii_zeros(digits_a);
            let trim_b = strip_leading_ascii_zeros(digits_b);
            match trim_a
                .len()
                .cmp(&trim_b.len())
                .then_with(|| trim_a.cmp(trim_b))
            {
                Ordering::Equal => {
                    ia = rest_a;
                    ib = rest_b;
                }
                non_eq => return non_eq,
            }
        } else {
            let ca = ia[0].to_ascii_lowercase();
            let cb = ib[0].to_ascii_lowercase();
            match ca.cmp(&cb) {
                Ordering::Equal => {
                    ia = &ia[1..];
                    ib = &ib[1..];
                }
                non_eq => return non_eq,
            }
        }
    }

    ia.len().cmp(&ib.len()).then_with(|| a.cmp(b))
}

/// Produces a normalized deduplication key for `path` (canonicalized, ASCII-lowercased on Windows).
#[must_use]
pub fn canonical_path_key(path: &Path) -> PathBuf {
    let resolved = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    #[cfg(windows)]
    {
        PathBuf::from(resolved.to_string_lossy().to_ascii_lowercase())
    }
    #[cfg(not(windows))]
    {
        resolved
    }
}

/// Scans `dir` for regular payload files and checksum/`.txt` files, skipping symlinked directories
/// and sorting outputs naturally by relative path from `dir`.
///
/// # Errors
///
/// Returns an `io::Error` if `dir` cannot be read or traversed.
pub fn scan_folder_for_batch(dir: &Path, include_subfolders: bool) -> io::Result<FolderScanResult> {
    if !dir.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("folder not found or not a directory: {}", dir.display()),
        ));
    }

    let mut target_files = Vec::new();
    let mut checksum_files = Vec::new();
    let mut stack = vec![dir.to_path_buf()];

    while let Some(current) = stack.pop() {
        for entry_res in std::fs::read_dir(&current)? {
            let entry = entry_res?;
            let file_type = entry.file_type()?;
            if file_type.is_symlink() {
                continue;
            }
            let path = entry.path();
            if file_type.is_dir() {
                if include_subfolders {
                    stack.push(path);
                }
            } else if file_type.is_file() {
                if is_text_or_checksum_extension(&path) {
                    checksum_files.push(path);
                } else {
                    target_files.push(path);
                }
            }
        }
    }

    let rel_key = |p: &Path| -> String {
        p.strip_prefix(dir)
            .unwrap_or(p)
            .to_string_lossy()
            .into_owned()
    };
    target_files.sort_by(|a, b| natural_cmp(&rel_key(a), &rel_key(b)));
    checksum_files.sort_by(|a, b| natural_cmp(&rel_key(a), &rel_key(b)));

    Ok(FolderScanResult {
        target_files,
        checksum_files,
    })
}

fn normalize_match_path(raw: &str) -> String {
    let mut s = raw.trim();
    while s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
    {
        s = s[1..s.len() - 1].trim();
    }
    let slash_norm = s.replace('\\', "/");
    let mut trimmed = slash_norm.as_str();
    while let Some(rest) = trimmed.strip_prefix("./") {
        trimmed = rest;
    }
    if cfg!(windows) {
        trimmed.to_ascii_lowercase()
    } else {
        trimmed.to_owned()
    }
}

fn path_matches_suffix(candidate: &str, suffix: &str) -> bool {
    if candidate == suffix {
        return true;
    }
    candidate
        .strip_suffix(suffix)
        .is_some_and(|prefix| prefix.ends_with('/'))
}

fn find_unique_path_match(
    raw_token: &str,
    norm_rels: &[String],
    norm_fulls: &[String],
    targets: &[BatchTargetRef<'_>],
    used_rows: &HashSet<usize>,
) -> Option<usize> {
    let norm_entry = normalize_match_path(raw_token);
    if norm_entry.is_empty() {
        return None;
    }

    let mut rel_matches = (0..targets.len()).filter(|&idx| {
        !used_rows.contains(&idx)
            && (path_matches_suffix(&norm_rels[idx], &norm_entry)
                || path_matches_suffix(&norm_fulls[idx], &norm_entry))
    });
    if let Some(first) = rel_matches.next() {
        if rel_matches.next().is_none() {
            return Some(first);
        }
        return None;
    }

    let mut base_matches = (0..targets.len()).filter(|&idx| {
        !used_rows.contains(&idx)
            && targets[idx]
                .path
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .is_some_and(|base| basenames_match(raw_token, base))
    });
    let first = base_matches.next()?;
    base_matches.next().is_none().then_some(first)
}

/// Plans assignments of parsed `(Option<filepath>, ParsedDigest)` entries onto `targets`.
///
/// Entries carrying a filepath token match by normalized relative path suffix first and fall back
/// to unique case-insensitive basename matching. Bare entries without filenames fill unassigned
/// rows positionally in order.
#[must_use]
pub fn plan_manifest_assignments(
    targets: &[BatchTargetRef<'_>],
    entries: &[(Option<String>, ParsedDigest)],
) -> ManifestApplyPlan {
    let norm_rels: Vec<String> = targets
        .iter()
        .map(|target| normalize_match_path(target.relative_label))
        .collect();
    let norm_fulls: Vec<String> = targets
        .iter()
        .map(|target| normalize_match_path(&target.path.to_string_lossy()))
        .collect();

    let mut plan = ManifestApplyPlan::default();
    let mut used_rows = HashSet::new();
    let mut bare_entries = Vec::new();

    for (path_opt, parsed) in entries {
        if let Some(raw_token) = path_opt {
            if let Some(idx) =
                find_unique_path_match(raw_token, &norm_rels, &norm_fulls, targets, &used_rows)
            {
                used_rows.insert(idx);
                plan.assignments.push((idx, parsed.clone()));
                plan.matched_by_path += 1;
            } else {
                plan.unmatched_entries += 1;
            }
        } else {
            bare_entries.push(parsed);
        }
    }

    let mut next_free = 0usize;
    for parsed in bare_entries {
        while next_free < targets.len() && used_rows.contains(&next_free) {
            next_free += 1;
        }
        if next_free < targets.len() {
            used_rows.insert(next_free);
            plan.assignments.push((next_free, parsed.clone()));
            plan.matched_positionally += 1;
            next_free += 1;
        } else {
            plan.unmatched_entries += 1;
        }
    }

    plan
}

/// Returns `true` when queuing `file_count` files totaling `total_bytes` in parallel should warn
/// the user about multi-GB storage saturation (`>= 5` files and `> 2 GiB`).
#[must_use]
pub const fn should_warn_large_parallel_batch(file_count: usize, total_bytes: u64) -> bool {
    file_count >= PARALLEL_WARN_FILE_COUNT && total_bytes > PARALLEL_LARGE_BATCH_BYTES
}

/// Computes the bounded concurrent worker cap for batch hashing (`2` for batches `> 2 GiB`, else `2..=4`).
#[must_use]
pub fn bounded_parallel_workers(total_bytes: u64) -> usize {
    if total_bytes > PARALLEL_LARGE_BATCH_BYTES {
        2
    } else {
        std::thread::available_parallelism().map_or(2, |cores| (cores.get() / 2).clamp(2, 4))
    }
}

/// Returns `true` when `algo` requires an explicit algorithm prefix in saved digest lines
/// because its hex length alone maps to a different default algorithm in [`HashAlgorithm::from_hex_len`].
#[must_use]
pub fn needs_explicit_prefix(algo: HashAlgorithm) -> bool {
    HashAlgorithm::from_hex_len(algo.expected_hex_len()) != Some(algo)
}

fn target_basename(target_file: &Path) -> String {
    target_file.file_name().map_or_else(
        || "file".to_owned(),
        |name| name.to_string_lossy().into_owned(),
    )
}

/// Builds a single-file hash filename by appending target extension (without dot), `"hash."`,
/// and the algorithm's [`HashAlgorithm::cli_name`] (or `"txt"` when `algo` is `None`).
#[must_use]
pub fn build_single_hash_filename(target_file: &Path, algo: Option<HashAlgorithm>) -> String {
    let stem = target_file
        .file_stem()
        .map(|s| s.to_string_lossy())
        .filter(|s| !s.is_empty())
        .unwrap_or(std::borrow::Cow::Borrowed("file"));
    let ext = target_file
        .extension()
        .map(|e| e.to_string_lossy())
        .unwrap_or_default();
    let suffix = algo.as_ref().map_or("txt", HashAlgorithm::cli_name);
    format!("{stem}{ext}hash.{suffix}")
}

/// Formats a single-file hash file line (`<hex>  <basename>\n`, or `<algo>:<hex>  <basename>\n`
/// when [`needs_explicit_prefix`] is `true`).
#[must_use]
pub fn format_single_hash_file_content(
    target_file: &Path,
    algo: HashAlgorithm,
    digest_hex: &str,
) -> String {
    let basename = target_basename(target_file);
    let hex = digest_hex.trim();
    if needs_explicit_prefix(algo) {
        format!("{}:{hex}  {basename}\n", algo.cli_name())
    } else {
        format!("{hex}  {basename}\n")
    }
}

/// Resolves a shared base directory for batch export when all `row_paths` lie under `explicit_base`
/// or share one common parent directory; returns `None` when files span unrelated folders.
#[must_use]
pub fn common_batch_directory(
    explicit_base: Option<&Path>,
    row_paths: &[&Path],
) -> Option<PathBuf> {
    if row_paths.is_empty() {
        return None;
    }

    if let Some(base) = explicit_base.filter(|p| !p.as_os_str().is_empty()) {
        let base_key = canonical_path_key(base);
        let all_inside = row_paths
            .iter()
            .all(|p| p.starts_with(base) || canonical_path_key(p).starts_with(&base_key));
        if all_inside {
            return Some(base.to_path_buf());
        }
    }

    let first_parent = row_paths[0]
        .parent()
        .filter(|p| !p.as_os_str().is_empty())?;
    let first_key = canonical_path_key(first_parent);
    if row_paths[1..].iter().all(|p| {
        p.parent()
            .filter(|d| !d.as_os_str().is_empty())
            .is_some_and(|d| canonical_path_key(d) == first_key)
    }) {
        Some(first_parent.to_path_buf())
    } else {
        None
    }
}

/// Builds a batch folder manifest filename (`<folder_name>hash.<ext>`), falling back to `"batch"`
/// for drive roots and `"txt"` when `uniform_algo` is `None`.
#[must_use]
pub fn build_folder_hash_filename(
    folder_dir: &Path,
    uniform_algo: Option<HashAlgorithm>,
) -> String {
    let folder_label = folder_dir
        .file_name()
        .map(|name| name.to_string_lossy())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(std::borrow::Cow::Borrowed("batch"));
    let ext = uniform_algo.as_ref().map_or("txt", HashAlgorithm::cli_name);
    format!("{folder_label}hash.{ext}")
}

/// Formats batch manifest lines as `<token> ./<rel_path>\n` relative to `base_dir` using forward slashes,
/// adding an explicit `<algo>:` prefix whenever [`needs_explicit_prefix`] holds.
#[must_use]
pub fn format_batch_hash_manifest(
    base_dir: &Path,
    items: &[(&Path, HashAlgorithm, &str)],
) -> String {
    let canon_base = std::fs::canonicalize(base_dir).ok();
    let mut out = String::new();

    for &(file_path, algo, digest_hex) in items {
        let rel_path = file_path
            .strip_prefix(base_dir)
            .ok()
            .map(Path::to_path_buf)
            .or_else(|| {
                canon_base.as_ref().and_then(|cb| {
                    std::fs::canonicalize(file_path)
                        .ok()
                        .and_then(|cf| cf.strip_prefix(cb).ok().map(Path::to_path_buf))
                })
            })
            .unwrap_or_else(|| {
                file_path
                    .file_name()
                    .map_or_else(|| file_path.to_path_buf(), PathBuf::from)
            });

        let slash_norm = rel_path.to_string_lossy().replace('\\', "/");
        let mut rel = slash_norm.as_str();
        while let Some(rest) = rel.strip_prefix("./") {
            rel = rest;
        }
        rel = rel.trim_start_matches('/');
        if rel.is_empty() {
            rel = "file";
        }

        let hex = digest_hex.trim();
        if needs_explicit_prefix(algo) {
            let _ = writeln!(out, "{}:{hex} ./{rel}", algo.cli_name());
        } else {
            let _ = writeln!(out, "{hex} ./{rel}");
        }
    }

    out
}

/// Result of attempting to write an algorithm-specific hash file with automatic `.txt` fallback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SaveHashOutcome {
    /// Saved to the algorithm-derived primary hash file path.
    SavedPrimary(PathBuf),
    /// Saved to the `.txt` fallback path; caller must prompt user to inspect it.
    SavedFallbackTxt {
        /// Path of the written `.txt` fallback file.
        path: PathBuf,
        /// Human-readable reason explaining why `.txt` fallback was used.
        reason: String,
    },
    /// Both primary and `.txt` fallback writes failed.
    Failed {
        /// Attempted primary path.
        primary_path: PathBuf,
        /// Primary error or fallback trigger reason.
        primary_err: String,
        /// Attempted `.txt` fallback path.
        fallback_path: PathBuf,
        /// Fallback write I/O error.
        fallback_err: String,
    },
}

/// Writes `content` to `primary_path`, automatically falling back to `fallback_txt_path` on write error
/// or immediately when `forced_fallback_reason` is `Some`.
#[must_use]
pub fn write_hash_file_with_fallback(
    primary_path: &Path,
    fallback_txt_path: &Path,
    content: &str,
    forced_fallback_reason: Option<String>,
) -> SaveHashOutcome {
    if let Some(reason) = forced_fallback_reason {
        return match std::fs::write(fallback_txt_path, content) {
            Ok(()) => SaveHashOutcome::SavedFallbackTxt {
                path: fallback_txt_path.to_path_buf(),
                reason,
            },
            Err(err) => SaveHashOutcome::Failed {
                primary_path: primary_path.to_path_buf(),
                primary_err: reason,
                fallback_path: fallback_txt_path.to_path_buf(),
                fallback_err: err.to_string(),
            },
        };
    }

    match std::fs::write(primary_path, content) {
        Ok(()) => SaveHashOutcome::SavedPrimary(primary_path.to_path_buf()),
        Err(primary_err) => {
            if primary_path == fallback_txt_path {
                return SaveHashOutcome::Failed {
                    primary_path: primary_path.to_path_buf(),
                    primary_err: primary_err.to_string(),
                    fallback_path: fallback_txt_path.to_path_buf(),
                    fallback_err: primary_err.to_string(),
                };
            }
            match std::fs::write(fallback_txt_path, content) {
                Ok(()) => SaveHashOutcome::SavedFallbackTxt {
                    path: fallback_txt_path.to_path_buf(),
                    reason: format!(
                        "Primary write to '{}' failed ({primary_err}); saved .txt fallback.",
                        primary_path.display()
                    ),
                },
                Err(fallback_err) => SaveHashOutcome::Failed {
                    primary_path: primary_path.to_path_buf(),
                    primary_err: primary_err.to_string(),
                    fallback_path: fallback_txt_path.to_path_buf(),
                    fallback_err: fallback_err.to_string(),
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cmp::Ordering;
    use std::path::{Path, PathBuf};

    use tempfile::TempDir;

    use super::{
        BatchTargetRef, PARALLEL_LARGE_BATCH_BYTES, PARALLEL_WARN_FILE_COUNT, SaveHashOutcome,
        bounded_parallel_workers, build_folder_hash_filename, build_single_hash_filename,
        common_batch_directory, format_batch_hash_manifest, format_single_hash_file_content,
        hash_file_dialog_extensions, is_dedicated_checksum_extension,
        is_text_or_checksum_extension, natural_cmp, needs_explicit_prefix,
        plan_manifest_assignments, scan_folder_for_batch, should_warn_large_parallel_batch,
        write_hash_file_with_fallback,
    };
    use crate::algo::{HashAlgorithm, hash_bytes};
    use crate::digest::{ParsedDigest, parse_digest_entries_from_file, parse_digest_from_file};

    fn sample_digest(hex: &str, algo: HashAlgorithm, explicit: bool) -> ParsedDigest {
        ParsedDigest {
            hex: hex.to_owned(),
            algorithm: algo,
            explicit_algo: explicit,
        }
    }

    #[test]
    fn natural_cmp_orders_numeric_suffixes() {
        let mut names = vec!["prog10.exe", "prog2.exe", "Prog1.exe", "prog02.exe"];
        names.sort_by(|a, b| natural_cmp(a, b));
        assert_eq!(
            names,
            vec!["Prog1.exe", "prog02.exe", "prog2.exe", "prog10.exe"]
        );
        assert_eq!(natural_cmp("item9", "item10"), Ordering::Less);
    }

    #[test]
    fn checksum_extension_helpers_derive_from_hash_algorithm() {
        for algo in HashAlgorithm::all() {
            let file = format!("sample.{}", algo.cli_name().to_ascii_uppercase());
            assert!(is_dedicated_checksum_extension(Path::new(&file)));
            assert!(is_text_or_checksum_extension(Path::new(&file)));
        }
        assert!(!is_dedicated_checksum_extension(Path::new("notes.txt")));
        assert!(is_text_or_checksum_extension(Path::new("notes.txt")));
        assert!(!is_text_or_checksum_extension(Path::new("installer.exe")));

        let dialog_exts = hash_file_dialog_extensions();
        assert!(dialog_exts.contains(&"txt"));
        for algo in HashAlgorithm::all() {
            assert!(dialog_exts.contains(&algo.cli_name()));
        }
    }

    #[test]
    fn scan_folder_top_level_vs_recursive_and_checksum_separation() {
        let dir = TempDir::new().expect("tempdir");
        let sub = dir.path().join("nested");
        std::fs::create_dir_all(&sub).expect("mkdir");

        std::fs::write(dir.path().join("prog10.exe"), b"a").expect("write");
        std::fs::write(dir.path().join("prog2.exe"), b"b").expect("write");
        std::fs::write(dir.path().join("hashes.txt"), b"c").expect("write");
        std::fs::write(dir.path().join("release.sha256"), b"d").expect("write");
        std::fs::write(sub.join("deep.bin"), b"e").expect("write");
        std::fs::write(sub.join("deep.blake3"), b"f").expect("write");

        let top = scan_folder_for_batch(dir.path(), false).expect("top scan");
        let top_names: Vec<_> = top
            .target_files
            .iter()
            .map(|p| p.file_name().expect("name").to_string_lossy().into_owned())
            .collect();
        assert_eq!(top_names, vec!["prog2.exe", "prog10.exe"]);
        assert_eq!(top.checksum_files.len(), 2);

        let rec = scan_folder_for_batch(dir.path(), true).expect("recursive scan");
        assert_eq!(rec.target_files.len(), 3);
        assert_eq!(rec.checksum_files.len(), 3);
    }

    #[test]
    fn manifest_plan_matches_paths_basenames_and_positional_mixed_algos() {
        let p1 = PathBuf::from(r"C:\Dl\prog1.exe");
        let p2 = PathBuf::from(r"C:\Dl\sub\prog2.exe");
        let p3 = PathBuf::from(r"C:\Dl\prog3.exe");
        let targets = [
            BatchTargetRef {
                path: &p1,
                relative_label: "prog1.exe",
            },
            BatchTargetRef {
                path: &p2,
                relative_label: r"sub\prog2.exe",
            },
            BatchTargetRef {
                path: &p3,
                relative_label: "prog3.exe",
            },
        ];

        let path_entries = vec![
            (
                Some("./sub/prog2.exe".to_owned()),
                sample_digest(
                    "d41d8cd98f00b204e9800998ecf8427e",
                    HashAlgorithm::Md5,
                    false,
                ),
            ),
            (
                Some("./prog1.exe".to_owned()),
                sample_digest(
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    HashAlgorithm::Sha256,
                    false,
                ),
            ),
            (
                Some("./missing.exe".to_owned()),
                sample_digest("00000000", HashAlgorithm::Crc32, false),
            ),
        ];

        let plan = plan_manifest_assignments(&targets, &path_entries);
        assert_eq!(plan.matched_by_path, 2);
        assert_eq!(plan.matched_positionally, 0);
        assert_eq!(plan.unmatched_entries, 1);
        assert_eq!(plan.assignments[0].0, 1);
        assert_eq!(plan.assignments[0].1.algorithm, HashAlgorithm::Md5);
        assert_eq!(plan.assignments[1].0, 0);
        assert_eq!(plan.assignments[1].1.algorithm, HashAlgorithm::Sha256);

        let bare_entries = vec![
            (
                None,
                sample_digest(
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    HashAlgorithm::Blake3,
                    true,
                ),
            ),
            (
                None,
                sample_digest(
                    "d41d8cd98f00b204e9800998ecf8427e",
                    HashAlgorithm::Md5,
                    false,
                ),
            ),
            (None, sample_digest("00000000", HashAlgorithm::Crc32, false)),
            (None, sample_digest("ffffffff", HashAlgorithm::Crc32, false)),
        ];
        let bare_plan = plan_manifest_assignments(&targets, &bare_entries);
        assert_eq!(bare_plan.matched_by_path, 0);
        assert_eq!(bare_plan.matched_positionally, 3);
        assert_eq!(bare_plan.unmatched_entries, 1);
        assert_eq!(
            bare_plan
                .assignments
                .iter()
                .map(|(i, d)| (*i, d.algorithm))
                .collect::<Vec<_>>(),
            vec![
                (0, HashAlgorithm::Blake3),
                (1, HashAlgorithm::Md5),
                (2, HashAlgorithm::Crc32),
            ]
        );
    }

    #[test]
    fn parallel_guard_thresholds_and_worker_caps() {
        assert!(!should_warn_large_parallel_batch(
            PARALLEL_WARN_FILE_COUNT - 1,
            PARALLEL_LARGE_BATCH_BYTES + 1
        ));
        assert!(!should_warn_large_parallel_batch(
            PARALLEL_WARN_FILE_COUNT,
            PARALLEL_LARGE_BATCH_BYTES
        ));
        assert!(should_warn_large_parallel_batch(
            PARALLEL_WARN_FILE_COUNT,
            PARALLEL_LARGE_BATCH_BYTES + 1
        ));

        let small_cap = bounded_parallel_workers(1024);
        assert!((2..=4).contains(&small_cap));
        assert_eq!(bounded_parallel_workers(PARALLEL_LARGE_BATCH_BYTES + 1), 2);
    }

    #[test]
    fn explicit_prefix_rule_is_dynamic_across_all_algorithms() {
        for &algo in HashAlgorithm::all() {
            let expected = HashAlgorithm::from_hex_len(algo.expected_hex_len()) != Some(algo);
            assert_eq!(needs_explicit_prefix(algo), expected);
        }
        assert!(needs_explicit_prefix(HashAlgorithm::Blake3));
        assert!(!needs_explicit_prefix(HashAlgorithm::Sha256));
        assert!(!needs_explicit_prefix(HashAlgorithm::Md5));
        assert!(!needs_explicit_prefix(HashAlgorithm::Sha512));
        assert!(!needs_explicit_prefix(HashAlgorithm::Crc32));
    }

    #[test]
    fn single_hash_filename_merges_target_extension_and_handles_edges() {
        let video = Path::new("2026-11-22 21-55-52.mp4");
        for &algo in HashAlgorithm::all() {
            let generated = build_single_hash_filename(video, Some(algo));
            let expected = format!("2026-11-22 21-55-52mp4hash.{}", algo.cli_name());
            assert_eq!(generated, expected);
        }
        assert_eq!(
            build_single_hash_filename(video, None),
            "2026-11-22 21-55-52mp4hash.txt"
        );
        assert_eq!(
            build_single_hash_filename(Path::new("archive.tar.gz"), Some(HashAlgorithm::Md5)),
            "archive.targzhash.md5"
        );
        assert_eq!(
            build_single_hash_filename(Path::new("README"), Some(HashAlgorithm::Sha256)),
            "READMEhash.sha256"
        );
        assert_eq!(
            build_single_hash_filename(Path::new(""), None),
            "filehash.txt"
        );
    }

    #[test]
    fn single_hash_file_content_round_trips_through_digest_parser() {
        let dir = TempDir::new().expect("tempdir");
        for &algo in HashAlgorithm::all() {
            let payload_name = if algo == HashAlgorithm::Md5 {
                "1234"
            } else {
                "clip file.mp4"
            };
            let target = dir.path().join(payload_name);
            let digest = hash_bytes(b"payload", algo);
            let content = format_single_hash_file_content(&target, algo, &digest);
            if needs_explicit_prefix(algo) {
                assert!(content.starts_with(&format!("{}:", algo.cli_name())));
            } else {
                assert!(content.starts_with(&digest));
            }
            let out_path = dir
                .path()
                .join(build_single_hash_filename(&target, Some(algo)));
            std::fs::write(&out_path, &content).expect("write");

            let parsed = parse_digest_from_file(&out_path, Some(&target), None).expect("parse");
            assert_eq!(parsed.algorithm, algo);
            assert_eq!(parsed.hex, digest);
        }
    }

    #[test]
    fn folder_naming_and_common_directory_resolution() {
        let dir = TempDir::new().expect("tempdir");
        let sub = dir.path().join("nested");
        std::fs::create_dir_all(&sub).expect("mkdir");
        let f1 = dir.path().join("a.bin");
        let f2 = sub.join("b.bin");
        std::fs::write(&f1, b"1").expect("write");
        std::fs::write(&f2, b"2").expect("write");

        let rows = [f1.as_path(), f2.as_path()];
        assert_eq!(
            common_batch_directory(Some(dir.path()), &rows),
            Some(dir.path().to_path_buf())
        );
        assert_eq!(common_batch_directory(None, &rows), None);

        let same_parent = [dir.path().join("x.bin"), dir.path().join("y.bin")];
        let same_refs = [same_parent[0].as_path(), same_parent[1].as_path()];
        assert_eq!(
            common_batch_directory(None, &same_refs),
            Some(dir.path().to_path_buf())
        );

        let unrelated = [Path::new("alpha/one.bin"), Path::new("beta/two.bin")];
        assert_eq!(common_batch_directory(None, &unrelated), None);
        assert_eq!(common_batch_directory(None, &[]), None);

        let folder = Path::new("Dl").join("My Folder");
        assert_eq!(
            build_folder_hash_filename(&folder, Some(HashAlgorithm::Sha256)),
            "My Folderhash.sha256"
        );
        assert_eq!(
            build_folder_hash_filename(&folder, None),
            "My Folderhash.txt"
        );
        #[cfg(windows)]
        assert_eq!(
            build_folder_hash_filename(Path::new(r"W:\"), Some(HashAlgorithm::Md5)),
            "batchhash.md5"
        );
        assert_eq!(
            build_folder_hash_filename(Path::new("/"), None),
            "batchhash.txt"
        );
    }

    #[test]
    fn batch_manifest_round_trips_mixed_algos_and_subfolders() {
        let dir = TempDir::new().expect("tempdir");
        let sub = dir.path().join("sub");
        std::fs::create_dir_all(&sub).expect("mkdir");

        let p1 = dir.path().join("prog1.exe");
        let p2 = sub.join("prog 2.mp4");
        let p3 = dir.path().join("notes.bin");
        std::fs::write(&p1, b"one").expect("write");
        std::fs::write(&p2, b"two").expect("write");
        std::fs::write(&p3, b"three").expect("write");

        let h1 = hash_bytes(b"one", HashAlgorithm::Sha256);
        let h2 = hash_bytes(b"two", HashAlgorithm::Md5);
        let h3 = hash_bytes(b"three", HashAlgorithm::Blake3);

        let items = [
            (p1.as_path(), HashAlgorithm::Sha256, h1.as_str()),
            (p2.as_path(), HashAlgorithm::Md5, h2.as_str()),
            (p3.as_path(), HashAlgorithm::Blake3, h3.as_str()),
        ];
        let manifest_text = format_batch_hash_manifest(dir.path(), &items);
        let expected_lines =
            format!("{h1} ./prog1.exe\n{h2} ./sub/prog 2.mp4\nblake3:{h3} ./notes.bin\n");
        assert_eq!(manifest_text, expected_lines);

        let manifest_path = dir
            .path()
            .join(build_folder_hash_filename(dir.path(), None));
        std::fs::write(&manifest_path, &manifest_text).expect("write manifest");

        let parsed_entries = parse_digest_entries_from_file(&manifest_path, None).expect("parse");
        let targets = [
            BatchTargetRef {
                path: &p1,
                relative_label: "prog1.exe",
            },
            BatchTargetRef {
                path: &p2,
                relative_label: r"sub\prog 2.mp4",
            },
            BatchTargetRef {
                path: &p3,
                relative_label: "notes.bin",
            },
        ];
        let plan = plan_manifest_assignments(&targets, &parsed_entries);
        assert_eq!(plan.matched_by_path, 3);
        assert_eq!(plan.matched_positionally, 0);
        assert_eq!(plan.unmatched_entries, 0);
        assert_eq!(plan.assignments[0].1.algorithm, HashAlgorithm::Sha256);
        assert_eq!(plan.assignments[0].1.hex, h1);
        assert_eq!(plan.assignments[1].1.algorithm, HashAlgorithm::Md5);
        assert_eq!(plan.assignments[1].1.hex, h2);
        assert_eq!(plan.assignments[2].1.algorithm, HashAlgorithm::Blake3);
        assert_eq!(plan.assignments[2].1.hex, h3);
    }

    #[test]
    fn write_hash_file_with_fallback_covers_primary_forced_error_fallback_and_both_fail() {
        let dir = TempDir::new().expect("tempdir");

        let p1 = dir.path().join("ok.sha256");
        let f1 = dir.path().join("ok.txt");
        assert_eq!(
            write_hash_file_with_fallback(&p1, &f1, "abc  file\n", None),
            SaveHashOutcome::SavedPrimary(p1.clone())
        );
        assert_eq!(std::fs::read_to_string(&p1).expect("read"), "abc  file\n");
        assert!(!f1.exists());

        let p2 = dir.path().join("mixed.sha256");
        let f2 = dir.path().join("mixed.txt");
        assert_eq!(
            write_hash_file_with_fallback(
                &p2,
                &f2,
                "mixed content\n",
                Some("mixed algos".to_owned()),
            ),
            SaveHashOutcome::SavedFallbackTxt {
                path: f2.clone(),
                reason: "mixed algos".to_owned(),
            }
        );
        assert!(!p2.exists());
        assert_eq!(
            std::fs::read_to_string(&f2).expect("read"),
            "mixed content\n"
        );

        let p3 = dir.path().join("blocked_primary.sha256");
        let f3 = dir.path().join("fallback_ok.txt");
        std::fs::create_dir(&p3).expect("create blocking dir");
        match write_hash_file_with_fallback(&p3, &f3, "fallback data\n", None) {
            SaveHashOutcome::SavedFallbackTxt { path, reason } => {
                assert_eq!(path, f3);
                assert!(reason.contains("failed"));
            }
            other => panic!("expected SavedFallbackTxt, got {other:?}"),
        }
        assert_eq!(
            std::fs::read_to_string(&f3).expect("read"),
            "fallback data\n"
        );

        let p4 = dir.path().join("blocked_p.sha256");
        let f4 = dir.path().join("blocked_f.txt");
        std::fs::create_dir(&p4).expect("create blocking primary");
        std::fs::create_dir(&f4).expect("create blocking fallback");
        assert!(matches!(
            write_hash_file_with_fallback(&p4, &f4, "fail\n", None),
            SaveHashOutcome::Failed { .. }
        ));
    }
}
