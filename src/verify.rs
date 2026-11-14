//! Verification orchestration, smart argument resolution, and file stability polling.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, anyhow, bail};

use crate::algo::{HashAlgorithm, hash_file_many_with_progress, hash_file_with_progress};
use crate::digest::{
    DigestError, MAX_HASH_FILE_BYTES, ParsedDigest, file_mentions_target, parse_digest_from_file,
    parse_digest_str,
};

/// Poll interval for [`wait_for_stable_file`].
const STABILITY_POLL_INTERVAL: Duration = Duration::from_millis(200);

/// Structured verification or computation result for CLI, GUI, and `--json` output.
#[derive(Debug, Clone, serde::Serialize)]
pub struct VerifyReport {
    /// Result status string: `"IDENTICAL"`, `"MISMATCH"`, or `"COMPUTED"`.
    pub status: String,
    /// `true` on match or compute-only completion; `false` on digest mismatch.
    pub identical: bool,
    /// Display name of the hash algorithm (e.g. `"SHA-256"`).
    pub algorithm: String,
    /// Expected lowercase hex digest when verifying, or `None` when computing only.
    pub expected: Option<String>,
    /// Computed lowercase hex digest of the target file.
    pub actual: String,
    /// Display path of the target file.
    pub file: String,
    /// Total bytes hashed.
    pub bytes: u64,
    /// Elapsed hashing duration in milliseconds.
    pub elapsed_ms: u128,
    /// Sustained throughput in MiB/s.
    pub throughput_mbps: f64,
}

/// Single algorithm digest item inside a multi-algorithm compute report.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MultiDigestItem {
    /// Display name of the hash algorithm (e.g. `"SHA-256"`).
    pub algorithm: String,
    /// Lowercase hexadecimal digest of the target file.
    pub digest: String,
}

/// Structured single-pass multi-algorithm computation result for CLI, GUI, and `--json` output.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MultiComputeReport {
    /// Result status string (`"COMPUTED_ALL"`).
    pub status: String,
    /// Display path of the target file.
    pub file: String,
    /// Computed digests ordered according to the requested algorithm slice.
    pub digests: Vec<MultiDigestItem>,
    /// Total bytes hashed.
    pub bytes: u64,
    /// Elapsed hashing duration in milliseconds.
    pub elapsed_ms: u128,
    /// Sustained hashing throughput in MiB/s.
    pub throughput_mbps: f64,
}

/// Resolved target file path and expected digest extracted from CLI arguments.
#[derive(Debug, Clone)]
pub struct ResolvedCheckInput {
    /// Path to the target file to hash.
    pub target_file: PathBuf,
    /// Normalized expected digest and algorithm.
    pub expected: ParsedDigest,
}

fn strip_outer_quotes(raw: &str) -> &str {
    let mut s = raw.trim();
    while s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
    {
        s = s[1..s.len() - 1].trim();
    }
    s
}

/// Ranks how strongly a filename/extension indicates a checksum file vs a target file.
fn checksum_file_rank(path: &Path) -> u8 {
    if let Some(ext) = path.extension().and_then(std::ffi::OsStr::to_str) {
        let dedicated = [
            "sha256", "sha512", "sha384", "sha1", "md5", "crc32", "blake3", "b3", "sum", "sums",
            "sfv", "hash", "digest",
        ];
        if dedicated.iter().any(|cand| ext.eq_ignore_ascii_case(cand)) {
            return 2;
        }
        if ext.eq_ignore_ascii_case("txt")
            || ext.eq_ignore_ascii_case("asc")
            || ext.eq_ignore_ascii_case("sig")
        {
            return 1;
        }
    }

    if let Some(name) = path.file_name().and_then(std::ffi::OsStr::to_str) {
        let lower = name.to_ascii_lowercase();
        if lower.contains("checksum")
            || lower.contains("sha256sum")
            || lower.contains("sha512sum")
            || lower.contains("sha1sum")
            || lower.contains("shasum")
            || lower.contains("md5sum")
            || lower.contains("b3sum")
        {
            return 2;
        }
    }

    0
}

fn try_parse_hash_candidate(
    candidate: &Path,
    target: &Path,
    override_algo: Option<HashAlgorithm>,
) -> Result<ParsedDigest, DigestError> {
    let len = fs::metadata(candidate)?.len();
    if len > MAX_HASH_FILE_BYTES {
        return Err(DigestError::FileTooLarge(len));
    }
    parse_digest_from_file(candidate, Some(target), override_algo)
}

fn resolve_both_files(
    p1: &Path,
    p2: &Path,
    force_hash_file: bool,
    override_algo: Option<HashAlgorithm>,
) -> anyhow::Result<ResolvedCheckInput> {
    let r1 = try_parse_hash_candidate(p1, p2, override_algo);
    let r2 = try_parse_hash_candidate(p2, p1, override_algo);

    match (r1, r2) {
        (Ok(expected), Err(_)) => Ok(ResolvedCheckInput {
            target_file: p2.to_path_buf(),
            expected,
        }),
        (Err(_), Ok(expected)) => Ok(ResolvedCheckInput {
            target_file: p1.to_path_buf(),
            expected,
        }),
        (Ok(d1), Ok(d2)) => {
            if force_hash_file {
                return Ok(ResolvedCheckInput {
                    target_file: p2.to_path_buf(),
                    expected: d1,
                });
            }

            let rank1 = checksum_file_rank(p1);
            let rank2 = checksum_file_rank(p2);
            if rank1 > rank2 {
                return Ok(ResolvedCheckInput {
                    target_file: p2.to_path_buf(),
                    expected: d1,
                });
            }
            if rank2 > rank1 {
                return Ok(ResolvedCheckInput {
                    target_file: p1.to_path_buf(),
                    expected: d2,
                });
            }

            let m1 = file_mentions_target(p1, p2, override_algo);
            let m2 = file_mentions_target(p2, p1, override_algo);
            if m1 && !m2 {
                return Ok(ResolvedCheckInput {
                    target_file: p2.to_path_buf(),
                    expected: d1,
                });
            }
            if m2 && !m1 {
                return Ok(ResolvedCheckInput {
                    target_file: p1.to_path_buf(),
                    expected: d2,
                });
            }

            bail!(
                "ambiguous inputs: both '{}' and '{}' contain valid digests; pass --hash-file (-f) to specify the hash file",
                p1.display(),
                p2.display()
            )
        }
        (Err(e1), Err(e2)) => {
            let rank1 = checksum_file_rank(p1);
            let rank2 = checksum_file_rank(p2);
            if force_hash_file || rank1 > rank2 {
                Err(anyhow!(e1).context(format!(
                    "failed to parse '{}' as a hash file",
                    p1.display()
                )))
            } else if rank2 > rank1 {
                Err(anyhow!(e2).context(format!(
                    "failed to parse '{}' as a hash file",
                    p2.display()
                )))
            } else {
                bail!(
                    "neither '{}' ({}) nor '{}' ({}) is a valid hash file",
                    p1.display(),
                    e1,
                    p2.display(),
                    e2
                )
            }
        }
    }
}

/// Resolves two positional CLI arguments into `(target_file, expected_digest)`.
///
/// Supports `<hash> <file>`, `<file> <hash>`, `<hash.txt> <file>`, and `<file> <hash.txt>`,
/// stripping outer quotes and checking file size/extension heuristics when both arguments
/// point to existing files.
///
/// # Errors
///
/// Returns an error if a required file does not exist, a path is a directory, a digest string
/// or hash file is invalid, or two existing candidate hash files cannot be disambiguated.
pub fn resolve_check_args(
    arg1: &str,
    arg2: &str,
    force_hash_file: bool,
    override_algo: Option<HashAlgorithm>,
) -> anyhow::Result<ResolvedCheckInput> {
    let a1 = strip_outer_quotes(arg1);
    let a2 = strip_outer_quotes(arg2);
    if a1.is_empty() || a2.is_empty() {
        bail!("both hash/hash-file and target file arguments must be non-empty");
    }

    let p1 = Path::new(a1);
    let p2 = Path::new(a2);

    if p1.is_dir() {
        bail!("expected a file, found directory: {}", p1.display());
    }
    if p2.is_dir() {
        bail!("expected a file, found directory: {}", p2.display());
    }

    match (p1.is_file(), p2.is_file()) {
        (true, true) => resolve_both_files(p1, p2, force_hash_file, override_algo),
        (false, true) => {
            if force_hash_file {
                bail!("hash file not found: {}", p1.display());
            }
            let expected = parse_digest_str(a1, override_algo)
                .with_context(|| format!("invalid digest or missing hash file '{a1}'"))?;
            Ok(ResolvedCheckInput {
                target_file: p2.to_path_buf(),
                expected,
            })
        }
        (true, false) => {
            if force_hash_file {
                if try_parse_hash_candidate(p1, p2, override_algo).is_ok() {
                    bail!("target file not found: {}", p2.display());
                }
                bail!("hash file not found: {}", p2.display());
            }
            match parse_digest_str(a2, override_algo) {
                Ok(expected) => Ok(ResolvedCheckInput {
                    target_file: p1.to_path_buf(),
                    expected,
                }),
                Err(err) => {
                    if checksum_file_rank(p1) > 0
                        && try_parse_hash_candidate(p1, p2, override_algo).is_ok()
                    {
                        bail!("target file not found: {}", p2.display());
                    }
                    Err(anyhow!(err)
                        .context(format!("invalid digest or missing target file '{a2}'")))
                }
            }
        }
        (false, false) => {
            if parse_digest_str(a1, override_algo).is_ok() {
                bail!("target file not found: {}", p2.display());
            }
            if parse_digest_str(a2, override_algo).is_ok() {
                bail!("target file not found: {}", p1.display());
            }
            bail!(
                "target file not found: neither '{}' nor '{}' exists",
                p1.display(),
                p2.display()
            )
        }
    }
}

/// Computes the file hash using `expected.algorithm` and compares it against `expected.hex`.
///
/// # Errors
///
/// Returns an error if reading or hashing `target_file` fails or is cancelled.
pub fn verify_target(
    target_file: &Path,
    expected: &ParsedDigest,
    progress: Option<&AtomicU64>,
    cancel: Option<&AtomicBool>,
    on_chunk: Option<&mut dyn FnMut(u64, u64)>,
) -> anyhow::Result<VerifyReport> {
    let metrics =
        hash_file_with_progress(target_file, expected.algorithm, progress, cancel, on_chunk)
            .with_context(|| format!("failed to hash '{}'", target_file.display()))?;

    let identical = metrics.digest == expected.hex;
    Ok(VerifyReport {
        status: if identical {
            "IDENTICAL".to_string()
        } else {
            "MISMATCH".to_string()
        },
        identical,
        algorithm: expected.algorithm.as_str().to_string(),
        expected: Some(expected.hex.clone()),
        actual: metrics.digest,
        file: target_file.display().to_string(),
        bytes: metrics.bytes_processed,
        elapsed_ms: metrics.elapsed_ms,
        throughput_mbps: metrics.throughput_mbps,
    })
}

/// Computes a file digest without comparing against an expected value.
///
/// # Errors
///
/// Returns an error if reading or hashing `target_file` fails or is cancelled.
pub fn compute_only(
    target_file: &Path,
    algo: HashAlgorithm,
    progress: Option<&AtomicU64>,
    cancel: Option<&AtomicBool>,
    on_chunk: Option<&mut dyn FnMut(u64, u64)>,
) -> anyhow::Result<VerifyReport> {
    let metrics = hash_file_with_progress(target_file, algo, progress, cancel, on_chunk)
        .with_context(|| format!("failed to hash '{}'", target_file.display()))?;

    Ok(VerifyReport {
        status: "COMPUTED".to_string(),
        identical: true,
        algorithm: algo.as_str().to_string(),
        expected: None,
        actual: metrics.digest,
        file: target_file.display().to_string(),
        bytes: metrics.bytes_processed,
        elapsed_ms: metrics.elapsed_ms,
        throughput_mbps: metrics.throughput_mbps,
    })
}

/// Computes digests for every algorithm in `algos` in a single streaming read pass over `target_file`.
///
/// # Errors
///
/// Returns an error if reading or hashing `target_file` fails or is cancelled.
pub fn compute_many(
    target_file: &Path,
    algos: &[HashAlgorithm],
    progress: Option<&AtomicU64>,
    cancel: Option<&AtomicBool>,
    on_chunk: Option<&mut dyn FnMut(u64, u64)>,
) -> anyhow::Result<MultiComputeReport> {
    let metrics = hash_file_many_with_progress(target_file, algos, progress, cancel, on_chunk)
        .with_context(|| format!("failed to hash '{}'", target_file.display()))?;

    let digests = metrics
        .digests
        .into_iter()
        .map(|entry| MultiDigestItem {
            algorithm: entry.algorithm.as_str().to_owned(),
            digest: entry.digest,
        })
        .collect();

    Ok(MultiComputeReport {
        status: "COMPUTED_ALL".to_owned(),
        file: target_file.display().to_string(),
        digests,
        bytes: metrics.bytes_processed,
        elapsed_ms: metrics.elapsed_ms,
        throughput_mbps: metrics.throughput_mbps,
    })
}

/// Formats multi-algorithm digests as `"<ALGORITHM>: <digest>"` lines separated by `"\n"`.
#[must_use]
pub fn format_multi_clipboard_text(report: &MultiComputeReport) -> String {
    report
        .digests
        .iter()
        .map(|item| format!("{}: {}", item.algorithm, item.digest))
        .collect::<Vec<_>>()
        .join("\n")
}

fn file_state(path: &Path) -> io::Result<(u64, Option<SystemTime>)> {
    let meta = fs::metadata(path)?;
    Ok((meta.len(), meta.modified().ok()))
}

/// Polls `path` size and modification timestamp every ~200ms until unchanged for `quiet_window`.
///
/// # Errors
///
/// Returns an `io::Error` if stating `path` fails (for example, if the file is missing or deleted).
pub fn wait_for_stable_file(path: &Path, quiet_window: Duration) -> io::Result<()> {
    let mut last_state = file_state(path)?;
    if quiet_window.is_zero() {
        return Ok(());
    }

    let mut stable_since = Instant::now();
    loop {
        let elapsed = stable_since.elapsed();
        if elapsed >= quiet_window {
            return Ok(());
        }

        let remaining = quiet_window.saturating_sub(elapsed);
        let sleep_for = STABILITY_POLL_INTERVAL
            .min(remaining)
            .max(Duration::from_millis(1));
        std::thread::sleep(sleep_for);

        let current_state = file_state(path)?;
        if current_state != last_state {
            last_state = current_state;
            stable_since = Instant::now();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::thread;
    use std::time::Duration;

    use tempfile::TempDir;

    use super::{
        MultiComputeReport, MultiDigestItem, compute_many, compute_only,
        format_multi_clipboard_text, resolve_check_args, verify_target, wait_for_stable_file,
    };
    use crate::algo::{HashAlgorithm, hash_bytes};
    use crate::digest::parse_digest_str;

    #[test]
    fn resolve_check_args_handles_swap_quotes_and_hash_files() {
        let dir = TempDir::new().expect("tempdir");
        let target_path = dir.path().join("payload.bin");
        let payload = b"hello hasher world";
        std::fs::write(&target_path, payload).expect("write target");

        let digest_hex = hash_bytes(payload, HashAlgorithm::Sha256);
        let quoted_target = format!("\"{}\"", target_path.display());

        let r1 = resolve_check_args(&digest_hex, &quoted_target, false, None)
            .expect("hash then file");
        assert_eq!(r1.target_file, target_path);
        assert_eq!(r1.expected.hex, digest_hex);

        let r2 = resolve_check_args(&quoted_target, &digest_hex, false, None)
            .expect("swapped file then hash");
        assert_eq!(r2.target_file, target_path);
        assert_eq!(r2.expected.hex, digest_hex);

        let hash_txt_path = dir.path().join("checksums.txt");
        std::fs::write(&hash_txt_path, format!("{digest_hex}  payload.bin\n"))
            .expect("write hash txt");
        let hash_txt_str = hash_txt_path.to_string_lossy().into_owned();

        let r3 = resolve_check_args(&hash_txt_str, &quoted_target, false, None)
            .expect("hash.txt then file");
        assert_eq!(r3.target_file, target_path);
        assert_eq!(r3.expected.hex, digest_hex);

        let r4 = resolve_check_args(&quoted_target, &hash_txt_str, false, None)
            .expect("file then hash.txt");
        assert_eq!(r4.target_file, target_path);
        assert_eq!(r4.expected.hex, digest_hex);
    }

    #[test]
    fn resolve_check_args_reports_missing_or_ambiguous_files() {
        let dir = TempDir::new().expect("tempdir");
        let f1 = dir.path().join("a.txt");
        let f2 = dir.path().join("b.txt");
        let digest_a = hash_bytes(b"a", HashAlgorithm::Sha256);
        let digest_b = hash_bytes(b"b", HashAlgorithm::Sha256);
        std::fs::write(&f1, format!("{digest_a}\n")).expect("write a");
        std::fs::write(&f2, format!("{digest_b}\n")).expect("write b");

        let s1 = f1.to_string_lossy().into_owned();
        let s2 = f2.to_string_lossy().into_owned();
        assert!(resolve_check_args(&s1, &s2, false, None).is_err());

        let forced = resolve_check_args(&s1, &s2, true, None).expect("forced hash file");
        assert_eq!(forced.target_file, f2);
        assert_eq!(forced.expected.hex, digest_a);

        let missing = dir.path().join("does-not-exist.bin");
        let missing_str = missing.to_string_lossy().into_owned();
        assert!(resolve_check_args(&digest_a, &missing_str, false, None).is_err());
    }

    #[test]
    fn verify_target_and_compute_only_reports() {
        let dir = TempDir::new().expect("tempdir");
        let target_path = dir.path().join("sample.dat");
        std::fs::write(&target_path, b"abc").expect("write sample");

        let good_digest =
            parse_digest_str("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", None)
                .expect("good digest");
        let ok_report = verify_target(&target_path, &good_digest, None, None, None).expect("verify");
        assert!(ok_report.identical);
        assert_eq!(ok_report.status, "IDENTICAL");
        assert_eq!(ok_report.algorithm, "SHA-256");
        assert_eq!(ok_report.expected.as_deref(), Some(good_digest.hex.as_str()));
        assert_eq!(ok_report.actual, good_digest.hex);
        assert_eq!(ok_report.bytes, 3);

        let bad_digest =
            parse_digest_str("0000000000000000000000000000000000000000000000000000000000000000", None)
                .expect("bad digest");
        let mismatch = verify_target(&target_path, &bad_digest, None, None, None).expect("verify");
        assert!(!mismatch.identical);
        assert_eq!(mismatch.status, "MISMATCH");

        let computed =
            compute_only(&target_path, HashAlgorithm::Blake3, None, None, None).expect("compute");
        assert!(computed.identical);
        assert_eq!(computed.status, "COMPUTED");
        assert_eq!(computed.algorithm, "BLAKE3");
        assert!(computed.expected.is_none());
        assert_eq!(
            computed.actual,
            "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
        );
    }

    #[test]
    fn wait_for_stable_file_waits_for_writes_to_settle() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("downloading.bin");
        {
            let mut f = std::fs::File::create(&path).expect("create");
            f.write_all(b"part1").expect("write");
        }

        let writer_path = path.clone();
        let handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(120));
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&writer_path)
                .expect("open append");
            f.write_all(b"part2").expect("write part2");
            f.flush().expect("flush");
        });

        wait_for_stable_file(&path, Duration::from_millis(350)).expect("wait stable");
        handle.join().expect("join writer");
        let contents = std::fs::read(&path).expect("read settled");
        assert_eq!(contents, b"part1part2");
    }

    #[test]
    fn compute_many_produces_all_digests_and_handles_cancel_or_missing() {
        let dir = TempDir::new().expect("tempdir");
        let target_path = dir.path().join("sample.dat");
        let payload = b"abc";
        std::fs::write(&target_path, payload).expect("write sample");

        let algos = HashAlgorithm::picker_order();
        let progress = AtomicU64::new(0);
        let cancel = AtomicBool::new(false);
        let mut updates = Vec::new();
        let mut cb = |done: u64, total: u64| updates.push((done, total));

        let report = compute_many(
            &target_path,
            algos,
            Some(&progress),
            Some(&cancel),
            Some(&mut cb),
        )
        .expect("compute_many");

        assert_eq!(report.status, "COMPUTED_ALL");
        assert_eq!(report.file, target_path.display().to_string());
        assert_eq!(report.bytes, 3);
        assert_eq!(progress.load(Ordering::Relaxed), 3);
        assert_eq!(updates, vec![(3, 3)]);
        assert!(report.throughput_mbps > 0.0);
        assert_eq!(report.digests.len(), algos.len());

        for (item, &algo) in report.digests.iter().zip(algos) {
            assert_eq!(item.algorithm, algo.as_str());
            assert_eq!(item.digest, hash_bytes(payload, algo));
        }

        cancel.store(true, Ordering::Relaxed);
        let cancelled = compute_many(&target_path, algos, None, Some(&cancel), None)
            .expect_err("cancelled compute_many should error");
        assert!(cancelled.chain().any(|cause| {
            cause
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io_err| io_err.kind() == std::io::ErrorKind::Interrupted)
        }));

        let missing = dir.path().join("missing.bin");
        assert!(compute_many(&missing, algos, None, None, None).is_err());
    }

    #[test]
    fn format_multi_clipboard_text_formats_expected_lines() {
        let empty = MultiComputeReport {
            status: "COMPUTED_ALL".to_owned(),
            file: "empty.bin".to_owned(),
            digests: Vec::new(),
            bytes: 0,
            elapsed_ms: 0,
            throughput_mbps: 0.0,
        };
        assert_eq!(format_multi_clipboard_text(&empty), "");

        let single = MultiComputeReport {
            status: "COMPUTED_ALL".to_owned(),
            file: "one.bin".to_owned(),
            digests: vec![MultiDigestItem {
                algorithm: "SHA-256".to_owned(),
                digest: "abcd".to_owned(),
            }],
            bytes: 1,
            elapsed_ms: 1,
            throughput_mbps: 1.0,
        };
        assert_eq!(format_multi_clipboard_text(&single), "SHA-256: abcd");

        let dir = TempDir::new().expect("tempdir");
        let target_path = dir.path().join("multi.dat");
        let payload = b"abc";
        std::fs::write(&target_path, payload).expect("write multi");

        let algos = HashAlgorithm::picker_order();
        let report = compute_many(&target_path, algos, None, None, None).expect("compute_many");
        let text = format_multi_clipboard_text(&report);
        assert!(!text.ends_with('\n'));

        let expected: Vec<String> = algos
            .iter()
            .map(|&algo| format!("{}: {}", algo.as_str(), hash_bytes(payload, algo)))
            .collect();
        assert_eq!(text, expected.join("\n"));
    }
}
