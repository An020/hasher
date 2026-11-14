//! Cryptographic and checksum hashing algorithms with 4 MiB streaming I/O.

use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use md5::Digest as Md5Digest;
use sha1::Digest as Sha1Digest;
use sha2::Digest as Sha2Digest;

/// Reusable streaming read buffer size (4 MiB).
const STREAM_BUFFER_BYTES: usize = 4 * 1024 * 1024;

/// Supported checksum and cryptographic hash algorithms.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    clap::ValueEnum,
)]
pub enum HashAlgorithm {
    /// IEEE 802.3 CRC-32 (32-bit, 8 hex characters).
    Crc32,
    /// MD5 message digest (128-bit, 32 hex characters).
    Md5,
    /// SHA-1 message digest (160-bit, 40 hex characters).
    Sha1,
    /// SHA-256 message digest (256-bit, 64 hex characters).
    Sha256,
    /// SHA-384 message digest (384-bit, 96 hex characters).
    Sha384,
    /// SHA-512 message digest (512-bit, 128 hex characters).
    Sha512,
    /// BLAKE3 message digest (256-bit, 64 hex characters).
    Blake3,
}

impl HashAlgorithm {
    /// Canonical display name for the algorithm.
    #[must_use]
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Crc32 => "CRC32",
            Self::Md5 => "MD5",
            Self::Sha1 => "SHA-1",
            Self::Sha256 => "SHA-256",
            Self::Sha384 => "SHA-384",
            Self::Sha512 => "SHA-512",
            Self::Blake3 => "BLAKE3",
        }
    }

    /// Expected lowercase hexadecimal digest length in characters.
    #[must_use]
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn expected_hex_len(&self) -> usize {
        match self {
            Self::Crc32 => 8,
            Self::Md5 => 32,
            Self::Sha1 => 40,
            Self::Sha256 | Self::Blake3 => 64,
            Self::Sha384 => 96,
            Self::Sha512 => 128,
        }
    }

    /// Infers the default algorithm from a normalized hex digest length.
    ///
    /// Note that 64-character digests default to `SHA-256`; `BLAKE3` requires
    /// explicit selection or a `blake3:` prefix.
    #[must_use]
    pub fn from_hex_len(len: usize) -> Option<Self> {
        match len {
            8 => Some(Self::Crc32),
            32 => Some(Self::Md5),
            40 => Some(Self::Sha1),
            64 => Some(Self::Sha256),
            96 => Some(Self::Sha384),
            128 => Some(Self::Sha512),
            _ => None,
        }
    }

    /// Returns a static slice containing every supported algorithm.
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[
            Self::Crc32,
            Self::Md5,
            Self::Sha1,
            Self::Sha256,
            Self::Sha384,
            Self::Sha512,
            Self::Blake3,
        ]
    }

    /// Default hash algorithm used for compute-only mode and quick-picker fallback.
    pub const DEFAULT_COMPUTE_ALGORITHM: Self = Self::Sha256;

    /// Returns the canonical display and selection order shared by the CLI quick
    /// picker, single-pass `"All"` mode, and GUI dropdown.
    #[must_use]
    pub const fn picker_order() -> &'static [Self] {
        &[
            Self::Sha256,
            Self::Sha512,
            Self::Sha384,
            Self::Sha1,
            Self::Md5,
            Self::Crc32,
            Self::Blake3,
        ]
    }

    /// Returns the canonical lowercase CLI identifier for this algorithm.
    #[must_use]
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub const fn cli_name(&self) -> &'static str {
        match self {
            Self::Crc32 => "crc32",
            Self::Md5 => "md5",
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
            Self::Blake3 => "blake3",
        }
    }

    /// Parses an algorithm name or alias dynamically by comparing normalized ASCII
    /// (case-insensitive, stripping `-` and `_`) against [`Self::as_str`] and [`Self::cli_name`].
    #[must_use]
    pub fn from_alias(raw: &str) -> Option<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() || !trimmed.is_ascii() {
            return None;
        }
        Self::all().iter().copied().find(|algo| {
            eq_normalized_ascii(trimmed, algo.as_str())
                || eq_normalized_ascii(trimmed, algo.cli_name())
        })
    }
}

/// Single source of truth for default compute-only and quick-picker algorithm selection.
pub const DEFAULT_COMPUTE_ALGORITHM: HashAlgorithm = HashAlgorithm::DEFAULT_COMPUTE_ALGORITHM;

fn eq_normalized_ascii(lhs: &str, rhs: &str) -> bool {
    let lhs_iter = lhs
        .bytes()
        .filter(|&b| b != b'-' && b != b'_')
        .map(|b| b.to_ascii_lowercase());
    let rhs_iter = rhs
        .bytes()
        .filter(|&b| b != b'-' && b != b'_')
        .map(|b| b.to_ascii_lowercase());
    lhs_iter.eq(rhs_iter)
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Digest output and throughput telemetry for a completed hash operation.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HashMetrics {
    /// Lowercase hexadecimal digest string.
    pub digest: String,
    /// Algorithm used to compute the digest.
    pub algorithm: HashAlgorithm,
    /// Total input bytes read.
    pub bytes_processed: u64,
    /// Elapsed wall-clock time in milliseconds.
    pub elapsed_ms: u128,
    /// Sustained hashing throughput in MiB/s.
    pub throughput_mbps: f64,
}

/// Single algorithm and computed digest pair produced by multi-algorithm hashing.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DigestEntry {
    /// Algorithm used to compute this digest.
    pub algorithm: HashAlgorithm,
    /// Lowercase hexadecimal digest string.
    pub digest: String,
}

/// Digest outputs and throughput telemetry for a single-pass multi-algorithm hash operation.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MultiHashMetrics {
    /// Computed digests ordered according to the requested algorithm slice.
    pub digests: Vec<DigestEntry>,
    /// Total input bytes read.
    pub bytes_processed: u64,
    /// Elapsed wall-clock time in milliseconds.
    pub elapsed_ms: u128,
    /// Sustained hashing throughput in MiB/s.
    pub throughput_mbps: f64,
}

/// Static-dispatch wrapper around concrete stateful hashers.
enum HasherEngine {
    Crc32(crc32fast::Hasher),
    Md5(md5::Md5),
    Sha1(sha1::Sha1),
    Sha256(sha2::Sha256),
    Sha384(Box<sha2::Sha384>),
    Sha512(Box<sha2::Sha512>),
    Blake3(Box<blake3::Hasher>),
}

impl HasherEngine {
    fn new(algo: HashAlgorithm) -> Self {
        match algo {
            HashAlgorithm::Crc32 => Self::Crc32(crc32fast::Hasher::new()),
            HashAlgorithm::Md5 => Self::Md5(Md5Digest::new()),
            HashAlgorithm::Sha1 => Self::Sha1(Sha1Digest::new()),
            HashAlgorithm::Sha256 => Self::Sha256(Sha2Digest::new()),
            HashAlgorithm::Sha384 => Self::Sha384(Box::new(Sha2Digest::new())),
            HashAlgorithm::Sha512 => Self::Sha512(Box::new(Sha2Digest::new())),
            HashAlgorithm::Blake3 => Self::Blake3(Box::new(blake3::Hasher::new())),
        }
    }

    fn update(&mut self, chunk: &[u8]) {
        match self {
            Self::Crc32(h) => h.update(chunk),
            Self::Md5(h) => Md5Digest::update(h, chunk),
            Self::Sha1(h) => Sha1Digest::update(h, chunk),
            Self::Sha256(h) => Sha2Digest::update(h, chunk),
            Self::Sha384(h) => Sha2Digest::update(h.as_mut(), chunk),
            Self::Sha512(h) => Sha2Digest::update(h.as_mut(), chunk),
            Self::Blake3(h) => {
                h.update(chunk);
            }
        }
    }

    fn finalize(self) -> String {
        match self {
            Self::Crc32(h) => {
                let sum = h.finalize();
                format!("{sum:08x}")
            }
            Self::Md5(h) => encode_hex_lower(Md5Digest::finalize(h).as_slice()),
            Self::Sha1(h) => encode_hex_lower(Sha1Digest::finalize(h).as_slice()),
            Self::Sha256(h) => encode_hex_lower(Sha2Digest::finalize(h).as_slice()),
            Self::Sha384(h) => encode_hex_lower(Sha2Digest::finalize(*h).as_slice()),
            Self::Sha512(h) => encode_hex_lower(Sha2Digest::finalize(*h).as_slice()),
            Self::Blake3(h) => encode_hex_lower(h.finalize().as_bytes()),
        }
    }
}

fn encode_hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(char::from(HEX[usize::from(b >> 4)]));
        out.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    out
}

struct StreamStats {
    bytes_processed: u64,
    elapsed_ms: u128,
    throughput_mbps: f64,
}

fn check_cancelled(cancel: Option<&AtomicBool>) -> io::Result<()> {
    if cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
        return Err(io::Error::new(io::ErrorKind::Interrupted, "Cancelled"));
    }
    Ok(())
}

fn open_file_checked(path: &Path, cancel: Option<&AtomicBool>) -> io::Result<(File, u64)> {
    check_cancelled(cancel)?;
    let file = File::open(path)?;
    let total_size = file.metadata()?.len();
    Ok((file, total_size))
}

fn stream_reader<R: Read>(
    reader: &mut R,
    total_size: u64,
    progress: Option<&AtomicU64>,
    cancel: Option<&AtomicBool>,
    mut on_chunk: Option<&mut dyn FnMut(u64, u64)>,
    mut on_bytes: impl FnMut(&[u8]),
) -> io::Result<StreamStats> {
    check_cancelled(cancel)?;

    let mut buffer = vec![0u8; STREAM_BUFFER_BYTES];
    let mut bytes_processed: u64 = 0;
    let start = Instant::now();

    loop {
        check_cancelled(cancel)?;

        let n = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read_len) => read_len,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        };

        on_bytes(&buffer[..n]);
        bytes_processed = bytes_processed.saturating_add(n as u64);

        if let Some(counter) = progress {
            counter.store(bytes_processed, Ordering::Relaxed);
        }
        if let Some(cb) = on_chunk.as_deref_mut() {
            cb(bytes_processed, total_size);
        }
    }

    if bytes_processed == 0 {
        if let Some(cb) = on_chunk {
            cb(0, total_size);
        }
    }

    let elapsed = start.elapsed();
    let elapsed_ms = elapsed.as_millis();
    let elapsed_secs = elapsed.as_secs_f64();
    #[allow(clippy::cast_precision_loss)]
    let throughput_mbps = (bytes_processed as f64 / (1024.0 * 1024.0)) / elapsed_secs.max(1e-9);

    Ok(StreamStats {
        bytes_processed,
        elapsed_ms,
        throughput_mbps,
    })
}

/// Streams a reader through the selected hash algorithm using a 4 MiB buffer.
///
/// Checks `cancel` before and during chunk reads and returns an
/// [`io::ErrorKind::Interrupted`] error if cancelled.
///
/// # Errors
///
/// Returns an `io::Error` if reading fails or if `cancel` becomes `true`.
pub fn hash_reader<R: Read>(
    reader: &mut R,
    algo: HashAlgorithm,
    total_size: u64,
    progress: Option<&AtomicU64>,
    cancel: Option<&AtomicBool>,
    on_chunk: Option<&mut dyn FnMut(u64, u64)>,
) -> io::Result<HashMetrics> {
    let mut engine = HasherEngine::new(algo);
    let stats = stream_reader(reader, total_size, progress, cancel, on_chunk, |chunk| {
        engine.update(chunk);
    })?;

    Ok(HashMetrics {
        digest: engine.finalize(),
        algorithm: algo,
        bytes_processed: stats.bytes_processed,
        elapsed_ms: stats.elapsed_ms,
        throughput_mbps: stats.throughput_mbps,
    })
}

/// Streams a reader once through every algorithm in `algos` using a 4 MiB buffer.
///
/// Checks `cancel` before and during chunk reads and returns an
/// [`io::ErrorKind::Interrupted`] error if cancelled. Computed digests are
/// returned in the exact order of `algos`.
///
/// # Errors
///
/// Returns an `io::Error` if reading fails or if `cancel` becomes `true`.
pub fn hash_reader_many<R: Read>(
    reader: &mut R,
    algos: &[HashAlgorithm],
    total_size: u64,
    progress: Option<&AtomicU64>,
    cancel: Option<&AtomicBool>,
    on_chunk: Option<&mut dyn FnMut(u64, u64)>,
) -> io::Result<MultiHashMetrics> {
    let mut engines: Vec<(HashAlgorithm, HasherEngine)> = algos
        .iter()
        .copied()
        .map(|algo| (algo, HasherEngine::new(algo)))
        .collect();

    let stats = stream_reader(reader, total_size, progress, cancel, on_chunk, |chunk| {
        for (_, engine) in &mut engines {
            engine.update(chunk);
        }
    })?;

    let digests = engines
        .into_iter()
        .map(|(algorithm, engine)| DigestEntry {
            algorithm,
            digest: engine.finalize(),
        })
        .collect();

    Ok(MultiHashMetrics {
        digests,
        bytes_processed: stats.bytes_processed,
        elapsed_ms: stats.elapsed_ms,
        throughput_mbps: stats.throughput_mbps,
    })
}

/// Computes the hash digest of a file on disk with optional progress and cancel handles.
///
/// # Errors
///
/// Returns an `io::Error` if opening, stating, or reading `path` fails, or if
/// `cancel` is set to `true` (`io::ErrorKind::Interrupted`).
pub fn hash_file_with_progress(
    path: &Path,
    algo: HashAlgorithm,
    progress: Option<&AtomicU64>,
    cancel: Option<&AtomicBool>,
    on_chunk: Option<&mut dyn FnMut(u64, u64)>,
) -> io::Result<HashMetrics> {
    let (mut file, total_size) = open_file_checked(path, cancel)?;
    hash_reader(&mut file, algo, total_size, progress, cancel, on_chunk)
}

/// Computes multiple hash digests of a file on disk in a single streaming read pass.
///
/// # Errors
///
/// Returns an `io::Error` if opening, stating, or reading `path` fails, or if
/// `cancel` is set to `true` (`io::ErrorKind::Interrupted`).
pub fn hash_file_many_with_progress(
    path: &Path,
    algos: &[HashAlgorithm],
    progress: Option<&AtomicU64>,
    cancel: Option<&AtomicBool>,
    on_chunk: Option<&mut dyn FnMut(u64, u64)>,
) -> io::Result<MultiHashMetrics> {
    let (mut file, total_size) = open_file_checked(path, cancel)?;
    hash_reader_many(&mut file, algos, total_size, progress, cancel, on_chunk)
}

/// Computes the lowercase hexadecimal digest of an in-memory byte slice.
#[must_use]
pub fn hash_bytes(data: &[u8], algo: HashAlgorithm) -> String {
    let mut engine = HasherEngine::new(algo);
    engine.update(data);
    engine.finalize()
}

#[cfg(test)]
mod tests {
    use std::io::{self, Cursor};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    use tempfile::NamedTempFile;

    use super::{
        DEFAULT_COMPUTE_ALGORITHM, HashAlgorithm, hash_bytes, hash_file_many_with_progress,
        hash_file_with_progress, hash_reader, hash_reader_many,
    };

    #[test]
    fn algorithm_metadata_and_lookup() {
        assert_eq!(HashAlgorithm::all().len(), 7);
        assert_eq!(HashAlgorithm::Crc32.as_str(), "CRC32");
        assert_eq!(HashAlgorithm::Md5.as_str(), "MD5");
        assert_eq!(HashAlgorithm::Sha1.as_str(), "SHA-1");
        assert_eq!(HashAlgorithm::Sha256.as_str(), "SHA-256");
        assert_eq!(HashAlgorithm::Sha384.as_str(), "SHA-384");
        assert_eq!(HashAlgorithm::Sha512.as_str(), "SHA-512");
        assert_eq!(HashAlgorithm::Blake3.as_str(), "BLAKE3");

        assert_eq!(HashAlgorithm::Crc32.expected_hex_len(), 8);
        assert_eq!(HashAlgorithm::Md5.expected_hex_len(), 32);
        assert_eq!(HashAlgorithm::Sha1.expected_hex_len(), 40);
        assert_eq!(HashAlgorithm::Sha256.expected_hex_len(), 64);
        assert_eq!(HashAlgorithm::Sha384.expected_hex_len(), 96);
        assert_eq!(HashAlgorithm::Sha512.expected_hex_len(), 128);
        assert_eq!(HashAlgorithm::Blake3.expected_hex_len(), 64);

        assert_eq!(HashAlgorithm::from_hex_len(8), Some(HashAlgorithm::Crc32));
        assert_eq!(HashAlgorithm::from_hex_len(32), Some(HashAlgorithm::Md5));
        assert_eq!(HashAlgorithm::from_hex_len(40), Some(HashAlgorithm::Sha1));
        assert_eq!(HashAlgorithm::from_hex_len(64), Some(HashAlgorithm::Sha256));
        assert_eq!(HashAlgorithm::from_hex_len(96), Some(HashAlgorithm::Sha384));
        assert_eq!(HashAlgorithm::from_hex_len(128), Some(HashAlgorithm::Sha512));
        assert_eq!(HashAlgorithm::from_hex_len(16), None);
    }

    #[test]
    fn test_vectors_empty_input() {
        assert_eq!(hash_bytes(b"", HashAlgorithm::Crc32), "00000000");
        assert_eq!(
            hash_bytes(b"", HashAlgorithm::Md5),
            "d41d8cd98f00b204e9800998ecf8427e"
        );
        assert_eq!(
            hash_bytes(b"", HashAlgorithm::Sha1),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
        assert_eq!(
            hash_bytes(b"", HashAlgorithm::Sha256),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hash_bytes(b"", HashAlgorithm::Sha384),
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );
        assert_eq!(
            hash_bytes(b"", HashAlgorithm::Sha512),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
        assert_eq!(
            hash_bytes(b"", HashAlgorithm::Blake3),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }

    #[test]
    fn test_vectors_abc_and_123456789() {
        assert_eq!(hash_bytes(b"abc", HashAlgorithm::Crc32), "352441c2");
        assert_eq!(
            hash_bytes(b"123456789", HashAlgorithm::Crc32),
            "cbf43926"
        );
        assert_eq!(
            hash_bytes(b"abc", HashAlgorithm::Md5),
            "900150983cd24fb0d6963f7d28e17f72"
        );
        assert_eq!(
            hash_bytes(b"abc", HashAlgorithm::Sha1),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hash_bytes(b"abc", HashAlgorithm::Sha256),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hash_bytes(b"abc", HashAlgorithm::Sha384),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
        );
        assert_eq!(
            hash_bytes(b"abc", HashAlgorithm::Sha512),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
        assert_eq!(
            hash_bytes(b"abc", HashAlgorithm::Blake3),
            "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
        );
    }

    #[test]
    fn test_vectors_nist_multi_block() {
        let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        assert_eq!(
            hash_bytes(msg, HashAlgorithm::Md5),
            "8215ef0796a20bcaaae116d3876c664a"
        );
        assert_eq!(
            hash_bytes(msg, HashAlgorithm::Sha1),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        assert_eq!(
            hash_bytes(msg, HashAlgorithm::Sha256),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        assert_eq!(
            hash_bytes(msg, HashAlgorithm::Sha384),
            "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b"
        );
        assert_eq!(
            hash_bytes(msg, HashAlgorithm::Sha512),
            "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445"
        );
    }

    #[test]
    fn file_hashing_reports_progress_and_supports_cancel() {
        use std::io::Write as _;

        let mut tmp = NamedTempFile::new().expect("temp file");
        let payload = vec![b'x'; 5 * 1024 * 1024];
        tmp.write_all(&payload).expect("write payload");
        tmp.flush().expect("flush payload");

        let progress = AtomicU64::new(0);
        let cancel = AtomicBool::new(false);
        let mut updates = Vec::new();
        let mut cb = |done: u64, total: u64| updates.push((done, total));

        let metrics = hash_file_with_progress(
            tmp.path(),
            HashAlgorithm::Sha256,
            Some(&progress),
            Some(&cancel),
            Some(&mut cb),
        )
        .expect("hash file");

        assert_eq!(metrics.bytes_processed, payload.len() as u64);
        assert_eq!(progress.load(Ordering::Relaxed), payload.len() as u64);
        assert_ne!(updates, [] as [(u64, u64); 0]);
        assert_eq!(
            updates.last().copied(),
            Some((payload.len() as u64, payload.len() as u64))
        );
        assert_eq!(metrics.digest, hash_bytes(&payload, HashAlgorithm::Sha256));
        assert!(metrics.throughput_mbps > 0.0);

        cancel.store(true, Ordering::Relaxed);
        let err = hash_file_with_progress(
            tmp.path(),
            HashAlgorithm::Sha256,
            None,
            Some(&cancel),
            None,
        )
        .expect_err("cancelled read should error");
        assert_eq!(err.kind(), std::io::ErrorKind::Interrupted);
    }

    #[test]
    fn empty_reader_triggers_callback_once() {
        let mut cursor = Cursor::new(Vec::<u8>::new());
        let mut calls = Vec::new();
        let mut cb = |done: u64, total: u64| calls.push((done, total));
        let metrics = hash_reader(
            &mut cursor,
            HashAlgorithm::Crc32,
            0,
            None,
            None,
            Some(&mut cb),
        )
        .expect("empty reader");
        assert_eq!(metrics.digest, "00000000");
        assert_eq!(calls, vec![(0, 0)]);
    }

    #[test]
    fn picker_order_matches_all_and_default_is_consistent() {
        let all = HashAlgorithm::all();
        let picker = HashAlgorithm::picker_order();

        assert_eq!(picker.len(), all.len());
        for &algo in all {
            assert_eq!(
                picker.iter().filter(|&&cand| cand == algo).count(),
                1,
                "picker_order must contain {algo:?} exactly once"
            );
        }
        for &algo in picker {
            assert_eq!(
                all.iter().filter(|&&cand| cand == algo).count(),
                1,
                "all must contain {algo:?} exactly once"
            );
        }

        assert_eq!(DEFAULT_COMPUTE_ALGORITHM, HashAlgorithm::Sha256);
        assert_eq!(
            HashAlgorithm::DEFAULT_COMPUTE_ALGORITHM,
            DEFAULT_COMPUTE_ALGORITHM
        );
        assert!(picker.contains(&DEFAULT_COMPUTE_ALGORITHM));
    }

    #[test]
    fn cli_name_and_from_alias_cover_all_variants() {
        assert_eq!(HashAlgorithm::Crc32.cli_name(), "crc32");
        assert_eq!(HashAlgorithm::Md5.cli_name(), "md5");
        assert_eq!(HashAlgorithm::Sha1.cli_name(), "sha1");
        assert_eq!(HashAlgorithm::Sha256.cli_name(), "sha256");
        assert_eq!(HashAlgorithm::Sha384.cli_name(), "sha384");
        assert_eq!(HashAlgorithm::Sha512.cli_name(), "sha512");
        assert_eq!(HashAlgorithm::Blake3.cli_name(), "blake3");

        let all = HashAlgorithm::all();
        for (idx, algo) in all.iter().enumerate() {
            for other in &all[idx + 1..] {
                assert_ne!(algo.cli_name(), other.cli_name());
            }
            assert_eq!(HashAlgorithm::from_alias(algo.cli_name()), Some(*algo));
            assert_eq!(HashAlgorithm::from_alias(algo.as_str()), Some(*algo));
            assert_eq!(
                HashAlgorithm::from_alias(&algo.cli_name().to_ascii_uppercase()),
                Some(*algo)
            );
            assert_eq!(
                HashAlgorithm::from_alias(&format!("  {}  ", algo.as_str().to_ascii_lowercase())),
                Some(*algo)
            );
            assert_eq!(
                HashAlgorithm::from_alias(&algo.as_str().replace('-', "_")),
                Some(*algo)
            );
        }

        assert_eq!(
            HashAlgorithm::from_alias("crc-32"),
            Some(HashAlgorithm::Crc32)
        );
        assert_eq!(HashAlgorithm::from_alias("MD_5"), Some(HashAlgorithm::Md5));
        assert_eq!(
            HashAlgorithm::from_alias("sha_1"),
            Some(HashAlgorithm::Sha1)
        );
        assert_eq!(
            HashAlgorithm::from_alias("sha-256"),
            Some(HashAlgorithm::Sha256)
        );
        assert_eq!(
            HashAlgorithm::from_alias("SHA_384"),
            Some(HashAlgorithm::Sha384)
        );
        assert_eq!(
            HashAlgorithm::from_alias("sha_512"),
            Some(HashAlgorithm::Sha512)
        );
        assert_eq!(
            HashAlgorithm::from_alias("blake-3"),
            Some(HashAlgorithm::Blake3)
        );

        for invalid in ["", "   ", "---", "___", "sha", "sha2", "sha 256", "sha256é", "unknown"] {
            assert_eq!(HashAlgorithm::from_alias(invalid), None);
        }
    }

    #[test]
    fn hash_reader_many_handles_all_subset_empty_and_midstream_cancel() {
        struct CancelAfterFirstRead<'a> {
            remaining_chunks: usize,
            cancel: &'a AtomicBool,
        }

        impl io::Read for CancelAfterFirstRead<'_> {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if self.remaining_chunks == 0 {
                    return Ok(0);
                }
                self.remaining_chunks -= 1;
                let count = buf.len().min(64);
                buf[..count].fill(b'a');
                self.cancel.store(true, Ordering::Relaxed);
                Ok(count)
            }
        }

        let algos = HashAlgorithm::picker_order();

        let mut empty_cursor = Cursor::new(Vec::<u8>::new());
        let mut empty_calls = Vec::new();
        let mut empty_cb = |done: u64, total: u64| empty_calls.push((done, total));
        let empty_metrics =
            hash_reader_many(&mut empty_cursor, algos, 0, None, None, Some(&mut empty_cb))
                .expect("empty multi reader");
        assert_eq!(empty_calls, vec![(0, 0)]);
        assert_eq!(empty_metrics.bytes_processed, 0);
        assert_eq!(empty_metrics.digests.len(), algos.len());
        for (entry, &expected_algo) in empty_metrics.digests.iter().zip(algos) {
            assert_eq!(entry.algorithm, expected_algo);
            assert_eq!(entry.digest, hash_bytes(b"", expected_algo));
        }

        let payload = b"abc";
        let subset = [HashAlgorithm::Blake3, HashAlgorithm::Crc32];
        let mut sub_cursor = Cursor::new(payload);
        let sub_metrics =
            hash_reader_many(&mut sub_cursor, &subset, payload.len() as u64, None, None, None)
                .expect("subset multi reader");
        assert_eq!(sub_metrics.bytes_processed, 3);
        assert_eq!(sub_metrics.digests.len(), 2);
        assert_eq!(sub_metrics.digests[0].algorithm, HashAlgorithm::Blake3);
        assert_eq!(
            sub_metrics.digests[0].digest,
            hash_bytes(payload, HashAlgorithm::Blake3)
        );
        assert_eq!(sub_metrics.digests[1].algorithm, HashAlgorithm::Crc32);
        assert_eq!(
            sub_metrics.digests[1].digest,
            hash_bytes(payload, HashAlgorithm::Crc32)
        );

        let mut none_cursor = Cursor::new(payload);
        let none_metrics = hash_reader_many(&mut none_cursor, &[], 3, None, None, None)
            .expect("empty algo slice");
        assert!(none_metrics.digests.is_empty());
        assert_eq!(none_metrics.bytes_processed, 3);

        let cancel = AtomicBool::new(false);
        let mut reader = CancelAfterFirstRead {
            remaining_chunks: 3,
            cancel: &cancel,
        };
        let err = hash_reader_many(&mut reader, algos, 192, None, Some(&cancel), None)
            .expect_err("mid-stream cancel should error");
        assert_eq!(err.kind(), io::ErrorKind::Interrupted);
    }

    #[test]
    fn file_hashing_many_single_pass_matches_individual_and_cancels() {
        use std::io::Write as _;

        let mut tmp = NamedTempFile::new().expect("temp file");
        let payload = vec![b'y'; 5 * 1024 * 1024];
        tmp.write_all(&payload).expect("write payload");
        tmp.flush().expect("flush payload");

        let algos = HashAlgorithm::picker_order();
        let progress = AtomicU64::new(0);
        let cancel = AtomicBool::new(false);
        let mut updates = Vec::new();
        let mut cb = |done: u64, total: u64| updates.push((done, total));

        let metrics = hash_file_many_with_progress(
            tmp.path(),
            algos,
            Some(&progress),
            Some(&cancel),
            Some(&mut cb),
        )
        .expect("hash file many");

        assert_eq!(metrics.bytes_processed, payload.len() as u64);
        assert_eq!(progress.load(Ordering::Relaxed), payload.len() as u64);
        assert_ne!(updates, [] as [(u64, u64); 0]);
        assert_eq!(
            updates.last().copied(),
            Some((payload.len() as u64, payload.len() as u64))
        );
        assert!(metrics.throughput_mbps > 0.0);
        assert_eq!(metrics.digests.len(), algos.len());

        for (entry, &expected_algo) in metrics.digests.iter().zip(algos) {
            assert_eq!(entry.algorithm, expected_algo);
            assert_eq!(entry.digest, hash_bytes(&payload, expected_algo));
        }

        cancel.store(true, Ordering::Relaxed);
        let err = hash_file_many_with_progress(tmp.path(), algos, None, Some(&cancel), None)
            .expect_err("cancelled multi-hash should error");
        assert_eq!(err.kind(), io::ErrorKind::Interrupted);
    }
}
