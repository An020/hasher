//! Digest normalization, algorithm detection, and checksum file parsing.

use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use crate::algo::HashAlgorithm;

/// Maximum permitted size for text hash/manifest files (1 MiB).
pub const MAX_HASH_FILE_BYTES: u64 = 1024 * 1024;

/// Errors produced when parsing a digest string or checksum file.
#[derive(Debug, thiserror::Error)]
pub enum DigestError {
    /// Input contains non-hexadecimal characters.
    #[error("invalid hexadecimal character in digest")]
    InvalidHex,
    /// Hexadecimal digest length does not match the expected algorithm length.
    #[error("invalid digest length: {0} hex characters")]
    InvalidLength(usize),
    /// Candidate hash file exceeds the 1 MiB safety limit.
    #[error("hash file is too large ({0} bytes; max {MAX_HASH_FILE_BYTES} bytes)")]
    FileTooLarge(u64),
    /// Underlying filesystem or UTF-8 decoding error.
    #[error("I/O error reading digest: {0}")]
    Io(#[from] io::Error),
    /// No valid digest was found in the hash file or input.
    #[error("no valid digest found in hash file")]
    NoDigestFound,
    /// Multiple digests exist and none uniquely identifies the target file.
    #[error("hash file contains multiple digests and none uniquely matches target file")]
    AmbiguousHashFile,
}

/// Validated, normalized lowercase digest paired with its resolved algorithm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedDigest {
    /// Lowercase ASCII hexadecimal digest string.
    pub hex: String,
    /// Algorithm associated with this digest.
    pub algorithm: HashAlgorithm,
    /// `true` when the algorithm came from an explicit prefix/tag in the input
    /// and `override_algo` was `None`.
    pub explicit_algo: bool,
}

/// Strips outer whitespace and matching surrounding `"` or `'` quotes.
fn trim_quotes_and_ws(mut s: &str) -> &str {
    loop {
        let trimmed = s.trim().trim_start_matches('\u{FEFF}').trim();
        let unquoted = if trimmed.len() >= 2
            && ((trimmed.starts_with('"') && trimmed.ends_with('"'))
                || (trimmed.starts_with('\'') && trimmed.ends_with('\'')))
        {
            &trimmed[1..trimmed.len() - 1]
        } else {
            return trimmed;
        };
        s = unquoted;
    }
}

/// Parses a recognized algorithm label (case-insensitive, optional hyphens).
fn parse_algo_name(label: &str) -> Option<HashAlgorithm> {
    let normalized = label.trim();
    if normalized.eq_ignore_ascii_case("crc32") || normalized.eq_ignore_ascii_case("crc-32") {
        Some(HashAlgorithm::Crc32)
    } else if normalized.eq_ignore_ascii_case("md5") || normalized.eq_ignore_ascii_case("md-5") {
        Some(HashAlgorithm::Md5)
    } else if normalized.eq_ignore_ascii_case("sha1") || normalized.eq_ignore_ascii_case("sha-1") {
        Some(HashAlgorithm::Sha1)
    } else if normalized.eq_ignore_ascii_case("sha256")
        || normalized.eq_ignore_ascii_case("sha-256")
    {
        Some(HashAlgorithm::Sha256)
    } else if normalized.eq_ignore_ascii_case("sha384")
        || normalized.eq_ignore_ascii_case("sha-384")
    {
        Some(HashAlgorithm::Sha384)
    } else if normalized.eq_ignore_ascii_case("sha512")
        || normalized.eq_ignore_ascii_case("sha-512")
    {
        Some(HashAlgorithm::Sha512)
    } else if normalized.eq_ignore_ascii_case("blake3")
        || normalized.eq_ignore_ascii_case("blake-3")
    {
        Some(HashAlgorithm::Blake3)
    } else {
        None
    }
}

/// Splits a `Key : Value` line such as PowerShell `Format-List` output.
fn split_kv_colon(line: &str) -> Option<(&str, &str)> {
    let (key, value) = line.split_once(':')?;
    Some((key.trim(), value.trim()))
}

/// Validates and finalizes a candidate hex token and optional detected algorithm.
fn finalize_digest(
    raw_hex: &str,
    detected_algo: Option<HashAlgorithm>,
    override_algo: Option<HashAlgorithm>,
) -> Result<ParsedDigest, DigestError> {
    let hex_token = trim_quotes_and_ws(raw_hex);
    if hex_token.is_empty() {
        return Err(DigestError::InvalidLength(0));
    }
    if !hex_token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(DigestError::InvalidHex);
    }

    let hex = hex_token.to_ascii_lowercase();
    let mut explicit_algo = false;

    let algorithm = if let Some(algo) = override_algo {
        algo
    } else if let Some(algo) = detected_algo {
        explicit_algo = true;
        algo
    } else {
        HashAlgorithm::from_hex_len(hex.len()).ok_or(DigestError::InvalidLength(hex.len()))?
    };

    if hex.len() != algorithm.expected_hex_len() {
        return Err(DigestError::InvalidLength(hex.len()));
    }

    Ok(ParsedDigest {
        hex,
        algorithm,
        explicit_algo,
    })
}

/// Cleans an extracted filename token from a checksum line.
fn clean_filename_token(raw: &str) -> Option<String> {
    let cleaned = trim_quotes_and_ws(raw);
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned.to_string())
    }
}

/// Parses a single checksum line or digest string into an optional filename and `ParsedDigest`.
fn parse_digest_entry(
    input: &str,
    override_algo: Option<HashAlgorithm>,
) -> Result<(Option<String>, ParsedDigest), DigestError> {
    let s = trim_quotes_and_ws(input);
    if s.is_empty() {
        return Err(DigestError::InvalidLength(0));
    }

    // 1. OpenSSL / BSD tag style: `SHA256 (filename) = <hex>`
    if let Some((left, right)) = s.rsplit_once('=') {
        let left_trimmed = left.trim();
        if let Some((algo_part, rest)) = left_trimmed.split_once('(') {
            if let Some(filename_inner) = rest.strip_suffix(')') {
                if let Some(algo) = parse_algo_name(algo_part) {
                    let parsed = finalize_digest(right, Some(algo), override_algo)?;
                    return Ok((clean_filename_token(filename_inner), parsed));
                }
            }
        }
    }

    // 2. PowerShell single-line `Hash : <hex>`
    if let Some((key, val)) = split_kv_colon(s) {
        if key.eq_ignore_ascii_case("hash") {
            let parsed = finalize_digest(val, None, override_algo)?;
            return Ok((None, parsed));
        }
        // 3. Explicit colon prefix: `sha256:<hex>`, `blake3:<hex>`, etc.
        if let Some(algo) = parse_algo_name(key) {
            let (hex_part, name_part) = split_hex_and_filename(val);
            let parsed = finalize_digest(hex_part, Some(algo), override_algo)?;
            return Ok((name_part, parsed));
        }
    }

    // 4. Space-separated algorithm prefix (e.g. PowerShell table row `SHA256 <hex> [path]`)
    if let Some((first, rest)) = split_first_ws(s) {
        if let Some(algo) = parse_algo_name(first) {
            let (hex_part, name_part) = split_hex_and_filename(rest.trim_start());
            let parsed = finalize_digest(hex_part, Some(algo), override_algo)?;
            return Ok((name_part, parsed));
        }
    }

    // 5. GNU style (`<hex>  filename` or `<hex> *filename`) or bare `<hex>`
    if let Some((first, rest)) = split_first_ws(s) {
        let has_gnu_sep = rest.starts_with(' ') || rest.starts_with('\t') || rest.starts_with('*');
        let rest_trimmed = rest.trim_start();
        let filename_raw = rest_trimmed.strip_prefix('*').unwrap_or(rest_trimmed);
        let looks_like_spaced_hex = !has_gnu_sep
            && rest_trimmed
                .split_whitespace()
                .all(|tok| !tok.is_empty() && tok.bytes().all(|b| b.is_ascii_hexdigit()));
        if looks_like_spaced_hex {
            return Err(DigestError::InvalidHex);
        }
        let parsed = finalize_digest(first, None, override_algo)?;
        return Ok((clean_filename_token(filename_raw), parsed));
    }

    let parsed = finalize_digest(s, None, override_algo)?;
    Ok((None, parsed))
}

fn split_first_ws(s: &str) -> Option<(&str, &str)> {
    let idx = s.find(char::is_whitespace)?;
    let (head, tail) = s.split_at(idx);
    let mut chars = tail.char_indices();
    let (_, ws_ch) = chars.next()?;
    let after_first_ws = &tail[ws_ch.len_utf8()..];
    Some((head, after_first_ws))
}

fn split_hex_and_filename(s: &str) -> (&str, Option<String>) {
    if let Some((head, tail)) = split_first_ws(s) {
        let rest = tail.trim_start();
        let filename_raw = rest.strip_prefix('*').unwrap_or(rest);
        (head, clean_filename_token(filename_raw))
    } else {
        (s, None)
    }
}

/// Parses a pasted multi-line PowerShell `Format-List` block when `Hash :` is present.
fn try_parse_powershell_block(
    input: &str,
    override_algo: Option<HashAlgorithm>,
) -> Option<Result<ParsedDigest, DigestError>> {
    let mut detected_algo = None;
    let mut hash_val = None;

    for raw_line in input.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = split_kv_colon(line) {
            if k.eq_ignore_ascii_case("algorithm") {
                detected_algo = parse_algo_name(v);
            } else if k.eq_ignore_ascii_case("hash") {
                hash_val = Some(v);
            }
        }
    }

    hash_val.map(|hex| finalize_digest(hex, detected_algo, override_algo))
}

/// Normalizes and validates a digest string or pasted checksum line.
///
/// Accepts raw hex, quoted values, `sha256:`-style prefixes, OpenSSL tag lines
/// (`SHA256 (file) = <hex>`), PowerShell `Get-FileHash` output, and GNU checksum lines.
///
/// # Errors
///
/// Returns [`DigestError::InvalidHex`] if non-hexadecimal characters remain, or
/// [`DigestError::InvalidLength`] if the hex length does not match the target algorithm.
pub fn parse_digest_str(
    input: &str,
    override_algo: Option<HashAlgorithm>,
) -> Result<ParsedDigest, DigestError> {
    let cleaned = trim_quotes_and_ws(input);
    if cleaned.is_empty() {
        return Err(DigestError::InvalidLength(0));
    }

    if cleaned.contains('\n') || cleaned.contains('\r') {
        if let Some(res) = try_parse_powershell_block(cleaned, override_algo) {
            return res;
        }
    }

    let (_, parsed) = parse_digest_entry(cleaned, override_algo)?;
    Ok(parsed)
}

/// Reads up to [`MAX_HASH_FILE_BYTES`] from a checksum text file and decodes it to UTF-8.
fn read_capped_text(path: &Path) -> Result<String, DigestError> {
    let meta = std::fs::metadata(path)?;
    if meta.len() > MAX_HASH_FILE_BYTES {
        return Err(DigestError::FileTooLarge(meta.len()));
    }

    let file = File::open(path)?;
    let mut bytes = Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(4096));
    file.take(MAX_HASH_FILE_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_HASH_FILE_BYTES {
        return Err(DigestError::FileTooLarge(bytes.len() as u64));
    }

    // Handle UTF-16 LE BOM written by Windows PowerShell 5.1 `Out-File` / `>`.
    if bytes.starts_with(&[0xFF, 0xFE]) {
        let rest = &bytes[2..];
        if rest.len() % 2 != 0 {
            return Err(DigestError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid UTF-16 LE byte length",
            )));
        }
        let units: Vec<u16> = rest
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        let text = String::from_utf16(&units)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        return Ok(text.trim_start_matches('\u{FEFF}').to_string());
    }

    let text =
        String::from_utf8(bytes).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    Ok(text.strip_prefix('\u{FEFF}').unwrap_or(&text).to_string())
}

/// Extracts `(Option<filename_token>, ParsedDigest)` entries from checksum file text.
fn extract_entries_from_text(
    text: &str,
    override_algo: Option<HashAlgorithm>,
) -> Vec<(Option<String>, ParsedDigest)> {
    let mut entries = Vec::new();
    let mut ps_algo: Option<HashAlgorithm> = None;
    let mut ps_hash: Option<&str> = None;
    let mut ps_path: Option<String> = None;

    let flush_ps = |algo: &mut Option<HashAlgorithm>,
                    hash: &mut Option<&str>,
                    path: &mut Option<String>,
                    out: &mut Vec<(Option<String>, ParsedDigest)>| {
        if let Some(hex_str) = hash.take() {
            if let Ok(parsed) = finalize_digest(hex_str, algo.take(), override_algo) {
                out.push((path.take(), parsed));
            }
        }
        *algo = None;
        *path = None;
    };

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            flush_ps(&mut ps_algo, &mut ps_hash, &mut ps_path, &mut entries);
            continue;
        }
        if line.starts_with('#') {
            continue;
        }

        if let Some((k, v)) = split_kv_colon(line) {
            if k.eq_ignore_ascii_case("algorithm") {
                flush_ps(&mut ps_algo, &mut ps_hash, &mut ps_path, &mut entries);
                ps_algo = parse_algo_name(v);
                continue;
            }
            if k.eq_ignore_ascii_case("hash") {
                if ps_hash.is_some() {
                    flush_ps(&mut ps_algo, &mut ps_hash, &mut ps_path, &mut entries);
                }
                ps_hash = Some(v);
                continue;
            }
            if k.eq_ignore_ascii_case("path") {
                ps_path = clean_filename_token(v);
                flush_ps(&mut ps_algo, &mut ps_hash, &mut ps_path, &mut entries);
                continue;
            }
        }

        if ps_hash.is_some() {
            flush_ps(&mut ps_algo, &mut ps_hash, &mut ps_path, &mut entries);
        }

        if let Ok(entry) = parse_digest_entry(line, override_algo) {
            entries.push(entry);
        }
    }

    flush_ps(&mut ps_algo, &mut ps_hash, &mut ps_path, &mut entries);
    entries
}

fn token_basename(token: &str) -> &str {
    token.rsplit(['/', '\\']).next().unwrap_or(token)
}

fn basenames_match(entry_name: &str, target_basename: &str) -> bool {
    let entry_base = token_basename(entry_name);
    if cfg!(windows) {
        entry_base.to_lowercase() == target_basename.to_lowercase()
    } else {
        entry_base == target_basename
    }
}

pub(crate) fn file_mentions_target(
    hash_file: &Path,
    target_file: &Path,
    override_algo: Option<HashAlgorithm>,
) -> bool {
    let Some(target_base) = target_file.file_name().and_then(std::ffi::OsStr::to_str) else {
        return false;
    };
    let Ok(text) = read_capped_text(hash_file) else {
        return false;
    };
    extract_entries_from_text(&text, override_algo)
        .into_iter()
        .any(|(name_opt, _)| {
            name_opt
                .as_deref()
                .is_some_and(|name| basenames_match(name, target_base))
        })
}

/// Extracts a single expected digest from a `.txt` or checksum file.
///
/// Enforces a 1 MiB file size guard before reading. When `target_file` is provided,
/// attempts a basename match first (case-insensitive on Windows), falling back to a
/// single unambiguous entry when the file contains exactly one valid digest.
///
/// # Errors
///
/// Returns [`DigestError::FileTooLarge`] if the file exceeds 1 MiB,
/// [`DigestError::NoDigestFound`] if no valid digest exists,
/// [`DigestError::AmbiguousHashFile`] if multiple digests exist without a unique target match,
/// or [`DigestError::Io`] on filesystem / UTF-8 decode failure.
pub fn parse_digest_from_file(
    hash_file: &Path,
    target_file: Option<&Path>,
    override_algo: Option<HashAlgorithm>,
) -> Result<ParsedDigest, DigestError> {
    let text = read_capped_text(hash_file)?;
    let entries = extract_entries_from_text(&text, override_algo);
    if entries.is_empty() {
        return Err(DigestError::NoDigestFound);
    }

    if let Some(target_basename) = target_file
        .and_then(Path::file_name)
        .and_then(std::ffi::OsStr::to_str)
    {
        let mut matched: Vec<ParsedDigest> = entries
            .iter()
            .filter_map(|(name_opt, digest)| {
                name_opt
                    .as_deref()
                    .filter(|name| basenames_match(name, target_basename))
                    .map(|_| digest.clone())
            })
            .collect();

        if matched.len() == 1 {
            if let Some(only) = matched.pop() {
                return Ok(only);
            }
        }
        if matched.len() > 1 {
            return Err(DigestError::AmbiguousHashFile);
        }
    }

    if entries.len() == 1 {
        if let Some((_, only)) = entries.into_iter().next() {
            return Ok(only);
        }
    }

    Err(DigestError::AmbiguousHashFile)
}

/// Parses every `(PathBuf, ParsedDigest)` entry in a GNU or OpenSSL checksum manifest.
///
/// Enforces the 1 MiB size guard before reading, skips blank lines and `#` comments,
/// and requires each entry line to supply both a file path and a valid digest.
///
/// # Errors
///
/// Returns [`DigestError::FileTooLarge`] if the file exceeds 1 MiB,
/// [`DigestError::NoDigestFound`] if the manifest contains no entries or an entry lacks a path,
/// [`DigestError::InvalidHex`] or [`DigestError::InvalidLength`] on malformed digests,
/// or [`DigestError::Io`] on filesystem / UTF-8 decode failure.
pub fn parse_checksum_manifest(
    manifest_path: &Path,
    override_algo: Option<HashAlgorithm>,
) -> Result<Vec<(PathBuf, ParsedDigest)>, DigestError> {
    let text = read_capped_text(manifest_path)?;
    let mut entries = Vec::new();

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name_opt, parsed) = parse_digest_entry(line, override_algo)?;
        let Some(path_str) = name_opt else {
            return Err(DigestError::NoDigestFound);
        };
        entries.push((PathBuf::from(path_str), parsed));
    }

    if entries.is_empty() {
        return Err(DigestError::NoDigestFound);
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::path::{Path, PathBuf};

    use tempfile::NamedTempFile;

    use super::{
        DigestError, MAX_HASH_FILE_BYTES, parse_checksum_manifest, parse_digest_from_file,
        parse_digest_str,
    };
    use crate::algo::HashAlgorithm;

    const SHA256_EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const SHA256_ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    #[test]
    fn normalize_quotes_case_whitespace_and_prefixes() {
        let upper_quoted = format!("  \"  {}  \"  ", SHA256_EMPTY.to_ascii_uppercase());
        let parsed = parse_digest_str(&upper_quoted, None).expect("upper quoted");
        assert_eq!(parsed.hex, SHA256_EMPTY);
        assert_eq!(parsed.algorithm, HashAlgorithm::Sha256);
        assert!(!parsed.explicit_algo);

        let b3 = format!("'BLAKE3: {}'", SHA256_ABC.to_ascii_uppercase());
        let parsed_b3 = parse_digest_str(&b3, None).expect("blake3 prefix");
        assert_eq!(parsed_b3.hex, SHA256_ABC);
        assert_eq!(parsed_b3.algorithm, HashAlgorithm::Blake3);
        assert!(parsed_b3.explicit_algo);

        let sha_hyphen = format!("sha-256:{SHA256_EMPTY}");
        let parsed_hyphen = parse_digest_str(&sha_hyphen, None).expect("sha-256 prefix");
        assert_eq!(parsed_hyphen.algorithm, HashAlgorithm::Sha256);
        assert!(parsed_hyphen.explicit_algo);

        let override_res =
            parse_digest_str(&format!("sha256:{SHA256_EMPTY}"), Some(HashAlgorithm::Blake3))
                .expect("override algo");
        assert_eq!(override_res.algorithm, HashAlgorithm::Blake3);
        assert!(!override_res.explicit_algo);
    }

    #[test]
    fn parse_all_supported_prefixes_and_formats() {
        let crc = parse_digest_str("crc32:CBF43926", None).expect("crc32");
        assert_eq!(crc.algorithm, HashAlgorithm::Crc32);
        assert_eq!(crc.hex, "cbf43926");
        assert!(crc.explicit_algo);

        let md5 = parse_digest_str("MD5:900150983cd24fb0d6963f7d28e17f72", None).expect("md5");
        assert_eq!(md5.algorithm, HashAlgorithm::Md5);
        assert!(md5.explicit_algo);

        let sha1 = parse_digest_str("sha-1:a9993e364706816aba3e25717850c26c9cd0d89d", None)
            .expect("sha1");
        assert_eq!(sha1.algorithm, HashAlgorithm::Sha1);
        assert!(sha1.explicit_algo);

        let openssl =
            parse_digest_str(&format!("SHA256 (ubuntu (amd64).iso) = {SHA256_EMPTY}"), None)
                .expect("openssl");
        assert_eq!(openssl.algorithm, HashAlgorithm::Sha256);
        assert_eq!(openssl.hex, SHA256_EMPTY);
        assert!(openssl.explicit_algo);

        let gnu_text = parse_digest_str(&format!("{SHA256_ABC}  test file.bin"), None).expect("gnu");
        assert_eq!(gnu_text.hex, SHA256_ABC);
        assert!(!gnu_text.explicit_algo);

        let gnu_bin = parse_digest_str(&format!("{SHA256_ABC} *test.bin"), None).expect("gnu bin");
        assert_eq!(gnu_bin.hex, SHA256_ABC);

        let ps_block = format!(
            "Algorithm : SHA256\nHash      : {}\nPath      : C:\\tmp\\file.iso\n",
            SHA256_ABC.to_ascii_uppercase()
        );
        let ps = parse_digest_str(&ps_block, None).expect("powershell block");
        assert_eq!(ps.algorithm, HashAlgorithm::Sha256);
        assert_eq!(ps.hex, SHA256_ABC);
        assert!(ps.explicit_algo);

        let ps_single = parse_digest_str(&format!("Hash : {SHA256_EMPTY}"), None).expect("ps single");
        assert_eq!(ps_single.hex, SHA256_EMPTY);
    }

    #[test]
    fn parse_digest_str_rejects_invalid_inputs() {
        assert!(matches!(
            parse_digest_str("", None),
            Err(DigestError::InvalidLength(0))
        ));
        assert!(matches!(
            parse_digest_str("not_hex_data", None),
            Err(DigestError::InvalidHex)
        ));
        assert!(matches!(
            parse_digest_str("abcd1234 eeff0011", None),
            Err(DigestError::InvalidHex)
        ));
        assert!(matches!(
            parse_digest_str("abcd", None),
            Err(DigestError::InvalidLength(4))
        ));
        assert!(matches!(
            parse_digest_str("cbf43926", Some(HashAlgorithm::Sha256)),
            Err(DigestError::InvalidLength(8))
        ));
    }

    #[test]
    fn parse_digest_from_file_handles_bom_matching_and_ambiguity() {
        let mut tmp = NamedTempFile::new().expect("temp file");
        writeln!(tmp, "\u{FEFF}# SHA-256 sums").expect("write");
        writeln!(tmp).expect("write");
        writeln!(tmp, "{SHA256_EMPTY}  empty.bin").expect("write");
        writeln!(tmp, "{SHA256_ABC} *dir/Release.ISO").expect("write");
        tmp.flush().expect("flush");

        let matched = parse_digest_from_file(
            tmp.path(),
            Some(Path::new("C:\\Downloads\\release.iso")),
            None,
        )
        .expect("basename match");
        assert_eq!(matched.hex, SHA256_ABC);

        let ambiguous =
            parse_digest_from_file(tmp.path(), Some(Path::new("other.zip")), None)
                .expect_err("multiple unmatched should error");
        assert!(matches!(ambiguous, DigestError::AmbiguousHashFile));
    }

    #[test]
    fn parse_digest_from_file_single_fallback_and_empty() {
        let mut single = NamedTempFile::new().expect("temp file");
        writeln!(single, "# only one entry").expect("write");
        writeln!(single, "{SHA256_ABC}  original-name.zip").expect("write");
        single.flush().expect("flush");

        let fallback = parse_digest_from_file(
            single.path(),
            Some(Path::new("renamed-download.zip")),
            None,
        )
        .expect("single digest fallback");
        assert_eq!(fallback.hex, SHA256_ABC);

        let mut empty = NamedTempFile::new().expect("temp file");
        writeln!(empty, "# comments only").expect("write");
        empty.flush().expect("flush");
        let err = parse_digest_from_file(empty.path(), None, None).expect_err("empty file");
        assert!(matches!(err, DigestError::NoDigestFound));
    }

    #[test]
    fn parse_digest_from_file_enforces_1_mib_limit() {
        let mut large = NamedTempFile::new().expect("temp file");
        let oversized = vec![b'a'; usize::try_from(MAX_HASH_FILE_BYTES).expect("usize") + 1];
        large.write_all(&oversized).expect("write oversized");
        large.flush().expect("flush");

        let err = parse_digest_from_file(large.path(), None, None).expect_err("file too large");
        assert!(matches!(
            err,
            DigestError::FileTooLarge(len) if len == MAX_HASH_FILE_BYTES + 1
        ));
    }

    #[test]
    fn parse_checksum_manifest_reads_gnu_and_openssl_lines() {
        let mut manifest = NamedTempFile::new().expect("temp file");
        writeln!(manifest, "# Manifest").expect("write");
        writeln!(manifest, "{SHA256_EMPTY}  sub/empty.bin").expect("write");
        writeln!(manifest, "{SHA256_ABC} *abc.txt").expect("write");
        writeln!(manifest, "BLAKE3 (data.bin) = {SHA256_ABC}").expect("write");
        manifest.flush().expect("flush");

        let entries = parse_checksum_manifest(manifest.path(), None).expect("manifest");
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].0, PathBuf::from("sub/empty.bin"));
        assert_eq!(entries[0].1.algorithm, HashAlgorithm::Sha256);
        assert_eq!(entries[1].0, PathBuf::from("abc.txt"));
        assert_eq!(entries[2].0, PathBuf::from("data.bin"));
        assert_eq!(entries[2].1.algorithm, HashAlgorithm::Blake3);
    }
}
