use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use hasher::algo::{hash_bytes, HashAlgorithm, DEFAULT_COMPUTE_ALGORITHM};
use serde_json::Value;
use tempfile::TempDir;

const SHA256_EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const SHA256_ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const BLAKE3_ABC: &str = "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85";
const WRONG_SHA256: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn run_hashcheck(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_hashcheck"))
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("execute hashcheck binary")
}

fn run_hashcheck_with_stdin(args: &[&str], stdin_bytes: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_hashcheck"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn hashcheck binary");

    {
        let mut stdin = child.stdin.take().expect("open piped stdin");
        stdin
            .write_all(stdin_bytes)
            .expect("write stdin to hashcheck");
    }

    child.wait_with_output().expect("wait for hashcheck output")
}

fn stdout_str(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr_str(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn path_arg(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[test]
fn matching_hash_formats_and_hash_file_exit_0() {
    let dir = TempDir::new().expect("create tempdir");
    let target = dir.path().join("sample.bin");
    std::fs::write(&target, b"abc").expect("write target");
    let target_str = path_arg(&target);

    let upper = SHA256_ABC.to_ascii_uppercase();
    let prefixed = format!("sha256:{SHA256_ABC}");
    for expected in [SHA256_ABC, upper.as_str(), prefixed.as_str()] {
        let out = run_hashcheck(&[expected, &target_str]);
        assert_eq!(
            out.status.code(),
            Some(0),
            "expected exit 0 for '{expected}', stderr: {}",
            stderr_str(&out)
        );
        let text = stdout_str(&out);
        assert!(
            text.contains("IDENTICAL"),
            "missing IDENTICAL in stdout for '{expected}': {text}"
        );
    }

    let hash_file = dir.path().join("checksum.txt");
    std::fs::write(&hash_file, format!("{SHA256_ABC}  sample.bin\n")).expect("write hash file");
    let hash_file_str = path_arg(&hash_file);

    let out_file = run_hashcheck(&[&hash_file_str, &target_str]);
    assert_eq!(
        out_file.status.code(),
        Some(0),
        "expected exit 0 for .txt hash file, stderr: {}",
        stderr_str(&out_file)
    );
    assert!(stdout_str(&out_file).contains("IDENTICAL"));
}

#[test]
fn smart_argument_swap_file_then_hash_or_hash_file() {
    let dir = TempDir::new().expect("create tempdir");
    let target = dir.path().join("payload.bin");
    std::fs::write(&target, b"abc").expect("write payload");
    let target_str = path_arg(&target);

    let hash_file = dir.path().join("hashes.txt");
    std::fs::write(&hash_file, format!("{SHA256_ABC}  payload.bin\n")).expect("write hashes.txt");
    let hash_file_str = path_arg(&hash_file);

    let swapped_raw = run_hashcheck(&[&target_str, SHA256_ABC]);
    assert_eq!(swapped_raw.status.code(), Some(0));
    assert!(stdout_str(&swapped_raw).contains("IDENTICAL"));

    let swapped_file = run_hashcheck(&[&target_str, &hash_file_str]);
    assert_eq!(
        swapped_file.status.code(),
        Some(0),
        "stderr: {}",
        stderr_str(&swapped_file)
    );
    assert!(stdout_str(&swapped_file).contains("IDENTICAL"));
}

#[test]
fn mismatch_exits_1_with_cautious_banner() {
    let dir = TempDir::new().expect("create tempdir");
    let target = dir.path().join("sample.bin");
    std::fs::write(&target, b"abc").expect("write target");
    let target_str = path_arg(&target);

    let out = run_hashcheck(&[WRONG_SHA256, &target_str]);
    assert_eq!(out.status.code(), Some(1));
    let text = stdout_str(&out);
    assert!(
        text.contains("NOT IDENTICAL. BE CAUTIOUS."),
        "unexpected mismatch output: {text}"
    );
}

#[test]
fn missing_file_invalid_digest_and_ambiguous_txt_exit_2() {
    let dir = TempDir::new().expect("create tempdir");
    let target = dir.path().join("sample.bin");
    std::fs::write(&target, b"abc").expect("write target");
    let target_str = path_arg(&target);

    let missing = dir.path().join("does-not-exist.bin");
    let missing_str = path_arg(&missing);
    let out_missing = run_hashcheck(&[SHA256_ABC, &missing_str]);
    assert_eq!(out_missing.status.code(), Some(2));

    let out_invalid = run_hashcheck(&["not_a_valid_digest", &target_str]);
    assert_eq!(out_invalid.status.code(), Some(2));

    let ambiguous = dir.path().join("ambiguous.txt");
    std::fs::write(
        &ambiguous,
        format!("{SHA256_EMPTY}  alpha.bin\n{SHA256_ABC}  beta.bin\n"),
    )
    .expect("write ambiguous.txt");
    let ambiguous_str = path_arg(&ambiguous);

    let out_ambiguous = run_hashcheck(&[&ambiguous_str, &target_str]);
    assert_eq!(
        out_ambiguous.status.code(),
        Some(2),
        "expected exit 2 for ambiguous multi-hash .txt, stdout: {}, stderr: {}",
        stdout_str(&out_ambiguous),
        stderr_str(&out_ambiguous)
    );
}

#[test]
fn batch_check_manifest_pass_and_mismatch() {
    let dir = TempDir::new().expect("create tempdir");
    let file_a = dir.path().join("a.bin");
    let file_b = dir.path().join("b.bin");
    std::fs::write(&file_a, b"abc").expect("write a.bin");
    std::fs::write(&file_b, b"").expect("write b.bin");

    let pass_manifest = dir.path().join("pass.sha256");
    std::fs::write(
        &pass_manifest,
        format!("{SHA256_ABC}  a.bin\n{SHA256_EMPTY}  b.bin\n"),
    )
    .expect("write pass manifest");
    let pass_str = path_arg(&pass_manifest);

    for flag in ["-c", "--check"] {
        let out = run_hashcheck(&[flag, &pass_str]);
        assert_eq!(
            out.status.code(),
            Some(0),
            "batch pass failed for {flag}, stderr: {}",
            stderr_str(&out)
        );
        let text = stdout_str(&out);
        assert!(text.contains("IDENTICAL"));
        assert!(text.contains("2 identical"));
    }

    let fail_manifest = dir.path().join("fail.sha256");
    std::fs::write(
        &fail_manifest,
        format!("{SHA256_ABC}  a.bin\n{WRONG_SHA256}  b.bin\n"),
    )
    .expect("write fail manifest");
    let fail_str = path_arg(&fail_manifest);

    for flag in ["-c", "--check"] {
        let out = run_hashcheck(&[flag, &fail_str]);
        assert_eq!(
            out.status.code(),
            Some(1),
            "batch mismatch failed for {flag}, stderr: {}",
            stderr_str(&out)
        );
        let text = stdout_str(&out);
        assert!(text.contains("NOT IDENTICAL. BE CAUTIOUS."));
    }
}

#[test]
fn json_output_emits_required_fields() {
    let dir = TempDir::new().expect("create tempdir");
    let target = dir.path().join("sample.bin");
    std::fs::write(&target, b"abc").expect("write target");
    let target_str = path_arg(&target);

    let out = run_hashcheck(&["--json", SHA256_ABC, &target_str]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_str(&out));

    let parsed: Value = serde_json::from_slice(&out.stdout).expect("parse valid JSON output");
    let obj = parsed.as_object().expect("JSON root must be an object");

    for key in [
        "status",
        "identical",
        "algorithm",
        "expected",
        "actual",
        "file",
        "bytes",
        "elapsed_ms",
        "throughput_mbps",
    ] {
        assert!(
            obj.contains_key(key),
            "missing JSON key '{key}' in {parsed}"
        );
    }

    assert_eq!(obj["status"], "IDENTICAL");
    assert_eq!(obj["identical"], true);
    assert_eq!(obj["algorithm"], HashAlgorithm::Sha256.as_str());
    assert_eq!(obj["expected"], SHA256_ABC);
    assert_eq!(obj["actual"], SHA256_ABC);
    assert_eq!(obj["bytes"], 3);
    assert!(obj["elapsed_ms"].is_u64());
    assert!(obj["throughput_mbps"].is_f64());

    let mismatch_out = run_hashcheck(&["--json", WRONG_SHA256, &target_str]);
    assert_eq!(mismatch_out.status.code(), Some(1));
    let mismatch_json: Value =
        serde_json::from_slice(&mismatch_out.stdout).expect("parse mismatch JSON");
    assert_eq!(mismatch_json["status"], "MISMATCH");
    assert_eq!(mismatch_json["identical"], false);
    assert_eq!(mismatch_json["expected"], WRONG_SHA256);
    assert_eq!(mismatch_json["actual"], SHA256_ABC);
}

#[test]
fn single_arg_compute_only_default_and_blake3() {
    let dir = TempDir::new().expect("create tempdir");
    let target = dir.path().join("sample.bin");
    std::fs::write(&target, b"abc").expect("write target");
    let target_str = path_arg(&target);

    let sha_out = run_hashcheck(&[&target_str]);
    assert_eq!(
        sha_out.status.code(),
        Some(0),
        "stderr: {}",
        stderr_str(&sha_out)
    );
    let sha_text = stdout_str(&sha_out);
    assert!(sha_text.contains(DEFAULT_COMPUTE_ALGORITHM.as_str()));
    assert!(sha_text.contains(SHA256_ABC));

    let b3_out = run_hashcheck(&["--algo", HashAlgorithm::Blake3.cli_name(), &target_str]);
    assert_eq!(
        b3_out.status.code(),
        Some(0),
        "stderr: {}",
        stderr_str(&b3_out)
    );
    let b3_text = stdout_str(&b3_out);
    assert!(b3_text.contains(HashAlgorithm::Blake3.as_str()));
    assert!(b3_text.contains(BLAKE3_ABC));
}

#[test]
fn get_hash_enter_default_computes_default_algorithm() {
    let dir = TempDir::new().expect("create tempdir");
    let target = dir.path().join("sample.bin");
    let payload = b"abc";
    std::fs::write(&target, payload).expect("write target");
    let target_str = path_arg(&target);

    let out = run_hashcheck_with_stdin(&["--get-hash", &target_str], b"\n");
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_str(&out));

    let text = stdout_str(&out);
    let expected_digest = hash_bytes(payload, DEFAULT_COMPUTE_ALGORITHM);
    assert_eq!(expected_digest, SHA256_ABC);
    assert!(text.contains(DEFAULT_COMPUTE_ALGORITHM.as_str()));
    assert!(text.contains(&expected_digest));
}

#[test]
fn get_hash_numbered_picker_choice_and_invalid_stdin() {
    let dir = TempDir::new().expect("create tempdir");
    let target = dir.path().join("sample.bin");
    let payload = b"abc";
    std::fs::write(&target, payload).expect("write target");
    let target_str = path_arg(&target);

    let choices = HashAlgorithm::picker_order();
    assert!(
        choices.len() > 1,
        "picker_order must contain at least one non-default choice"
    );

    for (idx, &algo) in choices
        .iter()
        .enumerate()
        .filter(|(_, algo)| **algo != DEFAULT_COMPUTE_ALGORITHM)
    {
        let input = format!("{}\n", idx + 1);
        let out = run_hashcheck_with_stdin(&["--get-hash", &target_str], input.as_bytes());
        assert_eq!(
            out.status.code(),
            Some(0),
            "choice {} ({algo}) failed, stderr: {}",
            idx + 1,
            stderr_str(&out)
        );
        let text = stdout_str(&out);
        let expected_digest = hash_bytes(payload, algo);
        assert!(
            text.contains(algo.as_str()),
            "missing algorithm {} in stdout: {text}",
            algo.as_str()
        );
        assert!(
            text.contains(&expected_digest),
            "missing digest {expected_digest} for {algo} in stdout: {text}"
        );
    }

    let out_of_range = format!("{}\n", choices.len() + 1);
    for invalid in ["0\n", out_of_range.as_str(), "not-an-algo\n"] {
        let out = run_hashcheck_with_stdin(&["--get-hash", &target_str], invalid.as_bytes());
        assert!(
            !out.status.success(),
            "expected non-zero exit for invalid stdin '{invalid}'"
        );
        assert_eq!(out.status.code(), Some(2));
        assert!(
            stderr_str(&out).contains("algorithm selection failed"),
            "unexpected stderr for '{invalid}': {}",
            stderr_str(&out)
        );
    }
}

#[test]
fn get_hash_all_algorithms_single_pass() {
    let dir = TempDir::new().expect("create tempdir");
    let target = dir.path().join("sample.bin");
    let payload = b"abc";
    std::fs::write(&target, payload).expect("write target");
    let target_str = path_arg(&target);

    let choices = HashAlgorithm::picker_order();

    let text_out = run_hashcheck_with_stdin(&["--get-hash", &target_str], b"a\n");
    assert_eq!(
        text_out.status.code(),
        Some(0),
        "stderr: {}",
        stderr_str(&text_out)
    );
    let text = stdout_str(&text_out);
    assert!(text.contains(&format!("COMPUTED FILE DIGESTS ({})", choices.len())));
    for &algo in choices {
        let expected_digest = hash_bytes(payload, algo);
        assert!(
            text.contains(algo.as_str()),
            "missing algorithm {} in stdout: {text}",
            algo.as_str()
        );
        assert!(
            text.contains(&expected_digest),
            "missing digest {expected_digest} for {algo} in stdout: {text}"
        );
    }

    let json_out = run_hashcheck_with_stdin(&["--get-hash", &target_str, "--json"], b"a\n");
    assert_eq!(
        json_out.status.code(),
        Some(0),
        "stderr: {}",
        stderr_str(&json_out)
    );
    let parsed: Value = serde_json::from_slice(&json_out.stdout).expect("parse multi JSON");
    let obj = parsed.as_object().expect("JSON root must be an object");
    assert_eq!(obj["status"], "COMPUTED_ALL");
    assert_eq!(obj["bytes"], payload.len());
    assert!(obj["copied"].is_boolean());
    let digests = obj["digests"].as_array().expect("digests must be an array");
    assert_eq!(digests.len(), choices.len());
    for (entry, &algo) in digests.iter().zip(choices) {
        assert_eq!(entry["algorithm"], algo.as_str());
        assert_eq!(entry["digest"], hash_bytes(payload, algo));
    }
}

#[test]
fn get_hash_explicit_blake3_json_emits_required_fields() {
    let dir = TempDir::new().expect("create tempdir");
    let target = dir.path().join("sample.bin");
    let payload = b"abc";
    std::fs::write(&target, payload).expect("write target");
    let target_str = path_arg(&target);

    let algo = HashAlgorithm::Blake3;
    let out = run_hashcheck(&[
        "--get-hash",
        &target_str,
        "--algo",
        algo.cli_name(),
        "--json",
    ]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_str(&out));

    let parsed: Value = serde_json::from_slice(&out.stdout).expect("parse valid JSON output");
    let obj = parsed.as_object().expect("JSON root must be an object");

    for key in [
        "status",
        "identical",
        "algorithm",
        "actual",
        "file",
        "bytes",
        "elapsed_ms",
        "throughput_mbps",
        "copied",
    ] {
        assert!(
            obj.contains_key(key),
            "missing JSON key '{key}' in {parsed}"
        );
    }

    let expected_digest = hash_bytes(payload, algo);
    assert_eq!(expected_digest, BLAKE3_ABC);
    assert_eq!(obj["status"], "COMPUTED");
    assert_eq!(obj["identical"], true);
    assert_eq!(obj["algorithm"], algo.as_str());
    assert_eq!(obj["actual"], expected_digest);
    assert_eq!(obj["bytes"], payload.len());
    assert!(obj["elapsed_ms"].is_u64());
    assert!(obj["throughput_mbps"].is_f64());
    assert!(obj["copied"].is_boolean());
    if obj["copied"] == Value::Bool(false) {
        assert!(obj["clipboard_error"].is_string());
    } else {
        assert!(!obj.contains_key("clipboard_error"));
    }
}

#[test]
fn get_hash_conflict_flags_and_missing_file_exit_2() {
    let dir = TempDir::new().expect("create tempdir");
    let target = dir.path().join("sample.bin");
    std::fs::write(&target, b"abc").expect("write target");
    let target_str = path_arg(&target);

    let manifest = dir.path().join("sample.sha256");
    std::fs::write(&manifest, format!("{SHA256_ABC}  sample.bin\n")).expect("write manifest");
    let manifest_str = path_arg(&manifest);

    let missing = dir.path().join("does-not-exist.bin");
    let missing_str = path_arg(&missing);

    let invalid_invocations: Vec<(&str, Vec<&str>)> = vec![
        (
            "interactive conflict",
            vec!["--get-hash", &target_str, "--interactive", &target_str],
        ),
        (
            "check conflict",
            vec!["--get-hash", &target_str, "--check", &manifest_str],
        ),
        ("gui conflict", vec!["--get-hash", &target_str, "--gui"]),
        (
            "hash-file conflict",
            vec!["--get-hash", &target_str, "--hash-file"],
        ),
        (
            "positional arg conflict",
            vec!["--get-hash", &target_str, "extra-positional"],
        ),
        ("missing target file", vec!["--get-hash", &missing_str]),
    ];

    for (label, args) in invalid_invocations {
        let out = run_hashcheck(&args);
        assert_eq!(
            out.status.code(),
            Some(2),
            "expected exit 2 for {label}, stdout: {}, stderr: {}",
            stdout_str(&out),
            stderr_str(&out)
        );
        assert!(
            !stderr_str(&out).trim().is_empty(),
            "expected error message on stderr for {label}"
        );
    }
}
