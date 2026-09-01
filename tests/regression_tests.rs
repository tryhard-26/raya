mod common;

use common::build_mock_pe;
use raya::binary::{detect_format, parse_elf, parse_pe, BinaryFormat};
use raya::engine::Engine;
use raya::entropy::shannon_entropy;
use raya::parser::parse_rules_from_file;
use std::fs;
use std::path::Path;

#[test]
fn test_generate_fixtures() {
    let fixtures_dir = Path::new("tests/fixtures");
    if !fixtures_dir.exists() {
        fs::create_dir_all(fixtures_dir).unwrap();
    }

    // 1. Build sample_injection.exe
    let mut injection_data = Vec::new();
    injection_data.extend_from_slice(b"VirtualAllocEx\0");
    injection_data.extend_from_slice(b"WriteProcessMemory\0");
    injection_data.extend_from_slice(b"CreateRemoteThread\0");
    injection_data.resize(1024, 0x90);

    let injection_pe = build_mock_pe(
        &[
            (".text", 0x60000020, &injection_data), // Readable, Executable, Code
            (".data", 0xC0000040, b"Injection Payload Buffer Data"),
        ],
        &[("kernel32.dll", &["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"])],
    );
    fs::write(fixtures_dir.join("sample_injection.exe"), &injection_pe).unwrap();

    // 2. Build clean_application.exe
    let mut clean_data = Vec::new();
    clean_data.extend_from_slice(b"Calculating report summary statistics...\0");
    clean_data.extend_from_slice(b"Application exiting cleanly.\0");
    clean_data.resize(1024, 0xCC);

    let clean_pe = build_mock_pe(
        &[
            (".text", 0x60000020, &clean_data),
            (".rdata", 0x40000040, b"Version 1.0.0 Clean Utility"),
        ],
        &[("kernel32.dll", &["ExitProcess", "GetSystemTimeAsFileTime"])],
    );
    fs::write(fixtures_dir.join("clean_application.exe"), &clean_pe).unwrap();

    // 3. Build high_entropy_benign.dat
    let mut high_entropy_data = Vec::with_capacity(256 * 10);
    for _ in 0..10 {
        for b in 0..=255u8 {
            high_entropy_data.push(b);
        }
    }
    fs::write(fixtures_dir.join("high_entropy_benign.dat"), &high_entropy_data).unwrap();
}

#[test]
fn test_safe_handling_of_malformed_inputs() {
    // Empty buffer
    assert!(parse_pe(&[]).is_none());
    assert!(parse_elf(&[]).is_none());
    assert_eq!(detect_format(&[]), BinaryFormat::Raw);

    // Truncated MZ
    assert!(parse_pe(b"M").is_none());
    assert!(parse_pe(b"MZ").is_none());

    // Invalid e_lfanew pointing out of bounds
    let mut bad_pe = vec![0u8; 64];
    bad_pe[0] = b'M';
    bad_pe[1] = b'Z';
    bad_pe[0x3C] = 0xFF;
    bad_pe[0x3D] = 0xFF;
    assert!(parse_pe(&bad_pe).is_none());

    // Truncated ELF
    assert!(parse_elf(b"\x7f").is_none());
    assert!(parse_elf(b"\x7fELF").is_none());
    assert!(parse_elf(b"\x7fELF\x02").is_none());

    // Fuzz test random bytes: must NEVER panic
    let mut pseudo_random = vec![0u8; 4096];
    let mut state: u32 = 0xDEADBEEF;
    for b in &mut pseudo_random {
        state = state.wrapping_mul(1103515245).wrapping_add(12345);
        *b = (state >> 16) as u8;
    }

    // These should safely return None or Raw without panicking
    let _ = parse_pe(&pseudo_random);
    let _ = parse_elf(&pseudo_random);
    let _ = detect_format(&pseudo_random);
    let ent = shannon_entropy(&pseudo_random);
    assert!(ent > 7.5);
}

#[test]
fn test_extension_independence() {
    let mock_pe = build_mock_pe(&[(".text", 0x60000020, b"Code")], &[]);
    // Format detection does not check filename extension, only magic headers
    let format = detect_format(&mock_pe);
    assert_eq!(format, BinaryFormat::Pe32Plus);
}

#[test]
fn test_benign_high_entropy_file_does_not_trigger_process_injection() {
    let rules = parse_rules_from_file("rules/injection/process_injection.raya").unwrap();
    let engine = Engine::compile_rules(rules).unwrap();

    let mut random_data = vec![0u8; 8192];
    for (i, b) in random_data.iter_mut().enumerate() {
        *b = (i % 256) as u8;
    }

    let result = engine.scan_bytes(&random_data, "benign_archive.zip");
    assert!(!result.has_matches(), "Benign high-entropy data should not trigger injection rule");
}
