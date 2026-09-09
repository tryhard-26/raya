mod common;

use common::build_mock_pe;
use raya::binary::{detect_format, parse_pe, BinaryFormat};

#[test]
fn test_pe_parsing_sections_and_entropy() {
    let text_content = vec![0x90; 1024]; // NOP sled -> low entropy
    let mut data_content = vec![0u8; 1024];
    for (i, b) in data_content.iter_mut().enumerate() {
        *b = (i % 256) as u8; // pseudo-uniform -> high entropy
    }

    let pe_data = build_mock_pe(
        &[
            (".text", 0x60000020, &text_content), // Readable + Executable
            (".data", 0xC0000040, &data_content), // Readable + Writable
        ],
        &[("kernel32.dll", &["VirtualAllocEx", "CreateThread"])],
    );

    assert_eq!(detect_format(&pe_data), BinaryFormat::Pe32Plus);

    let pe_info = parse_pe(&pe_data).expect("PE should parse successfully");
    assert!(pe_info.is_pe);
    assert!(pe_info.is_pe32_plus);
    assert!(!pe_info.is_dll);
    assert_eq!(pe_info.sections.len(), 2);

    let text_sec = pe_info.get_section(".text").expect(".text section missing");
    assert!(text_sec.is_readable);
    assert!(text_sec.is_executable);
    assert!(!text_sec.is_writable);
    assert!(text_sec.entropy < 1.0);

    let data_sec = pe_info.get_section(".data").expect(".data section missing");
    assert!(data_sec.is_readable);
    assert!(data_sec.is_writable);
    assert!(!data_sec.is_executable);
    assert!(data_sec.entropy > 7.0);
}

#[test]
fn test_pe_rwx_detection() {
    let mock_rwx = build_mock_pe(
        &[
            (".text", 0xE0000060, b"RWX Shellcode Section"), // Read + Write + Execute
        ],
        &[],
    );

    let pe_info = parse_pe(&mock_rwx).expect("PE should parse");
    assert!(
        pe_info.has_rwx_section(),
        "Should detect RWX section characteristics"
    );
}
