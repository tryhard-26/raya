use raya::binary::{detect_format, parse_elf, BinaryFormat};

#[test]
fn test_elf_header_parsing() {
    let mut elf = vec![0u8; 128];
    elf[0..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2; // 64-bit
    elf[5] = 1; // Little endian
    elf[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    elf[18..20].copy_from_slice(&62u16.to_le_bytes()); // x86_64
    elf[24..32].copy_from_slice(&0x401000u64.to_le_bytes()); // entry point

    assert_eq!(detect_format(&elf), BinaryFormat::Elf64);

    let info = parse_elf(&elf).expect("ELF should parse successfully");
    assert!(info.is_elf);
    assert!(info.is_64);
    assert!(info.is_executable);
    assert_eq!(info.entry_point, 0x401000);
    assert_eq!(info.machine, 62);
}
