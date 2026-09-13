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

#[test]
fn test_elf_hardening_mitigations() {
    let mut elf = vec![0u8; 256];
    elf[0..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2; // 64-bit
    elf[5] = 1; // Little endian
    elf[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    elf[18..20].copy_from_slice(&62u16.to_le_bytes()); // x86_64
    elf[24..32].copy_from_slice(&0x401000u64.to_le_bytes()); // entry point

    // Program headers at offset 64
    elf[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff = 64
    elf[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize = 56 (standard ELF64)
    elf[56..58].copy_from_slice(&2u16.to_le_bytes()); // e_phnum = 2

    // PH 0 at offset 64: PT_GNU_STACK (0x6474e551) with flags = PF_R | PF_W (0x6, non-executable -> has_nx = true)
    let ph0_offset = 64;
    elf[ph0_offset..ph0_offset + 4].copy_from_slice(&0x6474e551u32.to_le_bytes());
    elf[ph0_offset + 4..ph0_offset + 8].copy_from_slice(&0x00000006u32.to_le_bytes()); // flags: RW (no X)

    // PH 1 at offset 120: PT_GNU_RELRO (0x6474e552)
    let ph1_offset = 64 + 56;
    elf[ph1_offset..ph1_offset + 4].copy_from_slice(&0x6474e552u32.to_le_bytes());

    let info = parse_elf(&elf).expect("ELF should parse successfully");
    assert!(info.has_nx, "PT_GNU_STACK without X should yield has_nx");
    assert_eq!(info.relro, "Partial");

    // Evaluate detection rule
    let rule_src = r#"
        rule Verify_Elf_Hardening {
            condition:
                elf.is_elf and elf.has_nx and elf.relro == "Partial"
        }
    "#;
    let rules = raya::parser::parse_rules_from_str(rule_src).unwrap();
    let engine = raya::engine::Engine::compile_rules(rules).unwrap();
    let res = engine.scan_bytes(&elf, "test_sample.elf");
    assert!(res.has_matches());
    assert_eq!(res.matches[0].rule, "Verify_Elf_Hardening");
}
