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
    assert_eq!(pe_info.rwx_sections().len(), 1);
    assert_eq!(pe_info.rwx_sections()[0].name, ".text");
}

#[test]
fn test_pe_rwx_evidence_reporting() {
    let mock_rwx = build_mock_pe(
        &[(".shell", 0xE0000060, b"Shellcode Payload RWX Data")],
        &[],
    );

    let rule_src = r#"
        rule rwx_evidence_rule {
            meta:
                description = "Detects RWX sections"
                severity = "high"
            condition:
                pe.is_pe and pe.has_rwx
        }
    "#;
    let rules = raya::parser::parse_rules_from_str(rule_src).unwrap();
    let engine = raya::engine::Engine::compile_rules(rules).unwrap();
    let res = engine.scan_bytes(&mock_rwx, "rwx_sample.exe");
    assert!(res.has_matches());
    let m = &res.matches[0];
    assert!(!m.evidence.is_empty(), "Evidence must never be empty");
    match &m.evidence[0] {
        raya::engine::context::MatchedEvidence::PeCharacteristic { name, detail } => {
            assert_eq!(name, "has_rwx");
            assert!(
                detail.contains(".shell"),
                "Detail must contain offending section name"
            );
            assert!(
                detail.contains("VA 0x"),
                "Detail must contain virtual address"
            );
            assert!(
                detail.contains("VirtualSize:"),
                "Detail must contain section size"
            );
        }
        other => panic!("Expected PeCharacteristic evidence, got {:?}", other),
    }
}

#[test]
fn test_pe_additional_heuristics_and_rule_eval() {
    let mock_pe = build_mock_pe(
        &[
            (".text", 0x60000020, b"Code Section Content"),
            (".data", 0xC0000040, b"Data Section Content"),
        ],
        &[("kernel32.dll", &["VirtualAlloc", "Sleep"])],
    );

    let pe_info = parse_pe(&mock_pe).expect("PE should parse");
    assert!(pe_info.has_section(".text"));
    assert!(pe_info.has_section(".data"));
    assert!(!pe_info.has_section(".nonexistent"));
    assert_eq!(pe_info.number_of_imports(), 0);

    let rule_src = r#"
        rule PE_Heuristics_Rule {
            condition:
                pe.has_section(".text") and
                pe.number_of_imports == 0 and
                not pe.has_tls
        }
    "#;
    let rules = raya::parser::parse_rules_from_str(rule_src).unwrap();
    let engine = raya::engine::Engine::compile_rules(rules).unwrap();
    let res = engine.scan_bytes(&mock_pe, "mock_test.exe");
    assert!(res.has_matches());
    assert_eq!(res.matches[0].rule, "PE_Heuristics_Rule");
}

#[test]
fn test_pe_api_call_arg_tracking() {
    // Machine code for:
    // push 0x40 (PAGE_EXECUTE_READWRITE)
    // push 0x1000 (MEM_COMMIT)
    // call edx
    let code = [
        0x6A, 0x40, // push 0x40
        0x68, 0x00, 0x10, 0x00, 0x00, // push 0x1000
        0xFF, 0xD2, // call edx
    ];

    let mock_pe = build_mock_pe(
        &[
            (".text", 0x60000020, &code),
            (".rdata", 0x40000040, b"VirtualAlloc\0kernel32.dll\0"),
        ],
        &[("kernel32.dll", &["VirtualAlloc"])],
    );

    let rule_src = r#"
        rule Detect_VirtualAlloc_RWX {
            meta:
                severity = "critical"
                description = "Detects VirtualAlloc called with PAGE_EXECUTE_READWRITE"
            condition:
                pe.is_pe and pe.api_call_arg("VirtualAlloc", 0x40)
        }
    "#;

    let rules = raya::parser::parse_rules_from_str(rule_src).unwrap();
    let engine = raya::engine::Engine::compile_rules(rules).unwrap();
    let res = engine.scan_bytes(&mock_pe, "sample_alloc.exe");

    assert!(res.has_matches());
    assert_eq!(res.matches[0].rule, "Detect_VirtualAlloc_RWX");
    assert_eq!(res.matches[0].evidence.len(), 1);

    match &res.matches[0].evidence[0] {
        raya::engine::context::MatchedEvidence::ApiCallArgument {
            api,
            argument_name,
            value,
            constant_name,
            ..
        } => {
            assert_eq!(api, "VirtualAlloc");
            assert_eq!(argument_name, "flProtect");
            assert_eq!(*value, 0x40);
            assert_eq!(constant_name, "PAGE_EXECUTE_READWRITE");
        }
        other => panic!("Expected ApiCallArgument evidence, got {:?}", other),
    }
}

#[test]
fn test_basic_block_scoping_rule() {
    // BB1: xor eax, eax; jmp +4
    // BB2: push 0x40; call edx
    let code = [
        0x31, 0xC0, // xor eax, eax
        0xEB, 0x04, // jmp +4
        0x6A, 0x40, // push 0x40
        0xFF, 0xD2, // call edx
    ];

    let mock_pe = build_mock_pe(
        &[(".text", 0x60000020, &code)],
        &[("kernel32.dll", &["VirtualAlloc"])],
    );

    // Rule 1: Matches within the straight-line BB2
    let rule_src = r#"
        rule In_Same_Basic_Block {
            condition:
                pe.in_basic_block("push", "call")
        }
    "#;
    let rules = raya::parser::parse_rules_from_str(rule_src).unwrap();
    let engine = raya::engine::Engine::compile_rules(rules).unwrap();
    let res = engine.scan_bytes(&mock_pe, "bb_test.exe");
    assert!(res.has_matches());

    // Rule 2: Separated by jump boundary across basic blocks - should NOT match
    let rule_cross = r#"
        rule Cross_Basic_Block {
            condition:
                pe.in_basic_block("xor", "call")
        }
    "#;
    let rules_cross = raya::parser::parse_rules_from_str(rule_cross).unwrap();
    let engine_cross = raya::engine::Engine::compile_rules(rules_cross).unwrap();
    let res_cross = engine_cross.scan_bytes(&mock_pe, "bb_test.exe");
    assert!(
        !res_cross.has_matches(),
        "Should not match across jump boundary"
    );
}

#[test]
fn test_pe_syscall_evasion_rule() {
    // mov r10, rcx; mov eax, 0x18; syscall; ret
    let code = [
        0x49, 0x89, 0xCA, // mov r10, rcx
        0xB8, 0x18, 0x00, 0x00, 0x00, // mov eax, 0x18 (NtAllocateVirtualMemory)
        0x0F, 0x05, // syscall
        0xC3, // ret
    ];

    let mock_pe = build_mock_pe(&[(".text", 0x60000020, &code)], &[]);

    let rule_src = r#"
        rule Detect_Direct_Syscall {
            meta:
                severity = "critical"
            condition:
                pe.is_pe and (pe.has_direct_syscall or disasm.has_direct_syscall)
        }
    "#;

    let rules = raya::parser::parse_rules_from_str(rule_src).unwrap();
    let engine = raya::engine::Engine::compile_rules(rules).unwrap();
    let res = engine.scan_bytes(&mock_pe, "syscall_sample.exe");

    assert!(res.has_matches());
    assert_eq!(res.matches[0].rule, "Detect_Direct_Syscall");
    assert!(!res.matches[0].evidence.is_empty());

    match &res.matches[0].evidence[0] {
        raya::engine::context::MatchedEvidence::SyscallIndicator {
            stub_type,
            ssn,
            api_name,
            ..
        } => {
            assert_eq!(stub_type, "Direct");
            assert_eq!(*ssn, Some(0x18));
            assert_eq!(api_name.as_deref(), Some("NtAllocateVirtualMemory"));
        }
        other => panic!("Expected SyscallIndicator evidence, got {:?}", other),
    }
}

#[test]
fn test_pe_api_hash_rule() {
    let hash = raya::binary::api_hash::ror13("NtAllocateVirtualMemory");
    let mut code = vec![0xBA]; // mov edx, imm32
    code.extend_from_slice(&hash.to_le_bytes());
    code.push(0xC3); // ret

    let mock_pe = build_mock_pe(&[(".text", 0x60000020, &code)], &[]);

    let rule_src = r#"
        rule Detect_Api_Hash_Resolution {
            meta:
                severity = "high"
            condition:
                pe.is_pe and pe.has_api_hash and pe.has_api_hash("NtAllocateVirtualMemory")
        }
    "#;

    let rules = raya::parser::parse_rules_from_str(rule_src).unwrap();
    let engine = raya::engine::Engine::compile_rules(rules).unwrap();
    let res = engine.scan_bytes(&mock_pe, "apihash_sample.exe");

    assert!(res.has_matches());
    assert_eq!(res.matches[0].rule, "Detect_Api_Hash_Resolution");

    match &res.matches[0].evidence[0] {
        raya::engine::context::MatchedEvidence::ApiHash {
            algorithm,
            api_name,
            hash_value,
            ..
        } => {
            assert_eq!(algorithm.to_ascii_lowercase(), "ror13");
            assert_eq!(api_name, "NtAllocateVirtualMemory");
            assert_eq!(*hash_value, hash);
        }
        other => panic!("Expected ApiHash evidence, got {:?}", other),
    }
}

#[test]
fn test_pe_cfg_loop_and_complexity_rule() {
    // Loop with conditional back-edge:
    // xor eax, eax; inc eax; cmp eax, 10; jne -7; ret
    let code = [
        0x31, 0xC0, // xor eax, eax
        0xFF, 0xC0, // inc eax
        0x83, 0xF8, 0x0A, // cmp eax, 10
        0x75, 0xF9, // jne -7 (back to inc eax)
        0xC3, // ret
    ];

    let mock_pe = build_mock_pe(&[(".text", 0x60000020, &code)], &[]);

    let rule_src = r#"
        rule Detect_CFG_Loop_And_Complexity {
            condition:
                cfg.has_loop and cfg.loop_count >= 1
        }
    "#;

    let rules = raya::parser::parse_rules_from_str(rule_src).unwrap();
    let engine = raya::engine::Engine::compile_rules(rules).unwrap();
    let res = engine.scan_bytes(&mock_pe, "loop_sample.exe");

    assert!(res.has_matches());
    assert_eq!(res.matches[0].rule, "Detect_CFG_Loop_And_Complexity");
    assert!(!res.matches[0].evidence.is_empty());
}
