mod common;

use common::{build_mock_elf, build_mock_pe, build_mock_pe32};
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

    // 1. Build sample_injection.exe (Emotet-like injection payload)
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
        &[(
            "kernel32.dll",
            &["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
        )],
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
    fs::write(
        fixtures_dir.join("high_entropy_benign.dat"),
        &high_entropy_data,
    )
    .unwrap();

    // 4. Build wannacry_sample.exe (PE32)
    let mut wannacry_data = Vec::new();
    wannacry_data.extend_from_slice(b"tasksche.exe\0");
    wannacry_data.extend_from_slice(b"attrib +h .\0");
    wannacry_data.extend_from_slice(b"icacls . /grant Everyone:F\0");
    wannacry_data.extend_from_slice(b"WANACRY!\0");
    wannacry_data.extend_from_slice(b".wncry\0");
    wannacry_data.resize(1024, 0x90);

    let wannacry_pe = build_mock_pe32(
        &[
            (".text", 0x60000020, &wannacry_data),
            (
                ".rsrc",
                0x40000040,
                b"WannaCry Encrypted Resource Archive WANACRY!",
            ),
        ],
        &[],
    );
    fs::write(fixtures_dir.join("wannacry_sample.exe"), &wannacry_pe).unwrap();

    // 5. Build lockbit_sample.exe (PE32 with ransomware indicators)
    let mut lockbit_data = Vec::new();
    lockbit_data.extend_from_slice(b"vssadmin.exe Delete Shadows\0");
    lockbit_data.extend_from_slice(b"bcdedit /set {default} recoveryenabled No\0");
    lockbit_data.extend_from_slice(b"all your files have been encrypted\0");
    lockbit_data.extend_from_slice(b"restore-my-files.txt\0");
    lockbit_data.resize(1024, 0x90);

    let lockbit_pe = build_mock_pe32(
        &[
            (".text", 0x60000020, &lockbit_data),
            (".data", 0xC0000040, b"LockBit 3.0 Encrypted Configuration"),
        ],
        &[],
    );
    fs::write(fixtures_dir.join("lockbit_sample.exe"), &lockbit_pe).unwrap();

    // 6. Build cobalt_strike_beacon.exe (PE32+ with C2 beaconing indicators)
    let mut cs_data = Vec::new();
    cs_data.extend_from_slice(b"POST /api/v1/beacon\0");
    cs_data.extend_from_slice(b"Mozilla/5.0 (Windows NT 10.0; Win64; x64) RayaC2Test\0");
    cs_data.extend_from_slice(b"VirtualAllocEx\0");
    cs_data.extend_from_slice(b"WriteProcessMemory\0");
    cs_data.extend_from_slice(b"CreateRemoteThread\0");
    cs_data.resize(1024, 0x90);

    let cs_pe = build_mock_pe(
        &[
            (".text", 0x60000020, &cs_data),
            (
                ".rdata",
                0x40000040,
                b"Cobalt Strike Beacon Configuration Block",
            ),
        ],
        &[("wininet.dll", &["InternetOpenUrl", "HttpSendRequest"])],
    );
    fs::write(fixtures_dir.join("cobalt_strike_beacon.exe"), &cs_pe).unwrap();

    // 7. Build redline_stealer.exe (PE32 with persistence and stealer network activity)
    let mut redline_data = Vec::new();
    redline_data.extend_from_slice(b"Software\\Microsoft\\Windows\\CurrentVersion\\Run\0");
    redline_data.extend_from_slice(b"RegSetValueEx\0");
    redline_data.extend_from_slice(b"POST /api/v1/beacon\0");
    redline_data.resize(1024, 0x90);

    let redline_pe = build_mock_pe32(
        &[
            (".text", 0x60000020, &redline_data),
            (
                ".data",
                0xC0000040,
                b"RedLine Credential Harvester String Table",
            ),
        ],
        &[("advapi32.dll", &["RegSetValueExA"])],
    );
    fs::write(fixtures_dir.join("redline_stealer.exe"), &redline_pe).unwrap();

    // 8. Build upx_packed_sample.exe (PE32 with UPX sections and stub)
    let mut upx_stub_data = Vec::new();
    // Packed stub: 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57
    upx_stub_data.extend_from_slice(&[
        0x60, 0xBE, 0x00, 0x10, 0x40, 0x00, 0x8D, 0xBE, 0x00, 0x10, 0x00, 0x00, 0x57,
    ]);
    upx_stub_data.extend_from_slice(b"UPX0\0UPX1\0");
    upx_stub_data.resize(1024, 0x90);

    let upx_pe = build_mock_pe32(
        &[
            ("UPX0", 0xE0000080, b"Uninitialized packed section buffer"),
            ("UPX1", 0xE0000040, &upx_stub_data),
        ],
        &[],
    );
    fs::write(fixtures_dir.join("upx_packed_sample.exe"), &upx_pe).unwrap();

    // 9. Build mirai_sample.elf (ELF64 with Mirai botnet artifacts)
    let mut mirai_payload = Vec::new();
    mirai_payload.extend_from_slice(b"/bin/busybox killall\0");
    mirai_payload.extend_from_slice(b"/dev/watchdog\0");
    mirai_payload.extend_from_slice(b"/dev/misc/watchdog\0");
    mirai_payload.extend_from_slice(b"dvrHelper\0");
    mirai_payload.extend_from_slice(b"POST /cdn-cgi/\0");
    mirai_payload.resize(512, 0x90);

    let mirai_elf = build_mock_elf(&mirai_payload);
    fs::write(fixtures_dir.join("mirai_sample.elf"), &mirai_elf).unwrap();
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
    assert!(
        !result.has_matches(),
        "Benign high-entropy data should not trigger injection rule"
    );
}

#[test]
fn test_real_malware_detections() {
    // Make sure fixtures are generated
    test_generate_fixtures();

    // 1. WannaCry
    let wc_rules = parse_rules_from_file("rules/ransomware/wannacry.raya").unwrap();
    let wc_engine = Engine::compile_rules(wc_rules).unwrap();
    let wc_data = fs::read("tests/fixtures/wannacry_sample.exe").unwrap();
    let wc_res = wc_engine.scan_bytes(&wc_data, "wannacry_sample.exe");
    assert!(
        wc_res.has_matches(),
        "WannaCry sample should trigger ransomware_wannacry rule"
    );
    assert_eq!(wc_res.matches[0].rule, "ransomware_wannacry");

    // 2. LockBit 3.0
    let lb_rules = parse_rules_from_file("rules/ransomware/ransomware_indicators.raya").unwrap();
    let lb_engine = Engine::compile_rules(lb_rules).unwrap();
    let lb_data = fs::read("tests/fixtures/lockbit_sample.exe").unwrap();
    let lb_res = lb_engine.scan_bytes(&lb_data, "lockbit_sample.exe");
    assert!(
        lb_res.has_matches(),
        "LockBit sample should trigger ransomware_behavior_indicators"
    );
    assert_eq!(lb_res.matches[0].rule, "ransomware_behavior_indicators");

    // 3. Cobalt Strike C2 Beacon
    let cs_rules = parse_rules_from_file("rules/networking/c2_indicators.raya").unwrap();
    let cs_engine = Engine::compile_rules(cs_rules).unwrap();
    let cs_data = fs::read("tests/fixtures/cobalt_strike_beacon.exe").unwrap();
    let cs_res = cs_engine.scan_bytes(&cs_data, "cobalt_strike_beacon.exe");
    assert!(
        cs_res.has_matches(),
        "Cobalt Strike sample should trigger c2_network_beaconing"
    );
    assert_eq!(cs_res.matches[0].rule, "c2_network_beaconing");

    // 4. RedLine Stealer
    let rl_rules = parse_rules_from_file("rules/persistence/registry_persistence.raya").unwrap();
    let rl_engine = Engine::compile_rules(rl_rules).unwrap();
    let rl_data = fs::read("tests/fixtures/redline_stealer.exe").unwrap();
    let rl_res = rl_engine.scan_bytes(&rl_data, "redline_stealer.exe");
    assert!(
        rl_res.has_matches(),
        "RedLine Stealer should trigger registry_run_keys_persistence"
    );
    assert_eq!(rl_res.matches[0].rule, "registry_run_keys_persistence");

    // 5. UPX Packed Malware
    let upx_rules = parse_rules_from_file("rules/packers/packed_pe.raya").unwrap();
    let upx_engine = Engine::compile_rules(upx_rules).unwrap();
    let upx_data = fs::read("tests/fixtures/upx_packed_sample.exe").unwrap();
    let upx_res = upx_engine.scan_bytes(&upx_data, "upx_packed_sample.exe");
    assert!(
        upx_res.has_matches(),
        "UPX sample should trigger packed_pe_indicators"
    );
    assert_eq!(upx_res.matches[0].rule, "packed_pe_indicators");

    // 6. Mirai IoT Botnet (ELF)
    let mirai_rules = parse_rules_from_file("rules/botnet/mirai.raya").unwrap();
    let mirai_engine = Engine::compile_rules(mirai_rules).unwrap();
    let mirai_data = fs::read("tests/fixtures/mirai_sample.elf").unwrap();
    let mirai_res = mirai_engine.scan_bytes(&mirai_data, "mirai_sample.elf");
    assert!(
        mirai_res.has_matches(),
        "Mirai sample should trigger mirai_botnet rule"
    );
    assert_eq!(mirai_res.matches[0].rule, "mirai_botnet");

    // 7. Clean binary baseline
    let clean_data = fs::read("tests/fixtures/clean_application.exe").unwrap();
    assert!(!wc_engine
        .scan_bytes(&clean_data, "clean_app.exe")
        .has_matches());
    assert!(!lb_engine
        .scan_bytes(&clean_data, "clean_app.exe")
        .has_matches());
    assert!(!cs_engine
        .scan_bytes(&clean_data, "clean_app.exe")
        .has_matches());
    assert!(!rl_engine
        .scan_bytes(&clean_data, "clean_app.exe")
        .has_matches());
    assert!(!upx_engine
        .scan_bytes(&clean_data, "clean_app.exe")
        .has_matches());
    assert!(!mirai_engine
        .scan_bytes(&clean_data, "clean_app.exe")
        .has_matches());
}
