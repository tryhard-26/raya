use std::process::Command;

fn get_bin_path() -> String {
    env!("CARGO_BIN_EXE_raya").to_string()
}

#[test]
fn test_cli_version() {
    let output = Command::new(get_bin_path())
        .arg("version")
        .output()
        .expect("Failed to execute raya version");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("raya 0.1.0"));
    assert!(stdout.contains("Engine:       Raya Core"));
}

#[test]
fn test_cli_check_rules() {
    let output = Command::new(get_bin_path())
        .args(["check", "rules/"])
        .output()
        .expect("Failed to execute raya check");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("All rules validated successfully"));
}

#[test]
fn test_cli_scan_detection_exit_code() {
    let output = Command::new(get_bin_path())
        .args([
            "scan",
            "tests/fixtures/sample_injection.exe",
            "--rules",
            "rules/",
        ])
        .output()
        .expect("Failed to execute raya scan");

    // Detections should exit with code 1
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("process_injection"));
    assert!(stdout.contains("T1055"));
}

#[test]
fn test_cli_scan_clean_exit_code() {
    let output = Command::new(get_bin_path())
        .args([
            "scan",
            "tests/fixtures/clean_application.exe",
            "--rules",
            "rules/",
        ])
        .output()
        .expect("Failed to execute raya scan");

    // Clean scan should exit with code 0
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("No rules matched (clean)"));
}

#[test]
fn test_cli_scan_json_output() {
    let output = Command::new(get_bin_path())
        .args([
            "scan",
            "tests/fixtures/sample_injection.exe",
            "--rules",
            "rules/",
            "--json",
        ])
        .output()
        .expect("Failed to execute raya scan --json");

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("Scan output should be valid JSON");
    assert_eq!(parsed["file_type"], "PE32+");
    assert!(!parsed["matches"].as_array().unwrap().is_empty());
}

#[test]
fn test_cli_test_suite_runner() {
    let output = Command::new(get_bin_path())
        .args(["test", "tests/fixtures/test_spec.json"])
        .output()
        .expect("Failed to execute raya test");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Coverage:        100.0%"));
    assert!(stdout.contains("Failed:          0"));
    assert!(stdout.contains("False Positives: 0"));
    assert!(stdout.contains("False Negatives: 0"));
}
