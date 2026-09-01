use raya::ast::Severity;
use raya::engine::Engine;
use raya::parser::parse_rules_from_str;

#[test]
fn test_wide_and_nocase_matching() {
    let rule_src = r#"
        rule wide_test {
            meta:
                severity = "medium"
            strings:
                $w = "secret_command" wide nocase
            condition:
                $w
        }
    "#;

    let rules = parse_rules_from_str(rule_src).unwrap();
    let engine = Engine::compile_rules(rules).unwrap();

    let mut payload = Vec::new();
    // UTF-16 "SECRET_COMMAND"
    for b in "SECRET_COMMAND".bytes() {
        payload.push(b);
        payload.push(0);
    }

    let res = engine.scan_bytes(&payload, "memory_dump.raw");
    assert!(res.has_matches());
    assert_eq!(res.matches[0].rule, "wide_test");
    assert_eq!(res.matches[0].severity, Severity::Medium);
}

#[test]
fn test_hex_nibble_wildcard_matching() {
    let rule_src = r#"
        rule hex_nibble {
            strings:
                $op = { 4? 8B ?4 24 }
            condition:
                $op
        }
    "#;

    let rules = parse_rules_from_str(rule_src).unwrap();
    let engine = Engine::compile_rules(rules).unwrap();

    // 0x48 (high 4, low 8), 0x8B, 0x54 (high 5, low 4), 0x24
    let payload = vec![0x90, 0x48, 0x8B, 0x54, 0x24, 0xC3];
    let res = engine.scan_bytes(&payload, "binary.bin");
    assert!(res.has_matches());
}

#[test]
fn test_quantifiers_and_them() {
    let rule_src = r#"
        rule multi_pattern {
            strings:
                $a = "alpha"
                $b = "bravo"
                $c = "charlie"
                $d = "delta"
            condition:
                3 of them and not $d
        }
    "#;

    let rules = parse_rules_from_str(rule_src).unwrap();
    let engine = Engine::compile_rules(rules).unwrap();

    let pass_payload = b"alpha ... bravo ... charlie";
    let fail_payload = b"alpha ... bravo";
    let excluded_payload = b"alpha ... bravo ... charlie ... delta";

    assert!(engine.scan_bytes(pass_payload, "t1").has_matches());
    assert!(!engine.scan_bytes(fail_payload, "t2").has_matches());
    assert!(!engine.scan_bytes(excluded_payload, "t3").has_matches());
}

#[test]
fn test_string_counts_and_offsets() {
    let rule_src = r#"
        rule count_check {
            strings:
                $marker = "MARKER"
            condition:
                #marker >= 3 and @marker < 20
        }
    "#;

    let rules = parse_rules_from_str(rule_src).unwrap();
    let engine = Engine::compile_rules(rules).unwrap();

    let valid_payload = b"... MARKER ... MARKER ... MARKER ...";
    let invalid_offset = b"....................... MARKER ... MARKER ... MARKER";

    assert!(engine.scan_bytes(valid_payload, "v1").has_matches());
    assert!(!engine.scan_bytes(invalid_offset, "v2").has_matches());
}
