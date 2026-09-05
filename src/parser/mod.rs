pub mod lexer;
#[allow(clippy::module_inception)]
pub mod parser;

pub use lexer::{LexError, Lexer, Token, TokenKind};
pub use parser::{ParseError, Parser};

use crate::ast::Rule;
use std::fs;
use std::path::Path;

pub fn parse_rules_from_str(source: &str) -> Result<Vec<Rule>, ParseError> {
    let mut parser = Parser::from_source(source)?;
    parser.parse_rules()
}

pub fn parse_rules_from_file<P: AsRef<Path>>(path: P) -> Result<Vec<Rule>, ParseError> {
    let content = fs::read_to_string(path.as_ref()).map_err(|e| ParseError {
        location: Default::default(),
        message: format!("Failed to read rule file '{}': {}", path.as_ref().display(), e),
    })?;
    parse_rules_from_str(&content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::*;

    #[test]
    fn test_parse_simple_rule() {
        let source = r#"
            rule suspicious_powershell : windows malware {
                meta:
                    author = "analyst"
                    description = "Detects suspicious PowerShell loader characteristics"
                    severity = "high"

                strings:
                    $powershell = "powershell" ascii nocase
                    $encoded = "-enc" wide
                    $frombase64 = "FromBase64String"

                condition:
                    $powershell and ($encoded or $frombase64)
            }
        "#;

        let rules = parse_rules_from_str(source).expect("Should parse rule");
        assert_eq!(rules.len(), 1);
        let rule = &rules[0];
        assert_eq!(rule.name, "suspicious_powershell");
        assert_eq!(rule.tags, vec!["windows", "malware"]);
        assert_eq!(rule.severity(), Severity::High);
        assert_eq!(rule.strings.len(), 3);
        assert!(matches!(rule.condition, Expr::And(_, _)));
    }

    #[test]
    fn test_parse_hex_and_regex() {
        let source = r#"
            rule binary_pattern {
                strings:
                    $hex = { 48 8b ?? ?? 48 85 c0 }
                    $re = /[A-Za-z0-9+\/]{50,}={0,2}/i

                condition:
                    $hex or $re
            }
        "#;

        let rules = parse_rules_from_str(source).expect("Should parse hex and regex");
        assert_eq!(rules.len(), 1);
        let rule = &rules[0];
        assert_eq!(rule.strings.len(), 2);
        match &rule.strings[0].pattern {
            StringPattern::Hex { tokens } => {
                assert_eq!(tokens.len(), 7);
                assert_eq!(tokens[0], HexToken::Exact(0x48));
                assert_eq!(tokens[1], HexToken::Exact(0x8B));
                assert_eq!(tokens[2], HexToken::Wildcard);
                assert_eq!(tokens[3], HexToken::Wildcard);
                assert_eq!(tokens[4], HexToken::Exact(0x48));
                assert_eq!(tokens[5], HexToken::Exact(0x85));
                assert_eq!(tokens[6], HexToken::Exact(0xC0));
            }
            _ => panic!("Expected Hex pattern"),
        }
    }

    #[test]
    fn test_parse_count_and_pe_condition() {
        let source = r#"
            rule injection {
                strings:
                    $va = "VirtualAlloc"
                    $vae = "VirtualAllocEx"
                    $wpm = "WriteProcessMemory"

                condition:
                    2 of ($*) and pe.import("kernel32.dll", "VirtualAllocEx") and pe.section(".text").entropy > 7.2
            }
        "#;

        let rules = parse_rules_from_str(source).expect("Should parse PE expressions and counts");
        assert_eq!(rules.len(), 1);
    }
}
