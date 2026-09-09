use crate::ast::{HexToken, StringDefinition, StringPattern};
use aho_corasick::AhoCorasick;
use regex::bytes::RegexBuilder;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StringMatch {
    pub id: String,
    pub offset: usize,
    pub length: usize,
    pub snippet: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum MatchError {
    #[error("Regex error for string '{id}': {source}")]
    RegexError { id: String, source: regex::Error },
    #[error("Aho-Corasick builder error: {0}")]
    AhoCorasickError(#[from] aho_corasick::BuildError),
}

pub struct CompiledRulePatterns {
    /// Literal patterns searched via Aho-Corasick
    literal_ac: Option<AhoCorasick>,
    literal_ids: Vec<String>,
    /// Regex and Hex patterns searched via regex engine
    regex_patterns: Vec<(String, regex::bytes::Regex)>,
}

impl CompiledRulePatterns {
    pub fn compile(strings: &[StringDefinition]) -> Result<Self, MatchError> {
        let mut literal_patterns: Vec<Vec<u8>> = Vec::new();
        let mut literal_ids = Vec::new();
        let mut regex_patterns = Vec::new();

        for def in strings {
            match &def.pattern {
                StringPattern::Literal {
                    bytes,
                    ascii,
                    wide,
                    nocase,
                } => {
                    if *ascii && !*wide && !*nocase {
                        literal_patterns.push(bytes.clone());
                        literal_ids.push(def.id.clone());
                    } else {
                        // Build regex for literal to handle combinations of ascii, wide, nocase cleanly
                        let mut sub_regexes = Vec::new();

                        if *ascii {
                            let escaped = regex::escape(&String::from_utf8_lossy(bytes));
                            sub_regexes.push(escaped);
                        }

                        if *wide {
                            // UTF-16LE conversion
                            let mut wide_escaped = String::new();
                            for &b in bytes {
                                wide_escaped.push_str(&format!(r"\x{:02x}\x00", b));
                            }
                            sub_regexes.push(wide_escaped);
                        }

                        let combined = if sub_regexes.len() > 1 {
                            format!("(?:{})", sub_regexes.join("|"))
                        } else if !sub_regexes.is_empty() {
                            sub_regexes[0].clone()
                        } else {
                            regex::escape(&String::from_utf8_lossy(bytes))
                        };

                        let re = RegexBuilder::new(&combined)
                            .case_insensitive(*nocase)
                            .dot_matches_new_line(true)
                            .unicode(false)
                            .build()
                            .map_err(|e| MatchError::RegexError {
                                id: def.id.clone(),
                                source: e,
                            })?;

                        regex_patterns.push((def.id.clone(), re));
                    }
                }
                StringPattern::Hex { tokens } => {
                    let re_str = hex_tokens_to_regex(tokens);
                    let re = RegexBuilder::new(&re_str)
                        .dot_matches_new_line(true)
                        .unicode(false)
                        .build()
                        .map_err(|e| MatchError::RegexError {
                            id: def.id.clone(),
                            source: e,
                        })?;
                    regex_patterns.push((def.id.clone(), re));
                }
                StringPattern::Regex { pattern, nocase } => {
                    let re = RegexBuilder::new(pattern)
                        .case_insensitive(*nocase)
                        .dot_matches_new_line(true)
                        .unicode(false)
                        .build()
                        .map_err(|e| MatchError::RegexError {
                            id: def.id.clone(),
                            source: e,
                        })?;
                    regex_patterns.push((def.id.clone(), re));
                }
            }
        }

        let literal_ac = if !literal_patterns.is_empty() {
            Some(AhoCorasick::new(&literal_patterns)?)
        } else {
            None
        };

        Ok(Self {
            literal_ac,
            literal_ids,
            regex_patterns,
        })
    }

    pub fn scan(&self, data: &[u8]) -> HashMap<String, Vec<StringMatch>> {
        let mut matches: HashMap<String, Vec<StringMatch>> = HashMap::new();

        // 1. Literal search via Aho-Corasick
        if let Some(ac) = &self.literal_ac {
            for mat in ac.find_iter(data) {
                let id = &self.literal_ids[mat.pattern()];
                let offset = mat.start();
                let length = mat.end() - mat.start();
                let snippet_end = (offset + length.min(64)).min(data.len());
                let snippet = data[offset..snippet_end].to_vec();

                matches.entry(id.clone()).or_default().push(StringMatch {
                    id: id.clone(),
                    offset,
                    length,
                    snippet,
                });
            }
        }

        // 2. Regex and hex pattern searches
        for (id, re) in &self.regex_patterns {
            for mat in re.find_iter(data) {
                let offset = mat.start();
                let length = mat.end() - mat.start();
                let snippet_end = (offset + length.min(64)).min(data.len());
                let snippet = data[offset..snippet_end].to_vec();

                matches.entry(id.clone()).or_default().push(StringMatch {
                    id: id.clone(),
                    offset,
                    length,
                    snippet,
                });
            }
        }

        matches
    }
}

fn hex_tokens_to_regex(tokens: &[HexToken]) -> String {
    let mut regex = String::from("(?s-u)");
    for token in tokens {
        match token {
            HexToken::Exact(b) => {
                regex.push_str(&format!(r"\x{:02x}", b));
            }
            HexToken::Wildcard => {
                regex.push('.');
            }
            HexToken::HighNibble(high) => {
                let start = high << 4;
                let end = start | 0x0F;
                regex.push_str(&format!(r"[\x{:02x}-\x{:02x}]", start, end));
            }
            HexToken::LowNibble(low) => {
                let mut choices = Vec::new();
                for high in 0..=15u8 {
                    choices.push(format!(r"\x{:02x}", (high << 4) | low));
                }
                regex.push_str(&format!("(?:{})", choices.join("|")));
            }
        }
    }
    regex
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_literal_and_wide_matcher() {
        let defs = vec![
            StringDefinition {
                id: "$str1".to_string(),
                pattern: StringPattern::Literal {
                    bytes: b"powershell".to_vec(),
                    ascii: true,
                    wide: false,
                    nocase: true,
                },
            },
            StringDefinition {
                id: "$str2".to_string(),
                pattern: StringPattern::Literal {
                    bytes: b"malware".to_vec(),
                    ascii: false,
                    wide: true,
                    nocase: false,
                },
            },
        ];

        let compiled = CompiledRulePatterns::compile(&defs).expect("Compilation failed");

        let mut data = Vec::new();
        data.extend_from_slice(b"Header... PowerShell.exe ... ");
        // UTF-16 "malware"
        for &b in b"malware" {
            data.push(b);
            data.push(0);
        }
        data.extend_from_slice(b" ... Trailer");

        let matches = compiled.scan(&data);
        assert!(matches.contains_key("$str1"));
        assert!(matches.contains_key("$str2"));
    }

    #[test]
    fn test_hex_matcher_with_wildcards() {
        let defs = vec![StringDefinition {
            id: "$hex".to_string(),
            pattern: StringPattern::Hex {
                tokens: vec![
                    HexToken::Exact(0x48),
                    HexToken::Exact(0x8B),
                    HexToken::Wildcard,
                    HexToken::Wildcard,
                    HexToken::Exact(0x48),
                    HexToken::Exact(0x85),
                    HexToken::Exact(0xC0),
                ],
            },
        }];

        let compiled = CompiledRulePatterns::compile(&defs).expect("Compilation failed");
        let data = vec![0x90, 0x48, 0x8B, 0x54, 0x24, 0x48, 0x85, 0xC0, 0xCC];

        let matches = compiled.scan(&data);
        assert!(matches.contains_key("$hex"));
        assert_eq!(matches["$hex"][0].offset, 1);
        assert_eq!(matches["$hex"][0].length, 7);
    }
}
