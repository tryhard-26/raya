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
                    fullword,
                    xor,
                    base64,
                    base64wide,
                } => {
                    if *ascii
                        && !*wide
                        && !*nocase
                        && !*fullword
                        && xor.is_none()
                        && !*base64
                        && !*base64wide
                    {
                        literal_patterns.push(bytes.clone());
                        literal_ids.push(def.id.clone());
                    } else {
                        let mut sub_regexes = Vec::new();

                        if let Some((min_k, max_k)) = xor {
                            for key in *min_k..=*max_k {
                                let xored: Vec<u8> = bytes.iter().map(|b| b ^ key).collect();
                                if *ascii {
                                    let mut esc = String::new();
                                    for &b in &xored {
                                        esc.push_str(&format!(r"\x{:02x}", b));
                                    }
                                    sub_regexes.push(esc);
                                }
                                if *wide {
                                    let mut esc = String::new();
                                    for &b in &xored {
                                        esc.push_str(&format!(r"\x{:02x}\x00", b));
                                    }
                                    sub_regexes.push(esc);
                                }
                            }
                        } else {
                            if *ascii {
                                let escaped = regex::escape(&String::from_utf8_lossy(bytes));
                                sub_regexes.push(escaped);
                            }

                            if *wide {
                                let mut wide_escaped = String::new();
                                for &b in bytes {
                                    wide_escaped.push_str(&format!(r"\x{:02x}\x00", b));
                                }
                                sub_regexes.push(wide_escaped);
                            }

                            if *base64 {
                                for p in generate_base64_permutations(bytes) {
                                    sub_regexes.push(p);
                                }
                            }

                            if *base64wide {
                                let mut wide_bytes = Vec::with_capacity(bytes.len() * 2);
                                for &b in bytes {
                                    wide_bytes.push(b);
                                    wide_bytes.push(0);
                                }
                                for p in generate_base64_permutations(&wide_bytes) {
                                    sub_regexes.push(p);
                                }
                            }
                        }

                        let combined = if sub_regexes.len() > 1 {
                            format!("(?:{})", sub_regexes.join("|"))
                        } else if !sub_regexes.is_empty() {
                            sub_regexes[0].clone()
                        } else {
                            regex::escape(&String::from_utf8_lossy(bytes))
                        };

                        let final_pattern = if *fullword {
                            format!(r"\b(?:{})\b", combined)
                        } else {
                            combined
                        };

                        let re = RegexBuilder::new(&final_pattern)
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
                StringPattern::Regex {
                    pattern,
                    nocase,
                    fullword,
                } => {
                    let pat_str = if *fullword {
                        format!(r"\b(?:{})\b", pattern)
                    } else {
                        pattern.clone()
                    };
                    let re = RegexBuilder::new(&pat_str)
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

    pub fn scan_regex_only(&self, data: &[u8]) -> HashMap<String, Vec<StringMatch>> {
        let mut matches: HashMap<String, Vec<StringMatch>> = HashMap::new();
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

fn base64_encode(data: &[u8]) -> String {
    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0;
    while i < data.len() {
        let b0 = data[i];
        let b1 = if i + 1 < data.len() { data[i + 1] } else { 0 };
        let b2 = if i + 2 < data.len() { data[i + 2] } else { 0 };

        out.push(B64[(b0 >> 2) as usize] as char);
        out.push(B64[(((b0 & 3) << 4) | (b1 >> 4)) as usize] as char);
        if i + 1 < data.len() {
            out.push(B64[(((b1 & 0x0F) << 2) | (b2 >> 6)) as usize] as char);
        }
        if i + 2 < data.len() {
            out.push(B64[(b2 & 0x3F) as usize] as char);
        }
        i += 3;
    }
    out
}

fn generate_base64_permutations(bytes: &[u8]) -> Vec<String> {
    if bytes.is_empty() {
        return Vec::new();
    }
    let mut perms = Vec::new();

    let enc0 = base64_encode(bytes);
    if !enc0.is_empty() {
        perms.push(regex::escape(&enc0));
    }

    let mut d1 = vec![b'A'];
    d1.extend_from_slice(bytes);
    let enc1 = base64_encode(&d1);
    if enc1.len() > 2 {
        let sub = &enc1[2..];
        if !sub.is_empty() {
            perms.push(regex::escape(sub));
        }
    }

    let mut d2 = vec![b'A', b'A'];
    d2.extend_from_slice(bytes);
    let enc2 = base64_encode(&d2);
    if enc2.len() > 3 {
        let sub = &enc2[3..];
        if !sub.is_empty() {
            perms.push(regex::escape(sub));
        }
    }

    perms
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
            HexToken::Jump { min, max } => match max {
                Some(m) if *m == *min => regex.push_str(&format!(r".{{{}}}", min)),
                Some(m) => regex.push_str(&format!(r".{{{},{}}}?", min, m)),
                None => regex.push_str(&format!(r".{{{},}}?", min)),
            },
            HexToken::Alternation(branches) => {
                let branch_strs: Vec<String> = branches
                    .iter()
                    .map(|branch| {
                        let sub_re = hex_tokens_to_regex(branch);
                        sub_re.trim_start_matches("(?s-u)").to_string()
                    })
                    .collect();
                regex.push_str(&format!("(?:{})", branch_strs.join("|")));
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
                    fullword: false,
                    xor: None,
                    base64: false,
                    base64wide: false,
                },
            },
            StringDefinition {
                id: "$str2".to_string(),
                pattern: StringPattern::Literal {
                    bytes: b"malware".to_vec(),
                    ascii: false,
                    wide: true,
                    nocase: false,
                    fullword: false,
                    xor: None,
                    base64: false,
                    base64wide: false,
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

    #[test]
    fn test_hex_jumps_and_alternation() {
        let defs = vec![StringDefinition {
            id: "$complex_hex".to_string(),
            pattern: StringPattern::Hex {
                tokens: vec![
                    HexToken::Exact(0x55),
                    HexToken::Exact(0x8B),
                    HexToken::Exact(0xEC),
                    HexToken::Jump {
                        min: 2,
                        max: Some(4),
                    },
                    HexToken::Alternation(vec![
                        vec![HexToken::Exact(0x33), HexToken::Exact(0xC0)],
                        vec![HexToken::Exact(0x31), HexToken::Exact(0xC0)],
                    ]),
                ],
            },
        }];

        let compiled = CompiledRulePatterns::compile(&defs).expect("Compilation failed");
        let data = vec![0x90, 0x55, 0x8B, 0xEC, 0x90, 0x90, 0x90, 0x31, 0xC0, 0xC3];

        let matches = compiled.scan(&data);
        assert!(matches.contains_key("$complex_hex"));
        assert_eq!(matches["$complex_hex"][0].offset, 1);
    }

    #[test]
    fn test_fullword_and_xor() {
        let defs = vec![
            StringDefinition {
                id: "$fw".to_string(),
                pattern: StringPattern::Literal {
                    bytes: b"cmd.exe".to_vec(),
                    ascii: true,
                    wide: false,
                    nocase: false,
                    fullword: true,
                    xor: None,
                    base64: false,
                    base64wide: false,
                },
            },
            StringDefinition {
                id: "$xored".to_string(),
                pattern: StringPattern::Literal {
                    bytes: b"http".to_vec(),
                    ascii: true,
                    wide: false,
                    nocase: false,
                    fullword: false,
                    xor: Some((0x01, 0x7F)),
                    base64: false,
                    base64wide: false,
                },
            },
        ];

        let compiled = CompiledRulePatterns::compile(&defs).expect("Compilation failed");

        // "my_cmd.exe_backup" should NOT match fullword
        let data_negative = b"my_cmd.exe_backup";
        let matches_neg = compiled.scan(data_negative);
        assert!(!matches_neg.contains_key("$fw"));

        // "run cmd.exe now" should match fullword
        let data_positive = b"run cmd.exe now";
        let matches_pos = compiled.scan(data_positive);
        assert!(matches_pos.contains_key("$fw"));

        // Test XOR with key 0x20: b"http" ^ 0x20 = b"HTTP"
        let data_xor = b"test HTTP beacon";
        let matches_xor = compiled.scan(data_xor);
        assert!(matches_xor.contains_key("$xored"));
    }
}
