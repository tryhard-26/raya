// src/extractor/mod.rs
//
// In-Memory C2 Configuration Extraction Subsystem for Raya 2.0
// Extracts operational threat intelligence (C2 servers, ports, sleep times, AES keys,
// onion addresses, and botnet identifiers) from memory and binary artifacts.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExtractedConfig {
    pub family: String,
    pub c2_servers: Vec<String>,
    pub ports: Vec<u16>,
    pub sleep_time_ms: Option<u32>,
    pub jitter_percent: Option<u16>,
    pub user_agent: Option<String>,
    pub pipe_name: Option<String>,
    pub watermark: Option<u32>,
    pub mutex: Option<String>,
    pub crypto_keys: Vec<String>,
    pub dead_drop_resolvers: Vec<String>,
    pub extra: Vec<(String, String)>,
}

impl ExtractedConfig {
    pub fn new(family: &str) -> Self {
        Self {
            family: family.to_string(),
            c2_servers: Vec::new(),
            ports: Vec::new(),
            sleep_time_ms: None,
            jitter_percent: None,
            user_agent: None,
            pipe_name: None,
            watermark: None,
            mutex: None,
            crypto_keys: Vec::new(),
            dead_drop_resolvers: Vec::new(),
            extra: Vec::new(),
        }
    }
}

/// Primary entry point: Extracts all recognized C2 configurations from raw binary data.
pub fn extract_all_configs(data: &[u8]) -> Vec<ExtractedConfig> {
    let mut configs = Vec::new();

    if let Some(cs) = extract_cobalt_strike(data) {
        configs.push(cs);
    }
    if let Some(wc) = extract_wannacry(data) {
        configs.push(wc);
    }
    if let Some(mirai) = extract_mirai(data) {
        configs.push(mirai);
    }
    if let Some(redline) = extract_redline(data) {
        configs.push(redline);
    }
    if let Some(generic) = extract_generic_c2(data) {
        if !generic.c2_servers.is_empty() || !generic.dead_drop_resolvers.is_empty() {
            configs.push(generic);
        }
    }

    configs
}

// ---------------------------------------------------------------------------
// Cobalt Strike Beacon Config Extractor
// ---------------------------------------------------------------------------

pub fn extract_cobalt_strike(data: &[u8]) -> Option<ExtractedConfig> {
    // Cobalt Strike Beacons encrypt the configuration block with either 0x2e (v3) or 0x69 (v4).
    // The decrypted buffer contains repeated Type-Length-Value (TLV) or Type-Type-Length-Value entries.
    // In memory/disk, the config block is typically 1024 to 4096 bytes long.
    for &key in &[0x2eu8, 0x69u8] {
        if let Some(config) = parse_cobalt_strike_with_key(data, key) {
            return Some(config);
        }
    }
    None
}

fn parse_cobalt_strike_with_key(data: &[u8], key: u8) -> Option<ExtractedConfig> {
    if data.len() < 256 {
        return None;
    }

    // Look for repeating XORed patterns characteristic of CS config block
    // Specifically, Type 1 (Beacon Type, short), Type 2 (Port, short), Type 3 (Sleep, int)
    // We scan sliding windows of 1024 bytes decrypted with `key`
    let step = 16;
    let window_size = 2048.min(data.len());

    for offset in (0..data.len().saturating_sub(128)).step_by(step) {
        let end = (offset + window_size).min(data.len());
        let slice = &data[offset..end];

        // Decrypt window with key
        let mut decrypted = vec![0u8; slice.len()];
        for i in 0..slice.len() {
            decrypted[i] = slice[i] ^ key;
        }

        // Try parsing TLV settings
        if let Some(cfg) = parse_cs_tlv(&decrypted, key) {
            return Some(cfg);
        }
    }

    None
}

fn parse_cs_tlv(decrypted: &[u8], xor_key: u8) -> Option<ExtractedConfig> {
    let mut pos = 0;
    let mut config = ExtractedConfig::new(&format!(
        "Cobalt Strike Beacon (XOR Key: 0x{:02x})",
        xor_key
    ));
    let mut valid_entries = 0;

    while pos + 6 <= decrypted.len() {
        let setting_type = u16::from_be_bytes([decrypted[pos], decrypted[pos + 1]]);
        let data_type = u16::from_be_bytes([decrypted[pos + 2], decrypted[pos + 3]]);
        let length = u16::from_be_bytes([decrypted[pos + 4], decrypted[pos + 5]]) as usize;

        if setting_type == 0 && data_type == 0 && length == 0 {
            pos += 6;
            continue;
        }

        // Sanity bounds on CS TLV
        if setting_type > 100 || length > 1024 || pos + 6 + length > decrypted.len() {
            break;
        }

        let val_bytes = &decrypted[pos + 6..pos + 6 + length];

        match setting_type {
            1 if length == 2 => {
                // Beacon Type (0=HTTP, 1=DNS, 2=SMB, 4=TCP)
                let btype = u16::from_be_bytes([val_bytes[0], val_bytes[1]]);
                let desc = match btype {
                    0 => "HTTP",
                    1 => "DNS",
                    2 => "SMB",
                    4 => "TCP",
                    _ => "Custom",
                };
                config
                    .extra
                    .push(("Beacon Type".to_string(), desc.to_string()));
                valid_entries += 1;
            }
            2 if length == 2 => {
                // Port
                let port = u16::from_be_bytes([val_bytes[0], val_bytes[1]]);
                if port > 0 {
                    config.ports.push(port);
                    valid_entries += 1;
                }
            }
            3 if length == 4 => {
                // Sleep time (ms)
                let sleep =
                    u32::from_be_bytes([val_bytes[0], val_bytes[1], val_bytes[2], val_bytes[3]]);
                config.sleep_time_ms = Some(sleep);
                valid_entries += 1;
            }
            5 if length == 2 => {
                // Jitter (%)
                let jitter = u16::from_be_bytes([val_bytes[0], val_bytes[1]]);
                config.jitter_percent = Some(jitter);
                valid_entries += 1;
            }
            7 => {
                // C2 Server string
                let s = extract_ascii_string(val_bytes);
                if !s.is_empty() && (s.contains('.') || s.contains(':') || s.contains('/')) {
                    config.c2_servers.push(s);
                    valid_entries += 1;
                }
            }
            8 => {
                // User-Agent string
                let s = extract_ascii_string(val_bytes);
                if !s.is_empty() {
                    config.user_agent = Some(s);
                    valid_entries += 1;
                }
            }
            9 => {
                // Post URI
                let s = extract_ascii_string(val_bytes);
                if !s.is_empty() {
                    config.extra.push(("Post URI".to_string(), s));
                    valid_entries += 1;
                }
            }
            11 => {
                // Pipe name
                let s = extract_ascii_string(val_bytes);
                if !s.is_empty() {
                    config.pipe_name = Some(s);
                    valid_entries += 1;
                }
            }
            14 if length == 4 => {
                // Watermark
                let wm =
                    u32::from_be_bytes([val_bytes[0], val_bytes[1], val_bytes[2], val_bytes[3]]);
                config.watermark = Some(wm);
                valid_entries += 1;
            }
            _ => {}
        }

        pos += 6 + length;
    }

    if valid_entries >= 3 {
        Some(config)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// WannaCry Extractor
// ---------------------------------------------------------------------------

pub fn extract_wannacry(data: &[u8]) -> Option<ExtractedConfig> {
    let mut config = ExtractedConfig::new("WannaCry Ransomware");
    let mut found = false;

    // Search for killswitch domain
    let killswitch_candidates = [
        "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com",
        "ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.com",
        "ayylmaotjlkjaskdfjkasdjf.com",
    ];

    for domain in &killswitch_candidates {
        if find_subsequence(data, domain.as_bytes()) {
            config.c2_servers.push(format!("http://{}", domain));
            config
                .extra
                .push(("Killswitch Domain".to_string(), domain.to_string()));
            found = true;
        }
    }

    // Search for Onion C2 servers
    let onions = [
        "gx7ekbenv2riucmf.onion",
        "57g7spgrzlojinas.onion",
        "xxlvbrloxvriy2c5.onion",
        "76jdd2ir2embyv47.onion",
        "cwwnhwhlz52maqm7.onion",
    ];

    for onion in &onions {
        if find_subsequence(data, onion.as_bytes()) {
            config.c2_servers.push(onion.to_string());
            found = true;
        }
    }

    // Search for Bitcoin wallet addresses
    let btc_wallets = [
        "13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94",
        "12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw",
        "115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn",
    ];

    for btc in &btc_wallets {
        if find_subsequence(data, btc.as_bytes()) {
            config
                .extra
                .push(("Bitcoin Payment Address".to_string(), btc.to_string()));
            found = true;
        }
    }

    // Search for WannaCry payload archive password
    if find_subsequence(data, b"WNcry@2ol7") {
        config
            .crypto_keys
            .push("WNcry@2ol7 (Payload ZIP Password)".to_string());
        found = true;
    }

    if found {
        Some(config)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Mirai / Mozi Botnet Extractor
// ---------------------------------------------------------------------------

pub fn extract_mirai(data: &[u8]) -> Option<ExtractedConfig> {
    let mut config = ExtractedConfig::new("Mirai / Mozi Botnet");
    let mut found = false;

    // Mirai table decryption key is frequently 0xDE, 0x22, 0x55, 0x5C or 0xDEADBEEF
    let keys = [0xdeu8, 0x22u8, 0x55u8, 0x5cu8];
    for &key in &keys {
        // Mirai table entries are XOR encrypted. Look for common decoded strings:
        // "/bin/busybox", "POST /cdn-cgi/", "REPORT %s:%s", "HTTPFLOOD"
        if let Some(decrypted_c2) = scan_mirai_table(data, key) {
            config.c2_servers.extend(decrypted_c2);
            config
                .crypto_keys
                .push(format!("0x{:02x} (Table XOR Key)", key));
            found = true;
            break;
        }
    }

    // Direct search for unencrypted Mirai indicators
    if find_subsequence(data, b"/bin/busybox MIRAI")
        || find_subsequence(data, b"MIRAI: failed to allocate memory")
        || find_subsequence(data, b"REPORT %s:%s")
    {
        config.extra.push((
            "Botnet Signature".to_string(),
            "Mirai Telnet Scanner".to_string(),
        ));
        found = true;
    }

    if found {
        Some(config)
    } else {
        None
    }
}

fn scan_mirai_table(data: &[u8], key: u8) -> Option<Vec<String>> {
    let mut found_c2 = Vec::new();
    let min_len = 8;
    let mut i = 0;

    while i + min_len < data.len().min(64 * 1024) {
        let mut buf = Vec::new();
        let mut j = i;
        while j < data.len() && buf.len() < 128 {
            let b = data[j] ^ key;
            if (0x20..=0x7e).contains(&b) {
                buf.push(b);
                j += 1;
            } else {
                break;
            }
        }

        if buf.len() >= min_len {
            if let Ok(s) = std::str::from_utf8(&buf) {
                if (s.contains(".com")
                    || s.contains(".net")
                    || s.contains(".org")
                    || s.contains(".cc")
                    || s.contains(".ru"))
                    && (s.contains("c2")
                        || s.contains("cnc")
                        || s.contains("bot")
                        || s.contains("srv"))
                {
                    found_c2.push(s.to_string());
                }
            }
            i = j + 1;
        } else {
            i += 1;
        }
    }

    if !found_c2.is_empty() {
        Some(found_c2)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// RedLine / Vidar Stealer Extractor
// ---------------------------------------------------------------------------

pub fn extract_redline(data: &[u8]) -> Option<ExtractedConfig> {
    let mut config = ExtractedConfig::new("RedLine / Vidar Stealer");
    let mut found = false;

    // RedLine uses Base64 or XOR encoded settings for C2, ID, and Telegram dead-drop
    let redline_markers = [
        b"RedLine.Main" as &[u8],
        b"RedLineClient" as &[u8],
        b"CommandLineUpdate" as &[u8],
        b"StringDecrypt" as &[u8],
    ];

    for marker in &redline_markers {
        if find_subsequence(data, marker) {
            found = true;
            break;
        }
    }

    // Look for Telegram bot / Steam profile dead-drop resolvers
    let patterns = [
        "https://t.me/",
        "https://steamcommunity.com/profiles/",
        "https://discord.com/api/webhooks/",
    ];

    for pat in &patterns {
        if let Some(url) = extract_string_starting_with(data, pat) {
            config.dead_drop_resolvers.push(url);
            found = true;
        }
    }

    if found {
        Some(config)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Generic C2 Extractor (IP:Port, Onion, Webhooks)
// ---------------------------------------------------------------------------

pub fn extract_generic_c2(data: &[u8]) -> Option<ExtractedConfig> {
    let mut config = ExtractedConfig::new("Generic C2 Indicators");
    let mut seen = HashSet::new();

    // Scan for IPv4:Port strings
    let ip_port_regex = regex::bytes::Regex::new(r"(?i)\b((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)):(1\d{4}|[1-9]\d{3}|[1-9]\d{2}|[1-9]\d|[1-9])\b").ok();

    if let Some(re) = ip_port_regex {
        for m in re.find_iter(data) {
            if let Ok(s) = std::str::from_utf8(m.as_bytes()) {
                // Filter out standard localhost and zeros
                if !s.starts_with("127.0.0.1")
                    && !s.starts_with("0.0.0.0")
                    && !s.starts_with("255.255.255.255")
                    && seen.insert(s.to_string())
                {
                    config.c2_servers.push(s.to_string());
                }
            }
        }
    }

    // Scan for .onion addresses
    let onion_regex = regex::bytes::Regex::new(r"(?i)\b([a-z2-7]{16}|[a-z2-7]{56})\.onion\b").ok();
    if let Some(re) = onion_regex {
        for m in re.find_iter(data) {
            if let Ok(s) = std::str::from_utf8(m.as_bytes()) {
                if seen.insert(s.to_string()) {
                    config.c2_servers.push(s.to_string());
                }
            }
        }
    }

    // Scan for webhook resolvers
    let webhook_prefixes = [
        "https://discord.com/api/webhooks/",
        "https://api.telegram.org/bot",
        "https://pastebin.com/raw/",
    ];

    for prefix in &webhook_prefixes {
        if let Some(url) = extract_string_starting_with(data, prefix) {
            if seen.insert(url.clone()) {
                config.dead_drop_resolvers.push(url);
            }
        }
    }

    if !config.c2_servers.is_empty() || !config.dead_drop_resolvers.is_empty() {
        Some(config)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn extract_ascii_string(bytes: &[u8]) -> String {
    let mut s = String::new();
    for &b in bytes {
        if (0x20..=0x7e).contains(&b) {
            s.push(b as char);
        } else if b == 0 {
            break;
        }
    }
    s
}

fn extract_string_starting_with(data: &[u8], prefix: &str) -> Option<String> {
    let pbytes = prefix.as_bytes();
    for i in 0..data.len().saturating_sub(pbytes.len()) {
        if &data[i..i + pbytes.len()] == pbytes {
            let mut j = i;
            let mut buf = Vec::new();
            while j < data.len() && data[j] >= 0x21 && data[j] <= 0x7e && buf.len() < 256 {
                buf.push(data[j]);
                j += 1;
            }
            if let Ok(s) = String::from_utf8(buf) {
                return Some(s);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_wannacry_config() {
        let mut mock_data = Vec::new();
        mock_data.extend_from_slice(b"MZ\x90\x00\x03\x00\x00\x00");
        mock_data.extend_from_slice(b"Some random padding...");
        mock_data.extend_from_slice(b"http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com\0");
        mock_data.extend_from_slice(b"gx7ekbenv2riucmf.onion\0");
        mock_data.extend_from_slice(b"13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94\0");
        mock_data.extend_from_slice(b"WNcry@2ol7\0");

        let configs = extract_all_configs(&mock_data);
        assert!(!configs.is_empty());
        let wc = configs
            .iter()
            .find(|c| c.family.contains("WannaCry"))
            .expect("WannaCry not found");
        assert!(wc
            .c2_servers
            .iter()
            .any(|s| s.contains("iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com")));
        assert!(wc
            .c2_servers
            .iter()
            .any(|s| s.contains("gx7ekbenv2riucmf.onion")));
        assert!(wc.crypto_keys.iter().any(|k| k.contains("WNcry@2ol7")));
    }

    #[test]
    fn test_extract_generic_ip_port_and_onion() {
        let data =
            b"Header... connecting to 198.51.100.42:8443 and ex3lplq5p5qomc2a.onion for commands";
        let configs = extract_all_configs(data);
        let gen = configs
            .iter()
            .find(|c| c.family.contains("Generic C2"))
            .expect("Generic C2 not found");
        assert!(gen.c2_servers.contains(&"198.51.100.42:8443".to_string()));
        assert!(gen
            .c2_servers
            .contains(&"ex3lplq5p5qomc2a.onion".to_string()));
    }
}
