use iced_x86::{Decoder, DecoderOptions};

/// Scans code bytes for a consecutive sequence of instruction mnemonics.
/// For example: ["mov", "xor", "call"] matches MOV ... followed by XOR ... followed by CALL ...
pub fn has_mnemonic_sequence(code: &[u8], bitness: u32, target_sequence: &[&str]) -> bool {
    if code.is_empty() || target_sequence.is_empty() {
        return false;
    }

    let mut decoder = Decoder::with_ip(bitness, code, 0x1000, DecoderOptions::NONE);
    let mut seq_idx = 0;
    let target_lower: Vec<String> = target_sequence
        .iter()
        .map(|s| s.to_ascii_lowercase())
        .collect();

    while decoder.can_decode() {
        let instr = decoder.decode();
        let mnemonic_str = format!("{:?}", instr.mnemonic()).to_ascii_lowercase();

        if mnemonic_str == target_lower[seq_idx] {
            seq_idx += 1;
            if seq_idx == target_lower.len() {
                return true;
            }
        } else if seq_idx > 0 {
            // Check if current instruction restarts the sequence
            if mnemonic_str == target_lower[0] {
                seq_idx = 1;
            } else {
                seq_idx = 0;
            }
        }
    }

    false
}

/// Checks if any instruction in the code has the target mnemonic (e.g. "syscall", "rdtsc", "cpuid").
pub fn has_mnemonic(code: &[u8], bitness: u32, target: &str) -> bool {
    if code.is_empty() {
        return false;
    }

    let target_lower = target.to_ascii_lowercase();
    let mut decoder = Decoder::with_ip(bitness, code, 0x1000, DecoderOptions::NONE);

    while decoder.can_decode() {
        let instr = decoder.decode();
        let mnemonic_str = format!("{:?}", instr.mnemonic()).to_ascii_lowercase();
        if mnemonic_str == target_lower {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disasm_sequence() {
        // x86_64 machine code for:
        // mov eax, 1; xor ebx, ebx; call 0x1010
        let code = [
            0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
            0x31, 0xDB, // xor ebx, ebx
            0xE8, 0x09, 0x00, 0x00, 0x00, // call +9
        ];

        assert!(has_mnemonic_sequence(&code, 64, &["mov", "xor", "call"]));
        assert!(!has_mnemonic_sequence(&code, 64, &["call", "mov"]));
        assert!(has_mnemonic(&code, 64, "xor"));
        assert!(!has_mnemonic(&code, 64, "syscall"));
    }
}
