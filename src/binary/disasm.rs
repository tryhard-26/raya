use iced_x86::{Decoder, DecoderOptions, FlowControl, Mnemonic, OpKind, Register};
use std::collections::BTreeMap;

/// Represents a disassembled basic block of straight-line instructions.
#[derive(Debug, Clone, PartialEq)]
pub struct BasicBlock {
    pub start_ip: u64,
    pub end_ip: u64,
    pub mnemonics: Vec<String>,
    pub immediates: Vec<u64>,
    pub terminates_with_call: bool,
    pub terminates_with_return: bool,
}

/// Represents a scoped function bounded by entry/prologue and return instructions.
#[derive(Debug, Clone, PartialEq)]
pub struct ScopedFunction {
    pub start_ip: u64,
    pub end_ip: u64,
    pub mnemonics: Vec<String>,
    pub immediates: Vec<u64>,
}

/// Represents a matched API call argument pattern.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ApiCallArgMatch {
    pub api_name: String,
    pub argument_name: String,
    pub value: u64,
    pub constant_name: String,
    pub call_ip: u64,
}

/// Represents an extracted stack-constructed string.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StackString {
    pub value: String,
    pub offset: u64,
    pub is_wide: bool,
}

/// Resolves standard Windows / native security API argument constants based on the target API.
pub fn resolve_constant_name(api_name: &str, val: u64) -> Option<(&'static str, &'static str)> {
    let lower = api_name.to_ascii_lowercase();
    if lower.contains("process") {
        match val {
            0x001F0FFF => Some(("dwDesiredAccess", "PROCESS_ALL_ACCESS")),
            0x00100000 => Some(("dwDesiredAccess", "SYNCHRONIZE")),
            0x0002 => Some(("dwDesiredAccess", "PROCESS_CREATE_THREAD")),
            0x0008 => Some(("dwDesiredAccess", "PROCESS_VM_OPERATION")),
            0x0010 => Some(("dwDesiredAccess", "PROCESS_VM_READ")),
            0x0020 => Some(("dwDesiredAccess", "PROCESS_VM_WRITE")),
            0x4 => Some(("dwCreationFlags", "CREATE_SUSPENDED")),
            _ => None,
        }
    } else {
        match val {
            0x40 => Some(("flProtect", "PAGE_EXECUTE_READWRITE")),
            0x20 => Some(("flProtect", "PAGE_EXECUTE_READ")),
            0x10 => Some(("flProtect", "PAGE_EXECUTE")),
            0x04 => Some(("flProtect", "PAGE_READWRITE")),
            0x02 => Some(("flProtect", "PAGE_READONLY")),
            0x01 => Some(("flProtect", "PAGE_NOACCESS")),
            0x1000 => Some(("flAllocationType", "MEM_COMMIT")),
            0x2000 => Some(("flAllocationType", "MEM_RESERVE")),
            0x8000 => Some(("dwFreeType", "MEM_RELEASE")),
            0x001F0FFF => Some(("dwDesiredAccess", "PROCESS_ALL_ACCESS")),
            _ => None,
        }
    }
}

/// Extracts straight-line basic blocks from machine code.
pub fn extract_basic_blocks(code: &[u8], bitness: u32, base_ip: u64) -> Vec<BasicBlock> {
    if code.is_empty() {
        return Vec::new();
    }

    let mut blocks = Vec::new();
    let mut decoder = Decoder::with_ip(bitness, code, base_ip, DecoderOptions::NONE);

    let mut current_mnemonics = Vec::new();
    let mut current_immediates = Vec::new();
    let mut block_start_ip = base_ip;
    let mut last_ip = base_ip;

    while decoder.can_decode() {
        let instr = decoder.decode();
        let ip = instr.ip();
        let mnemonic_str = format!("{:?}", instr.mnemonic()).to_ascii_lowercase();

        for op in 0..instr.op_count() {
            match instr.op_kind(op) {
                OpKind::Immediate8 => current_immediates.push(instr.immediate8() as u64),
                OpKind::Immediate16 => current_immediates.push(instr.immediate16() as u64),
                OpKind::Immediate32 => current_immediates.push(instr.immediate32() as u64),
                OpKind::Immediate64 => current_immediates.push(instr.immediate64()),
                OpKind::Immediate8to16 => current_immediates.push(instr.immediate8to16() as u64),
                OpKind::Immediate8to32 => current_immediates.push(instr.immediate8to32() as u64),
                OpKind::Immediate8to64 => current_immediates.push(instr.immediate8to64() as u64),
                OpKind::Immediate32to64 => current_immediates.push(instr.immediate32to64() as u64),
                _ => {}
            }
        }

        current_mnemonics.push(mnemonic_str);
        last_ip = ip + instr.len() as u64;

        let flow = instr.flow_control();
        let terminates_block = matches!(
            flow,
            FlowControl::UnconditionalBranch
                | FlowControl::ConditionalBranch
                | FlowControl::Return
                | FlowControl::IndirectBranch
                | FlowControl::Interrupt
                | FlowControl::Call
                | FlowControl::IndirectCall
        );

        if terminates_block {
            blocks.push(BasicBlock {
                start_ip: block_start_ip,
                end_ip: last_ip,
                mnemonics: std::mem::take(&mut current_mnemonics),
                immediates: std::mem::take(&mut current_immediates),
                terminates_with_call: matches!(flow, FlowControl::Call | FlowControl::IndirectCall),
                terminates_with_return: matches!(flow, FlowControl::Return),
            });
            block_start_ip = last_ip;
        }
    }

    if !current_mnemonics.is_empty() {
        blocks.push(BasicBlock {
            start_ip: block_start_ip,
            end_ip: last_ip,
            mnemonics: current_mnemonics,
            immediates: current_immediates,
            terminates_with_call: false,
            terminates_with_return: false,
        });
    }

    blocks
}

/// Checks if any basic block contains the consecutive sequence of instruction mnemonics.
pub fn has_basic_block_sequence(code: &[u8], bitness: u32, target_sequence: &[&str]) -> bool {
    find_basic_block_sequence(code, bitness, 0x1000, target_sequence).is_some()
}

/// Finds the start address of the first basic block containing the consecutive sequence of instruction mnemonics.
pub fn find_basic_block_sequence(
    code: &[u8],
    bitness: u32,
    base_ip: u64,
    target_sequence: &[&str],
) -> Option<u64> {
    if target_sequence.is_empty() {
        return None;
    }
    let target_lower: Vec<String> = target_sequence
        .iter()
        .map(|s| s.to_ascii_lowercase())
        .collect();

    let blocks = extract_basic_blocks(code, bitness, base_ip);
    for bb in blocks {
        if bb.mnemonics.len() < target_lower.len() {
            continue;
        }
        for window in bb.mnemonics.windows(target_lower.len()) {
            if window == target_lower.as_slice() {
                return Some(bb.start_ip);
            }
        }
    }
    None
}

/// Checks if any basic block contains ALL specified instruction mnemonics (regardless of order).
pub fn has_basic_block_all(code: &[u8], bitness: u32, required: &[&str]) -> bool {
    find_basic_block_all(code, bitness, 0x1000, required).is_some()
}

/// Finds the start address of the first basic block containing ALL specified instruction mnemonics.
pub fn find_basic_block_all(
    code: &[u8],
    bitness: u32,
    base_ip: u64,
    required: &[&str],
) -> Option<u64> {
    if required.is_empty() {
        return None;
    }
    let target_lower: Vec<String> = required.iter().map(|s| s.to_ascii_lowercase()).collect();
    let blocks = extract_basic_blocks(code, bitness, base_ip);

    for bb in blocks {
        let has_all = target_lower.iter().all(|req| bb.mnemonics.contains(req));
        if has_all {
            return Some(bb.start_ip);
        }
    }
    None
}

/// Extracts functions bounded by function prologues and returns.
pub fn extract_functions(code: &[u8], bitness: u32, base_ip: u64) -> Vec<ScopedFunction> {
    let blocks = extract_basic_blocks(code, bitness, base_ip);
    let mut functions = Vec::new();

    let mut current_mnemonics = Vec::new();
    let mut current_immediates = Vec::new();
    let mut func_start_ip = base_ip;
    let mut func_end_ip = base_ip;

    for bb in blocks {
        if current_mnemonics.is_empty() {
            func_start_ip = bb.start_ip;
        }
        current_mnemonics.extend(bb.mnemonics.clone());
        current_immediates.extend(bb.immediates.clone());
        func_end_ip = bb.end_ip;

        if bb.terminates_with_return {
            functions.push(ScopedFunction {
                start_ip: func_start_ip,
                end_ip: func_end_ip,
                mnemonics: std::mem::take(&mut current_mnemonics),
                immediates: std::mem::take(&mut current_immediates),
            });
        }
    }

    if !current_mnemonics.is_empty() {
        functions.push(ScopedFunction {
            start_ip: func_start_ip,
            end_ip: func_end_ip,
            mnemonics: current_mnemonics,
            immediates: current_immediates,
        });
    }

    functions
}

/// Finds the start address of the first function containing the consecutive sequence of instruction mnemonics.
pub fn find_function_sequence(
    code: &[u8],
    bitness: u32,
    base_ip: u64,
    target_sequence: &[&str],
) -> Option<u64> {
    if target_sequence.is_empty() {
        return None;
    }
    let target_lower: Vec<String> = target_sequence
        .iter()
        .map(|s| s.to_ascii_lowercase())
        .collect();

    let funcs = extract_functions(code, bitness, base_ip);
    for func in funcs {
        if func.mnemonics.len() < target_lower.len() {
            continue;
        }
        for window in func.mnemonics.windows(target_lower.len()) {
            if window == target_lower.as_slice() {
                return Some(func.start_ip);
            }
        }
    }
    None
}

/// Tracks whether a target API call is preceded within its basic block by a specific constant argument.
pub fn detect_api_call_arguments(
    code: &[u8],
    bitness: u32,
    base_ip: u64,
    target_api: &str,
    target_val: u64,
) -> Option<ApiCallArgMatch> {
    let blocks = extract_basic_blocks(code, bitness, base_ip);
    for bb in blocks {
        if (bb.terminates_with_call || bb.mnemonics.iter().any(|m| m == "call"))
            && bb.immediates.contains(&target_val)
        {
            let (arg_name, const_name) = resolve_constant_name(target_api, target_val)
                .unwrap_or(("dwValue", "UNKNOWN_CONSTANT"));
            return Some(ApiCallArgMatch {
                api_name: target_api.to_string(),
                argument_name: arg_name.to_string(),
                value: target_val,
                constant_name: const_name.to_string(),
                call_ip: bb.end_ip,
            });
        }
    }
    None
}

/// Scans code bytes for a consecutive sequence of instruction mnemonics.
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

fn is_stack_register(reg: Register) -> bool {
    matches!(
        reg,
        Register::ESP | Register::EBP | Register::RSP | Register::RBP
    )
}

/// Automatically extracts stack-constructed strings from machine code instructions.
///
/// Malware frequently obfuscates static strings by building them dynamically on the stack
/// using sequential byte/word/dword immediate stores (`mov [ebp-X], 'c'`, `mov [esp+Y], 0x...`).
/// This function decodes linear instruction streams, tracks memory writes against stack base
/// registers (EBP/ESP/RBP/RSP), and reconstructs contiguous ASCII and UTF-16LE strings.
pub fn extract_stack_strings(code: &[u8], bitness: u32, base_ip: u64) -> Vec<StackString> {
    if code.is_empty() {
        return Vec::new();
    }

    let mut decoder = Decoder::with_ip(bitness, code, base_ip, DecoderOptions::NONE);
    let mut results = Vec::new();

    let mut stack_writes: BTreeMap<i64, (u8, u64)> = BTreeMap::new();

    while decoder.can_decode() {
        let instr = decoder.decode();

        let is_mov = instr.mnemonic() == Mnemonic::Mov;
        let is_stack_mem_dst = instr.op_count() >= 2
            && instr.op_kind(0) == OpKind::Memory
            && is_stack_register(instr.memory_base())
            && instr.memory_index() == Register::None;

        if is_mov && is_stack_mem_dst {
            let base_disp = if bitness == 32 {
                (instr.memory_displacement64() as u32 as i32) as i64
            } else {
                instr.memory_displacement64() as i64
            };
            let ip = instr.ip();

            let bytes: Option<Vec<u8>> = match instr.op_kind(1) {
                OpKind::Immediate8 => Some(vec![instr.immediate8()]),
                OpKind::Immediate16 => Some(instr.immediate16().to_le_bytes().to_vec()),
                OpKind::Immediate32 => Some(instr.immediate32().to_le_bytes().to_vec()),
                OpKind::Immediate64 => Some(instr.immediate64().to_le_bytes().to_vec()),
                OpKind::Immediate8to16 => {
                    Some((instr.immediate8to16() as u16).to_le_bytes().to_vec())
                }
                OpKind::Immediate8to32 => {
                    Some((instr.immediate8to32() as u32).to_le_bytes().to_vec())
                }
                OpKind::Immediate8to64 => {
                    Some((instr.immediate8to64() as u64).to_le_bytes().to_vec())
                }
                OpKind::Immediate32to64 => {
                    Some((instr.immediate32to64() as u64).to_le_bytes().to_vec())
                }
                _ => None,
            };

            if let Some(bytes) = bytes {
                for (offset_idx, &b) in bytes.iter().enumerate() {
                    stack_writes.insert(base_disp + offset_idx as i64, (b, ip));
                }
            }
        }

        let flow = instr.flow_control();
        let is_branch = matches!(
            flow,
            FlowControl::UnconditionalBranch
                | FlowControl::ConditionalBranch
                | FlowControl::Return
                | FlowControl::IndirectBranch
                | FlowControl::Interrupt
        );

        if is_branch && !stack_writes.is_empty() {
            extract_strings_from_map(&stack_writes, &mut results);
            stack_writes.clear();
        }
    }

    if !stack_writes.is_empty() {
        extract_strings_from_map(&stack_writes, &mut results);
    }

    let mut deduped = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for s in results {
        if seen.insert(s.value.clone()) {
            deduped.push(s);
        }
    }

    deduped
}

fn extract_strings_from_map(map: &BTreeMap<i64, (u8, u64)>, results: &mut Vec<StackString>) {
    if map.is_empty() {
        return;
    }

    let mut current_run: Vec<(i64, u8, u64)> = Vec::new();

    for (&disp, &(byte, ip)) in map {
        if let Some(&(prev_disp, _, _)) = current_run.last() {
            if disp != prev_disp + 1 {
                process_buffer(&current_run, results);
                current_run.clear();
            }
        }
        current_run.push((disp, byte, ip));
    }

    if !current_run.is_empty() {
        process_buffer(&current_run, results);
    }
}

fn process_buffer(run: &[(i64, u8, u64)], results: &mut Vec<StackString>) {
    if run.len() < 4 {
        return;
    }

    let bytes: Vec<u8> = run.iter().map(|&(_, b, _)| b).collect();

    // 1. ASCII extraction
    let mut ascii_start = None;
    for (i, &b) in bytes.iter().enumerate() {
        let is_printable = (0x20..=0x7E).contains(&b) || b == b'\t' || b == b'\r' || b == b'\n';
        if is_printable {
            if ascii_start.is_none() {
                ascii_start = Some(i);
            }
        } else if let Some(start) = ascii_start {
            let slice = &bytes[start..i];
            if slice.len() >= 4 {
                if let Ok(s) = std::str::from_utf8(slice) {
                    results.push(StackString {
                        value: s.to_string(),
                        offset: run[start].2,
                        is_wide: false,
                    });
                }
            }
            ascii_start = None;
        }
    }
    if let Some(start) = ascii_start {
        let slice = &bytes[start..];
        if slice.len() >= 4 {
            if let Ok(s) = std::str::from_utf8(slice) {
                results.push(StackString {
                    value: s.to_string(),
                    offset: run[start].2,
                    is_wide: false,
                });
            }
        }
    }

    // 2. UTF-16LE extraction
    if bytes.len() >= 8 {
        let mut u16_chars = Vec::new();
        let mut u16_start = None;
        for i in (0..bytes.len().saturating_sub(1)).step_by(2) {
            let b0 = bytes[i];
            let b1 = bytes[i + 1];
            if b1 == 0 && ((0x20..=0x7E).contains(&b0) || b0 == b'\t' || b0 == b'\r' || b0 == b'\n')
            {
                if u16_start.is_none() {
                    u16_start = Some(i);
                }
                u16_chars.push(b0 as char);
            } else {
                if u16_chars.len() >= 4 {
                    let s: String = u16_chars.iter().collect();
                    let start_idx = u16_start.unwrap_or(0);
                    results.push(StackString {
                        value: s,
                        offset: run[start_idx].2,
                        is_wide: true,
                    });
                }
                u16_chars.clear();
                u16_start = None;
            }
        }
        if u16_chars.len() >= 4 {
            let s: String = u16_chars.iter().collect();
            let start_idx = u16_start.unwrap_or(0);
            results.push(StackString {
                value: s,
                offset: run[start_idx].2,
                is_wide: true,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disasm_sequence() {
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

    #[test]
    fn test_basic_block_scoping() {
        // Basic block 1: mov eax, 1; xor ebx, ebx; jmp +5
        // Basic block 2: push 0x40; call edx
        let code = [
            0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
            0x31, 0xDB, // xor ebx, ebx
            0xEB, 0x05, // jmp +5
            0x6A, 0x40, // push 0x40 (PAGE_EXECUTE_READWRITE)
            0xFF, 0xD2, // call edx
        ];

        let bbs = extract_basic_blocks(&code, 32, 0x401000);
        assert_eq!(bbs.len(), 2);

        // Sequence spanning across jump should NOT match in same basic block
        assert!(!has_basic_block_sequence(
            &code,
            32,
            &["xor", "jmp", "push"]
        ));

        // Sequences within basic block match
        assert!(has_basic_block_sequence(&code, 32, &["mov", "xor", "jmp"]));
        assert!(has_basic_block_sequence(&code, 32, &["push", "call"]));
    }

    #[test]
    fn test_api_call_argument_tracking() {
        // x86 32-bit: push 0x40 (PAGE_EXECUTE_READWRITE); push 0x1000 (MEM_COMMIT); call edx
        let code = [
            0x6A, 0x40, // push 0x40
            0x68, 0x00, 0x10, 0x00, 0x00, // push 0x1000
            0xFF, 0xD2, // call edx
        ];

        let res = detect_api_call_arguments(&code, 32, 0x401000, "VirtualAlloc", 0x40);
        assert!(res.is_some());
        let hit = res.unwrap();
        assert_eq!(hit.api_name, "VirtualAlloc");
        assert_eq!(hit.value, 0x40);
        assert_eq!(hit.constant_name, "PAGE_EXECUTE_READWRITE");
        assert_eq!(hit.argument_name, "flProtect");
    }

    #[test]
    fn test_stack_string_extraction() {
        // x86 32-bit:
        // mov byte ptr [ebp-4], 'c' (0x63)
        // mov byte ptr [ebp-3], 'm' (0x6D)
        // mov byte ptr [ebp-2], 'd' (0x64)
        // mov byte ptr [ebp-1], '.' (0x2E)
        // mov byte ptr [ebp+0], 'e' (0x65)
        // mov byte ptr [ebp+1], 'x' (0x78)
        // mov byte ptr [ebp+2], 'e' (0x65)
        // mov byte ptr [ebp+3], 0x00
        let code = [
            0xC6, 0x45, 0xFC, 0x63, // mov byte ptr [ebp-4], 'c'
            0xC6, 0x45, 0xFD, 0x6D, // mov byte ptr [ebp-3], 'm'
            0xC6, 0x45, 0xFE, 0x64, // mov byte ptr [ebp-2], 'd'
            0xC6, 0x45, 0xFF, 0x2E, // mov byte ptr [ebp-1], '.'
            0xC6, 0x45, 0x00, 0x65, // mov byte ptr [ebp+0], 'e'
            0xC6, 0x45, 0x01, 0x78, // mov byte ptr [ebp+1], 'x'
            0xC6, 0x45, 0x02, 0x65, // mov byte ptr [ebp+2], 'e'
            0xC6, 0x45, 0x03, 0x00, // mov byte ptr [ebp+3], 0
        ];

        let stack_strings = extract_stack_strings(&code, 32, 0x401000);
        assert_eq!(stack_strings.len(), 1);
        assert_eq!(stack_strings[0].value, "cmd.exe");
        assert!(!stack_strings[0].is_wide);
    }

    #[test]
    fn test_stack_string_dword_64bit() {
        // x86_64:
        // mov dword ptr [rsp], 0x70747468 ("http")
        // mov dword ptr [rsp+4], 0x002F2F3A ("://\0")
        let code = [
            0xC7, 0x04, 0x24, 0x68, 0x74, 0x74, 0x70, // mov dword ptr [rsp], 0x70747468
            0xC7, 0x44, 0x24, 0x04, 0x3A, 0x2F, 0x2F,
            0x00, // mov dword ptr [rsp+4], 0x002F2F3A
        ];

        let stack_strings = extract_stack_strings(&code, 64, 0x140001000);
        assert_eq!(stack_strings.len(), 1);
        assert_eq!(stack_strings[0].value, "http://");
        assert!(!stack_strings[0].is_wide);
    }
}
