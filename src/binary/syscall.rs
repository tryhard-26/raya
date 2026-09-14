//! # Direct & Indirect Syscall Evasion Detector
//!
//! Scans disassembled machine code for direct and indirect system call stubs
//! commonly utilized by advanced loaders (e.g. Cobalt Strike, Havoc, Brute Ratel,
//! Hell's Gate, Halo's Gate, Tartarus Gate, SysWhispers2/3) to bypass user-mode
//! EDR API hooks in `ntdll.dll`.

use iced_x86::{Instruction, Mnemonic, OpKind, Register};

/// Categorization of the detected system call stub.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SyscallType {
    /// Inlined direct kernel transition (`syscall` / `sysenter` instruction present in binary).
    Direct,
    /// Trampoline setting up arguments and jumping to a `syscall` gadget in `ntdll.dll`.
    Indirect,
    /// WoW64 or legacy interrupt dispatch (`int 0x2E`).
    LegacyInterrupt,
}

/// Information about a detected system call invocation stub.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SyscallStub {
    /// Virtual address or offset where the stub was located.
    pub address: u64,
    /// System Service Number (SSN) loaded into EAX/RAX, if statically identifiable.
    pub ssn: Option<u32>,
    /// Estimated Windows NT API name based on common SSN tables (e.g. "NtAllocateVirtualMemory").
    pub estimated_api: Option<String>,
    /// Categorization (Direct, Indirect, or Legacy).
    pub stub_type: SyscallType,
    /// Human-readable disassembly representation of the stub sequence.
    pub disassembly: String,
}

/// Maps common Windows 10/11 System Service Numbers (SSNs) to their corresponding NT APIs.
pub fn map_ssn_to_api(ssn: u32) -> Option<&'static str> {
    match ssn {
        0x18 | 0x15 | 0x1B => Some("NtAllocateVirtualMemory"),
        0x3A | 0x3B | 0x3F => Some("NtWriteVirtualMemory"),
        0x50 | 0x51 | 0x4D => Some("NtProtectVirtualMemory"),
        0xC2 | 0xC7 | 0xBE | 0xC1 => Some("NtCreateThreadEx"),
        0x45 | 0x44 | 0x48 => Some("NtQueueApcThread"),
        0x26 | 0x25 | 0x28 => Some("NtOpenProcess"),
        0x23 | 0x2A | 0x2C => Some("NtTerminateProcess"),
        0x35 | 0x36 => Some("NtFreeVirtualMemory"),
        0x19 | 0x1A => Some("NtMapViewOfSection"),
        0x57 | 0x58 => Some("NtUnmapViewOfSection"),
        _ => None,
    }
}

/// Scans pre-decoded instructions for direct and indirect syscall stubs.
pub fn detect_syscall_stubs(instructions: &[Instruction]) -> Vec<SyscallStub> {
    let mut stubs = Vec::new();
    if instructions.is_empty() {
        return stubs;
    }

    for (idx, instr) in instructions.iter().enumerate() {
        // 1. Check for direct `syscall` (x64), `sysenter` (x86), or `int 0x2e`
        let is_direct_syscall = instr.mnemonic() == Mnemonic::Syscall;
        let is_sysenter = instr.mnemonic() == Mnemonic::Sysenter;
        let is_int_2e = instr.mnemonic() == Mnemonic::Int && instr.immediate8() == 0x2E;

        if is_direct_syscall || is_sysenter || is_int_2e {
            let stub_type = if is_int_2e {
                SyscallType::LegacyInterrupt
            } else {
                SyscallType::Direct
            };

            // Inspect the preceding 1-4 instructions for `mov eax, <SSN>` and `mov r10, rcx`
            let start_idx = idx.saturating_sub(4);
            let window = &instructions[start_idx..=idx];

            let mut ssn = None;
            let mut has_r10_rcx = false;
            let mut disasm_lines = Vec::new();

            for prev in window {
                disasm_lines.push(format!("{}", prev));

                // Check for `mov r10, rcx`
                if prev.mnemonic() == Mnemonic::Mov
                    && prev.op0_register() == Register::R10
                    && prev.op1_register() == Register::RCX
                {
                    has_r10_rcx = true;
                }

                // Check for `mov eax, <imm>` or `mov rax, <imm>`
                if prev.mnemonic() == Mnemonic::Mov
                    && (prev.op0_register() == Register::EAX
                        || prev.op0_register() == Register::RAX)
                    && prev.op1_kind() == OpKind::Immediate32
                {
                    ssn = Some(prev.immediate32());
                } else if prev.mnemonic() == Mnemonic::Mov
                    && (prev.op0_register() == Register::EAX
                        || prev.op0_register() == Register::RAX)
                    && prev.op1_kind() == OpKind::Immediate8to32
                {
                    ssn = Some(prev.immediate8to32() as u32);
                }
            }

            let estimated_api = ssn.and_then(map_ssn_to_api).map(String::from);

            // Record stub if it has the SSN or the classic `mov r10, rcx` pattern
            if ssn.is_some() || has_r10_rcx || is_direct_syscall {
                stubs.push(SyscallStub {
                    address: instructions[start_idx].ip(),
                    ssn,
                    estimated_api,
                    stub_type,
                    disassembly: disasm_lines.join(" ; "),
                });
            }
        }

        // 2. Check for Indirect Syscall Trampoline
        // Pattern: `mov r10, rcx; mov eax, <SSN>; ... jmp r11` (or jmp [rip+offset])
        if instr.mnemonic() == Mnemonic::Jmp
            && (instr.op0_kind() == OpKind::Register || instr.op0_kind() == OpKind::Memory)
            && instr.op0_register() != Register::None
        {
            let start_idx = idx.saturating_sub(4);
            let window = &instructions[start_idx..=idx];

            let mut ssn = None;
            let mut has_r10_rcx = false;
            let mut disasm_lines = Vec::new();

            for prev in window {
                disasm_lines.push(format!("{}", prev));
                if prev.mnemonic() == Mnemonic::Mov
                    && prev.op0_register() == Register::R10
                    && prev.op1_register() == Register::RCX
                {
                    has_r10_rcx = true;
                }
                if prev.mnemonic() == Mnemonic::Mov
                    && (prev.op0_register() == Register::EAX
                        || prev.op0_register() == Register::RAX)
                {
                    if prev.op1_kind() == OpKind::Immediate32 {
                        ssn = Some(prev.immediate32());
                    } else if prev.op1_kind() == OpKind::Immediate8to32 {
                        ssn = Some(prev.immediate8to32() as u32);
                    }
                }
            }

            if has_r10_rcx && ssn.is_some() {
                let estimated_api = ssn.and_then(map_ssn_to_api).map(String::from);
                stubs.push(SyscallStub {
                    address: instructions[start_idx].ip(),
                    ssn,
                    estimated_api,
                    stub_type: SyscallType::Indirect,
                    disassembly: disasm_lines.join(" ; "),
                });
            }
        }
    }

    stubs
}

/// Scans ARM64 machine code for direct system call transitions (`SVC #0` / `SVC #0x80`).
pub fn detect_arm64_syscall_stubs(code: &[u8], base_ip: u64, is_darwin: bool) -> Vec<SyscallStub> {
    let mut stubs = Vec::new();
    if code.len() < 4 {
        return stubs;
    }

    let num_words = code.len() / 4;
    for i in 0..num_words {
        let offset = i * 4;
        let inst = u32::from_le_bytes([
            code[offset],
            code[offset + 1],
            code[offset + 2],
            code[offset + 3],
        ]);
        let ip = base_ip + offset as u64;

        // Check for SVC instruction: bits 31..21 = 0b11010100000 (0xD4000000), bits 4..0 = 0b00001 (0x01)
        if (inst & 0xFFE0001F) == 0xD4000001 {
            let svc_imm = (inst >> 5) & 0xFFFF;

            // Look back up to 4 instructions for SSN loaded into x16 (Darwin), x8 (Linux), or x0
            let start_idx = i.saturating_sub(4);
            let mut ssn = None;
            let mut disasm_lines = Vec::new();

            for j in start_idx..i {
                let prev_off = j * 4;
                let prev_inst = u32::from_le_bytes([
                    code[prev_off],
                    code[prev_off + 1],
                    code[prev_off + 2],
                    code[prev_off + 3],
                ]);

                // MOVZ Xd, #imm16: bits 31..23 = 0b110100101 (0xD2800000)
                if (prev_inst & 0xFF800000) == 0xD2800000 {
                    let rd = prev_inst & 0x1F;
                    let imm = (prev_inst >> 5) & 0xFFFF;
                    if (is_darwin && rd == 16) || (!is_darwin && (rd == 8 || rd == 16)) {
                        ssn = Some(imm);
                        disasm_lines.push(format!("mov x{}, #0x{:x}", rd, imm));
                    }
                }
                // MOVZ Wd, #imm16: bits 31..23 = 0b010100101 (0x52800000)
                else if (prev_inst & 0xFF800000) == 0x52800000 {
                    let rd = prev_inst & 0x1F;
                    let imm = (prev_inst >> 5) & 0xFFFF;
                    if (is_darwin && rd == 16) || (!is_darwin && (rd == 8 || rd == 16)) {
                        ssn = Some(imm);
                        disasm_lines.push(format!("mov w{}, #0x{:x}", rd, imm));
                    }
                }
            }

            disasm_lines.push(format!("svc #0x{:x}", svc_imm));

            let estimated_api = if is_darwin {
                ssn.and_then(map_darwin_arm64_syscall).map(|s| s.to_string())
            } else {
                ssn.and_then(map_linux_arm64_syscall).map(|s| s.to_string())
            };

            stubs.push(SyscallStub {
                address: ip,
                ssn,
                estimated_api,
                stub_type: SyscallType::Direct,
                disassembly: disasm_lines.join("; "),
            });
        }
    }

    stubs
}

pub fn map_darwin_arm64_syscall(ssn: u32) -> Option<&'static str> {
    match ssn {
        1 => Some("sys_exit"),
        2 => Some("sys_fork"),
        3 => Some("sys_read"),
        4 => Some("sys_write"),
        5 => Some("sys_open"),
        6 => Some("sys_close"),
        7 => Some("sys_wait4"),
        20 => Some("sys_getpid"),
        73 => Some("sys_munmap"),
        74 => Some("sys_mprotect"),
        197 => Some("sys_mmap"),
        202 => Some("sys_sysctl"),
        338 => Some("sys_proc_info"),
        _ => None,
    }
}

pub fn map_linux_arm64_syscall(ssn: u32) -> Option<&'static str> {
    match ssn {
        56 => Some("openat"),
        57 => Some("close"),
        63 => Some("read"),
        64 => Some("write"),
        93 => Some("exit"),
        94 => Some("exit_group"),
        220 => Some("clone"),
        221 => Some("execve"),
        222 => Some("mmap"),
        226 => Some("mprotect"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::{Decoder, DecoderOptions};

    #[test]
    fn test_direct_syscall_detection() {
        // mov r10, rcx; mov eax, 0x18; syscall; ret
        let code = [
            0x49, 0x89, 0xCA, // mov r10, rcx
            0xB8, 0x18, 0x00, 0x00, 0x00, // mov eax, 0x18 (NtAllocateVirtualMemory)
            0x0F, 0x05, // syscall
            0xC3, // ret
        ];

        let mut decoder = Decoder::with_ip(64, &code, 0x140001000, DecoderOptions::NONE);
        let mut instructions = Vec::new();
        let mut instr = Instruction::default();
        while decoder.can_decode() {
            decoder.decode_out(&mut instr);
            instructions.push(instr);
        }

        let stubs = detect_syscall_stubs(&instructions);
        assert_eq!(stubs.len(), 1);
        let s = &stubs[0];
        assert_eq!(s.stub_type, SyscallType::Direct);
        assert_eq!(s.ssn, Some(0x18));
        assert_eq!(s.estimated_api.as_deref(), Some("NtAllocateVirtualMemory"));
    }

    #[test]
    fn test_indirect_syscall_trampoline() {
        // mov r10, rcx; mov eax, 0x50; jmp r11
        let code = [
            0x49, 0x89, 0xCA, // mov r10, rcx
            0xB8, 0x50, 0x00, 0x00, 0x00, // mov eax, 0x50 (NtProtectVirtualMemory)
            0x41, 0xFF, 0xE3, // jmp r11
        ];

        let mut decoder = Decoder::with_ip(64, &code, 0x140001000, DecoderOptions::NONE);
        let mut instructions = Vec::new();
        let mut instr = Instruction::default();
        while decoder.can_decode() {
            decoder.decode_out(&mut instr);
            instructions.push(instr);
        }

        let stubs = detect_syscall_stubs(&instructions);
        assert_eq!(stubs.len(), 1);
        let s = &stubs[0];
        assert_eq!(s.stub_type, SyscallType::Indirect);
        assert_eq!(s.ssn, Some(0x50));
        assert_eq!(s.estimated_api.as_deref(), Some("NtProtectVirtualMemory"));
    }

    #[test]
    fn test_arm64_darwin_syscall_detection() {
        // movz x16, #1 (sys_exit) -> 0xD2800030 (rd = 16, imm = 1)
        // svc #0x80 -> 0xD4001001
        let mut code = Vec::new();
        let movz_x16: u32 = 0xD2800000 | (1 << 5) | 16;
        let svc_80: u32 = 0xD4000001 | (0x80 << 5);
        code.extend_from_slice(&movz_x16.to_le_bytes());
        code.extend_from_slice(&svc_80.to_le_bytes());

        let stubs = detect_arm64_syscall_stubs(&code, 0x1000, true);
        assert_eq!(stubs.len(), 1);
        assert_eq!(stubs[0].stub_type, SyscallType::Direct);
        assert_eq!(stubs[0].ssn, Some(1));
        assert_eq!(stubs[0].estimated_api.as_deref(), Some("sys_exit"));
    }
}
