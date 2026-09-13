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
}
