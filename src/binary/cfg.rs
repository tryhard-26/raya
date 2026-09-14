//! # Control Flow Graph (CFG) Analysis
//!
//! Reconstructs directed control flow graphs from disassembled x86/x64 instruction
//! streams, identifies basic blocks, tracks branch edges, calculates cyclomatic
//! complexity, and detects loops and control flow flattening (CFF) obfuscation.

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Edge type between basic blocks in a Control Flow Graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum EdgeType {
    /// Normal sequential fallthrough to the next instruction block.
    Fallthrough,
    /// Unconditional jump (e.g. `jmp`).
    Unconditional,
    /// Conditional branch taken (e.g. `jz`, `jnz`).
    ConditionalTrue,
    /// Conditional branch not taken (fallthrough path of a conditional jump).
    ConditionalFalse,
    /// Indirect jump or dynamic dispatch (e.g. `jmp rax`, `jmp [rbx]`).
    Indirect,
}

/// A directed edge connecting two basic blocks.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CfgEdge {
    pub source_ip: u64,
    pub target_ip: u64,
    pub edge_type: EdgeType,
}

/// A node in the Control Flow Graph representing a basic block.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CfgBlock {
    pub start_ip: u64,
    pub end_ip: u64,
    pub instruction_count: usize,
    pub mnemonics: Vec<String>,
    pub successors: Vec<u64>,
    pub predecessors: Vec<u64>,
    pub is_loop_header: bool,
}

/// Summary of a detected natural loop.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CfgLoop {
    /// Address of the loop header (target of back-edge).
    pub header_ip: u64,
    /// Address of the back-edge source (tail of the loop).
    pub tail_ip: u64,
    /// Total basic blocks belonging to this loop body.
    pub block_count: usize,
}

/// Reconstructed Control Flow Graph for an executable section or function.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ControlFlowGraph {
    /// Map of block start IP to CfgBlock.
    pub blocks: BTreeMap<u64, CfgBlock>,
    /// All directed edges in the CFG.
    pub edges: Vec<CfgEdge>,
    /// Calculated cyclomatic complexity (E - V + 2P).
    pub cyclomatic_complexity: usize,
    /// Detected natural loops in the graph.
    pub loops: Vec<CfgLoop>,
    /// True if the graph exhibits control flow flattening heuristics.
    pub is_flattened: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimpleFlow {
    Next,
    Call,
    UnconditionalBranch(u64),
    ConditionalBranch(u64),
    IndirectBranch,
    Return,
}

#[derive(Debug, Clone)]
pub struct DisassembledInstruction {
    pub ip: u64,
    pub next_ip: u64,
    pub mnemonic: String,
    pub flow: SimpleFlow,
}

impl ControlFlowGraph {
    /// Reconstructs a Control Flow Graph from machine code bytes.
    pub fn from_bytes(code: &[u8], bitness: u32, base_ip: u64) -> Self {
        if code.is_empty() {
            return Self::empty();
        }

        let mut decoder = Decoder::with_ip(bitness, code, base_ip, DecoderOptions::NONE);
        let mut instructions = Vec::new();
        let mut instr = Instruction::default();

        while decoder.can_decode() {
            decoder.decode_out(&mut instr);
            if instr.is_invalid() {
                continue;
            }
            instructions.push(instr);
        }

        Self::from_instructions(&instructions)
    }

    /// Reconstructs a Control Flow Graph from ARM64 machine code bytes.
    pub fn from_arm64_bytes(code: &[u8], base_ip: u64) -> Self {
        if code.len() < 4 {
            return Self::empty();
        }
        let instructions = decode_arm64_instructions(code, base_ip);
        Self::from_flow_instructions(&instructions)
    }

    /// Reconstructs a Control Flow Graph from pre-decoded iced-x86 instructions.
    pub fn from_instructions(instructions: &[Instruction]) -> Self {
        if instructions.is_empty() {
            return Self::empty();
        }

        let flow_instructions: Vec<DisassembledInstruction> = instructions
            .iter()
            .map(|instr| {
                let flow = match instr.flow_control() {
                    FlowControl::UnconditionalBranch => {
                        let t = instr.near_branch_target();
                        if t != 0 {
                            SimpleFlow::UnconditionalBranch(t)
                        } else {
                            SimpleFlow::IndirectBranch
                        }
                    }
                    FlowControl::ConditionalBranch => {
                        let t = instr.near_branch_target();
                        if t != 0 {
                            SimpleFlow::ConditionalBranch(t)
                        } else {
                            SimpleFlow::Next
                        }
                    }
                    FlowControl::IndirectBranch => SimpleFlow::IndirectBranch,
                    FlowControl::Return => SimpleFlow::Return,
                    FlowControl::Call => SimpleFlow::Call,
                    _ => SimpleFlow::Next,
                };
                DisassembledInstruction {
                    ip: instr.ip(),
                    next_ip: instr.next_ip(),
                    mnemonic: format!("{:?}", instr.mnemonic()).to_ascii_lowercase(),
                    flow,
                }
            })
            .collect();

        Self::from_flow_instructions(&flow_instructions)
    }

    /// Reconstructs a Control Flow Graph from generalized flow instructions.
    pub fn from_flow_instructions(instructions: &[DisassembledInstruction]) -> Self {
        if instructions.is_empty() {
            return Self::empty();
        }

        // 1. Identify Leaders (entry points to basic blocks)
        let mut leaders = BTreeSet::new();
        leaders.insert(instructions[0].ip);

        let mut next_is_leader = false;
        for instr in instructions {
            let ip = instr.ip;
            if next_is_leader {
                leaders.insert(ip);
                next_is_leader = false;
            }

            match instr.flow {
                SimpleFlow::UnconditionalBranch(target) => {
                    if target != 0 {
                        leaders.insert(target);
                    }
                    next_is_leader = true;
                }
                SimpleFlow::ConditionalBranch(target) => {
                    if target != 0 {
                        leaders.insert(target);
                    }
                    // Next sequential instruction is also a leader
                    next_is_leader = true;
                }
                SimpleFlow::IndirectBranch | SimpleFlow::Return => {
                    next_is_leader = true;
                }
                _ => {}
            }
        }

        // 2. Partition into Basic Blocks
        let mut blocks = BTreeMap::new();
        let mut current_block_start = instructions[0].ip;
        let mut current_mnemonics = Vec::new();
        let mut current_count = 0;

        for (idx, instr) in instructions.iter().enumerate() {
            let ip = instr.ip;
            let mnemonic = instr.mnemonic.clone();

            // If this instruction is a leader and not the very first in current block, flush
            if leaders.contains(&ip) && ip != current_block_start && current_count > 0 {
                let prev_ip = instructions[idx - 1].next_ip;
                blocks.insert(
                    current_block_start,
                    CfgBlock {
                        start_ip: current_block_start,
                        end_ip: prev_ip,
                        instruction_count: current_count,
                        mnemonics: std::mem::take(&mut current_mnemonics),
                        successors: Vec::new(),
                        predecessors: Vec::new(),
                        is_loop_header: false,
                    },
                );
                current_block_start = ip;
                current_count = 0;
            }

            current_mnemonics.push(mnemonic);
            current_count += 1;

            // Check if this instruction terminates the block
            let terminates = matches!(
                instr.flow,
                SimpleFlow::UnconditionalBranch(_)
                    | SimpleFlow::ConditionalBranch(_)
                    | SimpleFlow::IndirectBranch
                    | SimpleFlow::Return
            );

            if terminates {
                blocks.insert(
                    current_block_start,
                    CfgBlock {
                        start_ip: current_block_start,
                        end_ip: instr.next_ip,
                        instruction_count: current_count,
                        mnemonics: std::mem::take(&mut current_mnemonics),
                        successors: Vec::new(),
                        predecessors: Vec::new(),
                        is_loop_header: false,
                    },
                );
                if idx + 1 < instructions.len() {
                    current_block_start = instructions[idx + 1].ip;
                }
                current_count = 0;
            }
        }

        // Flush trailing block if any
        if current_count > 0 {
            let last_ip = instructions
                .last()
                .map(|i| i.next_ip)
                .unwrap_or(current_block_start);
            blocks.insert(
                current_block_start,
                CfgBlock {
                    start_ip: current_block_start,
                    end_ip: last_ip,
                    instruction_count: current_count,
                    mnemonics: current_mnemonics,
                    successors: Vec::new(),
                    predecessors: Vec::new(),
                    is_loop_header: false,
                },
            );
        }

        // 3. Connect Edges
        let mut edges = Vec::new();
        for instr in instructions {
            let ip = instr.ip;
            // Find which block this instruction terminates
            if let Some(block) = blocks.get(&ip) {
                if block.instruction_count > 1 {
                    continue; // Not the terminator
                }
            }

            // Check if this instruction is the terminator of its enclosing block
            let mut is_terminator = false;
            let mut enclosing_start = None;
            for (start, blk) in &blocks {
                if ip >= *start && ip < blk.end_ip {
                    enclosing_start = Some(*start);
                    // Check if it's the last instruction before end_ip
                    if instr.next_ip == blk.end_ip {
                        is_terminator = true;
                    }
                    break;
                }
            }

            if let (true, Some(src_block)) = (is_terminator, enclosing_start) {
                match instr.flow {
                    SimpleFlow::UnconditionalBranch(target) => {
                        if blocks.contains_key(&target) {
                            edges.push(CfgEdge {
                                source_ip: src_block,
                                target_ip: target,
                                edge_type: EdgeType::Unconditional,
                            });
                        }
                    }
                    SimpleFlow::ConditionalBranch(target) => {
                        if blocks.contains_key(&target) {
                            edges.push(CfgEdge {
                                source_ip: src_block,
                                target_ip: target,
                                edge_type: EdgeType::ConditionalTrue,
                            });
                        }
                        // Fallthrough path
                        let next_ip = instr.next_ip;
                        if blocks.contains_key(&next_ip) {
                            edges.push(CfgEdge {
                                source_ip: src_block,
                                target_ip: next_ip,
                                edge_type: EdgeType::ConditionalFalse,
                            });
                        }
                    }
                    SimpleFlow::IndirectBranch => {
                        edges.push(CfgEdge {
                            source_ip: src_block,
                            target_ip: 0,
                            edge_type: EdgeType::Indirect,
                        });
                    }
                    SimpleFlow::Next | SimpleFlow::Call => {
                        // Sequential fallthrough into next block
                        let next_ip = instr.next_ip;
                        if blocks.contains_key(&next_ip) {
                            edges.push(CfgEdge {
                                source_ip: src_block,
                                target_ip: next_ip,
                                edge_type: EdgeType::Fallthrough,
                            });
                        }
                    }
                    SimpleFlow::Return => {
                        // Function exit, no outgoing edge
                    }
                }
            }
        }

        // 4. Update Successors and Predecessors on blocks
        for edge in &edges {
            if edge.target_ip != 0 {
                if let Some(src) = blocks.get_mut(&edge.source_ip) {
                    if !src.successors.contains(&edge.target_ip) {
                        src.successors.push(edge.target_ip);
                    }
                }
                if let Some(dst) = blocks.get_mut(&edge.target_ip) {
                    if !dst.predecessors.contains(&edge.source_ip) {
                        dst.predecessors.push(edge.source_ip);
                    }
                }
            }
        }

        // 5. Detect Natural Loops (Back-edges where target_ip <= source_ip and target is an ancestor)
        let mut loops = Vec::new();
        for edge in &edges {
            if edge.target_ip != 0 && edge.target_ip <= edge.source_ip {
                // Potential back-edge. Check if target_ip can reach source_ip (forming a directed cycle)
                if Self::is_reachable(&blocks, edge.target_ip, edge.source_ip) {
                    let loop_blocks = Self::get_loop_body(&blocks, edge.target_ip, edge.source_ip);
                    if let Some(header) = blocks.get_mut(&edge.target_ip) {
                        header.is_loop_header = true;
                    }
                    loops.push(CfgLoop {
                        header_ip: edge.target_ip,
                        tail_ip: edge.source_ip,
                        block_count: loop_blocks.len(),
                    });
                }
            }
        }

        // 6. Calculate Cyclomatic Complexity: M = E - V + 2P (P = 1)
        let num_vertices = blocks.len();
        let num_edges = edges.iter().filter(|e| e.target_ip != 0).count();
        let cyclomatic_complexity = if num_vertices > 0 && num_edges >= num_vertices {
            num_edges.saturating_sub(num_vertices) + 2
        } else if num_vertices > 0 {
            1
        } else {
            0
        };

        // 7. Detect Control Flow Flattening (CFF)
        // Heuristic: A dispatcher block with out-degree >= 5 and loops present
        let mut is_flattened = false;
        for blk in blocks.values() {
            if blk.successors.len() >= 5 && !loops.is_empty() {
                is_flattened = true;
                break;
            }
        }
        if cyclomatic_complexity >= 40 && !loops.is_empty() {
            is_flattened = true;
        }

        Self {
            blocks,
            edges,
            cyclomatic_complexity,
            loops,
            is_flattened,
        }
    }

    fn is_reachable(blocks: &BTreeMap<u64, CfgBlock>, start: u64, target: u64) -> bool {
        if start == target {
            return true;
        }
        let mut visited = BTreeSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(start);
        visited.insert(start);

        while let Some(curr) = queue.pop_front() {
            if curr == target {
                return true;
            }
            if let Some(blk) = blocks.get(&curr) {
                for &succ in &blk.successors {
                    if visited.insert(succ) {
                        queue.push_back(succ);
                    }
                }
            }
        }
        false
    }

    fn get_loop_body(blocks: &BTreeMap<u64, CfgBlock>, header: u64, tail: u64) -> BTreeSet<u64> {
        let mut body = BTreeSet::new();
        body.insert(header);
        body.insert(tail);

        let mut stack = Vec::new();
        stack.push(tail);

        while let Some(node) = stack.pop() {
            if let Some(blk) = blocks.get(&node) {
                for &pred in &blk.predecessors {
                    if body.insert(pred) {
                        stack.push(pred);
                    }
                }
            }
        }
        body
    }

    /// Empty CFG constructor.
    pub fn empty() -> Self {
        Self {
            blocks: BTreeMap::new(),
            edges: Vec::new(),
            cyclomatic_complexity: 0,
            loops: Vec::new(),
            is_flattened: false,
        }
    }

    /// Returns true if at least one natural loop was detected.
    pub fn has_loop(&self) -> bool {
        !self.loops.is_empty()
    }

    /// Returns the count of detected natural loops.
    pub fn loop_count(&self) -> usize {
        self.loops.len()
    }
}

/// Decodes ARM64 machine instructions into generalized flow instructions for CFG analysis.
pub fn decode_arm64_instructions(code: &[u8], base_ip: u64) -> Vec<DisassembledInstruction> {
    let mut instructions = Vec::new();
    let num_words = (code.len() / 4).min(32768);

    let cond_names = [
        "b.eq", "b.ne", "b.cs", "b.cc", "b.mi", "b.pl", "b.vs", "b.vc",
        "b.hi", "b.ls", "b.ge", "b.lt", "b.gt", "b.le", "b.al", "b.nv",
    ];

    for i in 0..num_words {
        let offset = i * 4;
        let inst = u32::from_le_bytes([
            code[offset],
            code[offset + 1],
            code[offset + 2],
            code[offset + 3],
        ]);
        let ip = base_ip + offset as u64;
        let next_ip = ip + 4;

        let (mnemonic, flow) = if (inst & 0xFC000000) == 0x14000000 {
            // B <label> (unconditional branch)
            let imm26 = (inst & 0x03FFFFFF) as i32;
            let signed_words = if (imm26 & 0x02000000) != 0 {
                imm26 - (1 << 26)
            } else {
                imm26
            };
            let target = (ip as i64 + (signed_words as i64 * 4)) as u64;
            ("b".to_string(), SimpleFlow::UnconditionalBranch(target))
        } else if (inst & 0xFC000000) == 0x94000000 {
            // BL <label> (branch with link / call)
            let imm26 = (inst & 0x03FFFFFF) as i32;
            let signed_words = if (imm26 & 0x02000000) != 0 {
                imm26 - (1 << 26)
            } else {
                imm26
            };
            let _target = (ip as i64 + (signed_words as i64 * 4)) as u64;
            ("bl".to_string(), SimpleFlow::Call)
        } else if (inst & 0xFF000010) == 0x54000000 {
            // B.cond <label>
            let cond = (inst & 0x0F) as usize;
            let imm19 = ((inst >> 5) & 0x7FFFF) as i32;
            let signed_words = if (imm19 & 0x00040000) != 0 {
                imm19 - (1 << 19)
            } else {
                imm19
            };
            let target = (ip as i64 + (signed_words as i64 * 4)) as u64;
            let mnem = cond_names.get(cond).copied().unwrap_or("b.cond").to_string();
            (mnem, SimpleFlow::ConditionalBranch(target))
        } else if (inst & 0x7E000000) == 0x34000000 {
            // CBZ / CBNZ <Rt>, <label>
            let is_cbnz = (inst & 0x01000000) != 0;
            let imm19 = ((inst >> 5) & 0x7FFFF) as i32;
            let signed_words = if (imm19 & 0x00040000) != 0 {
                imm19 - (1 << 19)
            } else {
                imm19
            };
            let target = (ip as i64 + (signed_words as i64 * 4)) as u64;
            let mnem = if is_cbnz { "cbnz" } else { "cbz" }.to_string();
            (mnem, SimpleFlow::ConditionalBranch(target))
        } else if (inst & 0x7E000000) == 0x36000000 {
            // TBZ / TBNZ <Rt>, #<bit>, <label>
            let is_tbnz = (inst & 0x01000000) != 0;
            let imm14 = ((inst >> 5) & 0x3FFF) as i32;
            let signed_words = if (imm14 & 0x00002000) != 0 {
                imm14 - (1 << 14)
            } else {
                imm14
            };
            let target = (ip as i64 + (signed_words as i64 * 4)) as u64;
            let mnem = if is_tbnz { "tbnz" } else { "tbz" }.to_string();
            (mnem, SimpleFlow::ConditionalBranch(target))
        } else if (inst & 0xFFFFFC1F) == 0xD65F0000 {
            // RET [Rn]
            ("ret".to_string(), SimpleFlow::Return)
        } else if (inst & 0xFFFFFC1F) == 0xD61F0000 {
            // BR Rn
            ("br".to_string(), SimpleFlow::IndirectBranch)
        } else if (inst & 0xFFFFFC1F) == 0xD63F0000 {
            // BLR Rn
            ("blr".to_string(), SimpleFlow::Call)
        } else {
            // Non-branching instruction
            let mnem = if inst == 0xD503201F {
                "nop"
            } else if (inst & 0xFFE0001F) == 0xD4000001 {
                "svc"
            } else if (inst & 0xFFE0001F) == 0xD4200000 {
                "brk"
            } else if (inst & 0x7F800000) == 0x52800000 {
                "movz"
            } else if (inst & 0x7F800000) == 0x12800000 {
                "movn"
            } else if (inst & 0x7F800000) == 0x72800000 {
                "movk"
            } else if (inst & 0x7FE0FFE0) == 0x2A0003E0 {
                "mov"
            } else if (inst & 0x1F000000) == 0x11000000 || (inst & 0x7F200000) == 0x0B000000 {
                "add"
            } else if (inst & 0x1F000000) == 0x51000000 || (inst & 0x7F200000) == 0x4B000000 {
                "sub"
            } else if (inst & 0x7F80001F) == 0x7100001F || (inst & 0x7F20001F) == 0x6B00001F {
                "cmp"
            } else if (inst & 0x3E000000) == 0x28000000 {
                if (inst >> 22) & 1 == 1 { "ldp" } else { "stp" }
            } else if (inst & 0x3B000000) == 0x39000000 || (inst & 0x3B200C00) == 0x38200800 {
                if (inst >> 22) & 1 == 1 { "ldr" } else { "str" }
            } else if (inst & 0x9F000000) == 0x90000000 {
                "adrp"
            } else if (inst & 0x9F000000) == 0x10000000 {
                "adr"
            } else {
                "inst"
            };
            (mnem.to_string(), SimpleFlow::Next)
        };

        instructions.push(DisassembledInstruction {
            ip,
            next_ip,
            mnemonic,
            flow,
        });
    }

    instructions
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cfg_straight_line() {
        // xor eax, eax; inc eax; ret
        let code = [0x31, 0xC0, 0xFF, 0xC0, 0xC3];
        let cfg = ControlFlowGraph::from_bytes(&code, 64, 0x1000);
        assert_eq!(cfg.blocks.len(), 1);
        assert_eq!(cfg.cyclomatic_complexity, 1);
        assert!(!cfg.has_loop());
    }

    #[test]
    fn test_cfg_branch_and_loop() {
        // Loop:
        // 0x1000: xor eax, eax
        // 0x1002: inc eax
        // 0x1004: cmp eax, 10
        // 0x1007: jne 0x1002 (back to 0x1002)
        // 0x1009: ret
        let code = [
            0x31, 0xC0, // xor eax, eax
            0xFF, 0xC0, // inc eax
            0x83, 0xF8, 0x0A, // cmp eax, 10
            0x75, 0xF9, // jne 0x1002 (target = 0x1009 - 7 = 0x1002)
            0xC3, // ret
        ];
        let cfg = ControlFlowGraph::from_bytes(&code, 64, 0x1000);
        assert!(cfg.blocks.len() >= 2);
        assert!(cfg.has_loop(), "Should detect natural loop with back-edge");
        assert_eq!(cfg.loop_count(), 1);
    }

    #[test]
    fn test_arm64_cfg_straight_line() {
        // movz x0, #1 (0xD2800020)
        // ret (0xD65F03C0)
        let mut code = Vec::new();
        code.extend_from_slice(&0xD2800020u32.to_le_bytes());
        code.extend_from_slice(&0xD65F03C0u32.to_le_bytes());

        let cfg = ControlFlowGraph::from_arm64_bytes(&code, 0x1000);
        assert_eq!(cfg.blocks.len(), 1);
        assert_eq!(cfg.cyclomatic_complexity, 1);
        assert!(!cfg.has_loop());
    }

    #[test]
    fn test_arm64_cfg_branch_and_loop() {
        // 0x1000: movz x0, #0 (0xD2800000)
        // 0x1004: add x0, x0, #1 (0x91000400)
        // 0x1008: cmp x0, #10 (0xF100281F)
        // 0x100C: b.ne 0x1004 (target = 0x100C - 8 = 0x1004 -> offset = -2 words = 0x7FFFE -> 0x54FFFCD1)
        // 0x1010: ret (0xD65F03C0)
        let mut code = Vec::new();
        code.extend_from_slice(&0xD2800000u32.to_le_bytes());
        code.extend_from_slice(&0x91000400u32.to_le_bytes());
        code.extend_from_slice(&0xF100281Fu32.to_le_bytes());
        // b.ne to -2 words (-8 bytes): cond = 1 (ne). imm19 = (-2 as i32) & 0x7FFFF = 0x7FFFE. (0x7FFFE << 5) | 1 = 0xFFFC0 | 1 = 0x54FFFCD1
        let b_ne_inst: u32 = 0x54000000 | ((0x7FFFE & 0x7FFFF) << 5) | 0x01;
        code.extend_from_slice(&b_ne_inst.to_le_bytes());
        code.extend_from_slice(&0xD65F03C0u32.to_le_bytes());

        let cfg = ControlFlowGraph::from_arm64_bytes(&code, 0x1000);
        assert!(cfg.blocks.len() >= 2);
        assert!(cfg.has_loop(), "Should detect ARM64 natural loop with back-edge");
        assert_eq!(cfg.loop_count(), 1);
    }
}
