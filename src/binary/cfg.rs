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

    /// Reconstructs a Control Flow Graph from pre-decoded iced-x86 instructions.
    pub fn from_instructions(instructions: &[Instruction]) -> Self {
        if instructions.is_empty() {
            return Self::empty();
        }

        // 1. Identify Leaders (entry points to basic blocks)
        let mut leaders = BTreeSet::new();
        leaders.insert(instructions[0].ip());

        let mut next_is_leader = false;
        for instr in instructions {
            let ip = instr.ip();
            if next_is_leader {
                leaders.insert(ip);
                next_is_leader = false;
            }

            match instr.flow_control() {
                FlowControl::UnconditionalBranch => {
                    let target = instr.near_branch_target();
                    if target != 0 {
                        leaders.insert(target);
                    }
                    next_is_leader = true;
                }
                FlowControl::ConditionalBranch => {
                    let target = instr.near_branch_target();
                    if target != 0 {
                        leaders.insert(target);
                    }
                    // Next sequential instruction is also a leader
                    next_is_leader = true;
                }
                FlowControl::IndirectBranch => {
                    next_is_leader = true;
                }
                FlowControl::Return => {
                    next_is_leader = true;
                }
                _ => {}
            }
        }

        // 2. Partition into Basic Blocks
        let mut blocks = BTreeMap::new();
        let mut current_block_start = instructions[0].ip();
        let mut current_mnemonics = Vec::new();
        let mut current_count = 0;

        for (idx, instr) in instructions.iter().enumerate() {
            let ip = instr.ip();
            let mnemonic = format!("{:?}", instr.mnemonic()).to_ascii_lowercase();

            // If this instruction is a leader and not the very first in current block, flush
            if leaders.contains(&ip) && ip != current_block_start && current_count > 0 {
                let prev_ip = instructions[idx - 1].next_ip();
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
                instr.flow_control(),
                FlowControl::UnconditionalBranch
                    | FlowControl::ConditionalBranch
                    | FlowControl::IndirectBranch
                    | FlowControl::Return
            );

            if terminates {
                blocks.insert(
                    current_block_start,
                    CfgBlock {
                        start_ip: current_block_start,
                        end_ip: instr.next_ip(),
                        instruction_count: current_count,
                        mnemonics: std::mem::take(&mut current_mnemonics),
                        successors: Vec::new(),
                        predecessors: Vec::new(),
                        is_loop_header: false,
                    },
                );
                if idx + 1 < instructions.len() {
                    current_block_start = instructions[idx + 1].ip();
                }
                current_count = 0;
            }
        }

        // Flush trailing block if any
        if current_count > 0 {
            let last_ip = instructions
                .last()
                .map(|i| i.next_ip())
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
            let ip = instr.ip();
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
                    if instr.next_ip() == blk.end_ip {
                        is_terminator = true;
                    }
                    break;
                }
            }

            if let (true, Some(src_block)) = (is_terminator, enclosing_start) {
                match instr.flow_control() {
                    FlowControl::UnconditionalBranch => {
                        let target = instr.near_branch_target();
                        if blocks.contains_key(&target) {
                            edges.push(CfgEdge {
                                source_ip: src_block,
                                target_ip: target,
                                edge_type: EdgeType::Unconditional,
                            });
                        }
                    }
                    FlowControl::ConditionalBranch => {
                        let target = instr.near_branch_target();
                        if blocks.contains_key(&target) {
                            edges.push(CfgEdge {
                                source_ip: src_block,
                                target_ip: target,
                                edge_type: EdgeType::ConditionalTrue,
                            });
                        }
                        // Fallthrough path
                        let next_ip = instr.next_ip();
                        if blocks.contains_key(&next_ip) {
                            edges.push(CfgEdge {
                                source_ip: src_block,
                                target_ip: next_ip,
                                edge_type: EdgeType::ConditionalFalse,
                            });
                        }
                    }
                    FlowControl::IndirectBranch => {
                        edges.push(CfgEdge {
                            source_ip: src_block,
                            target_ip: 0,
                            edge_type: EdgeType::Indirect,
                        });
                    }
                    FlowControl::Next | FlowControl::Call => {
                        // Sequential fallthrough into next block
                        let next_ip = instr.next_ip();
                        if blocks.contains_key(&next_ip) {
                            edges.push(CfgEdge {
                                source_ip: src_block,
                                target_ip: next_ip,
                                edge_type: EdgeType::Fallthrough,
                            });
                        }
                    }
                    FlowControl::Return => {
                        // Function exit, no outgoing edge
                    }
                    _ => {}
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
}
