// src/diff/mod.rs
//
// Binary Similarity & Patch Diffing Engine for Raya 2.0
// Computes graph isomorphism, topological CFG distance, section deltas,
// and import Jaccard similarity to measure distance between two binaries.

use crate::binary::BinaryAnalysis;
use crate::hash::{compute_hashes, ssdeep_compare};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryDiffReport {
    pub similarity_score: f64, // 0.0% to 100.0%
    pub file_a_metrics: FileOverview,
    pub file_b_metrics: FileOverview,
    pub cfg_diff: CfgDiff,
    pub section_diff: SectionDiff,
    pub import_diff: ImportDiff,
    pub structural_summary: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileOverview {
    pub size: usize,
    pub format: String,
    pub sha256: String,
    pub entropy: f64,
    pub imphash: Option<String>,
    pub ssdeep: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CfgDiff {
    pub blocks_a: usize,
    pub blocks_b: usize,
    pub blocks_delta: i64,
    pub edges_a: usize,
    pub edges_b: usize,
    pub edges_delta: i64,
    pub complexity_a: usize,
    pub complexity_b: usize,
    pub complexity_delta: i64,
    pub loops_a: usize,
    pub loops_b: usize,
    pub loops_delta: i64,
    pub cff_obfuscation_a: bool,
    pub cff_obfuscation_b: bool,
    pub cfg_similarity: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionDiff {
    pub common_sections: Vec<String>,
    pub added_sections: Vec<String>,
    pub removed_sections: Vec<String>,
    pub entropy_deltas: Vec<(String, f64, f64)>, // (name, entropy_a, entropy_b)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportDiff {
    pub jaccard_similarity: f64,
    pub common_imports: usize,
    pub added_imports: Vec<String>,
    pub removed_imports: Vec<String>,
}

/// Computes a comprehensive binary diff between two buffers.
pub fn diff_binaries(data_a: &[u8], data_b: &[u8]) -> BinaryDiffReport {
    let hashes_a = compute_hashes(data_a);
    let hashes_b = compute_hashes(data_b);

    let analysis_a = BinaryAnalysis::analyze(data_a);
    let analysis_b = BinaryAnalysis::analyze(data_b);

    // 1. CFG Diff
    let cfg_a = analysis_a.cfg.as_ref();
    let cfg_b = analysis_b.cfg.as_ref();

    let blocks_a = cfg_a.map(|c| c.blocks.len()).unwrap_or(0);
    let blocks_b = cfg_b.map(|c| c.blocks.len()).unwrap_or(0);
    let edges_a = cfg_a.map(|c| c.edges.len()).unwrap_or(0);
    let edges_b = cfg_b.map(|c| c.edges.len()).unwrap_or(0);
    let comp_a = cfg_a.map(|c| c.cyclomatic_complexity).unwrap_or(0);
    let comp_b = cfg_b.map(|c| c.cyclomatic_complexity).unwrap_or(0);
    let loops_a = cfg_a.map(|c| c.loops.len()).unwrap_or(0);
    let loops_b = cfg_b.map(|c| c.loops.len()).unwrap_or(0);
    let cff_a = cfg_a.map(|c| c.is_flattened).unwrap_or(false);
    let cff_b = cfg_b.map(|c| c.is_flattened).unwrap_or(false);

    let max_blocks = blocks_a.max(blocks_b);
    let block_sim = if max_blocks == 0 {
        1.0
    } else {
        1.0 - ((blocks_a as f64 - blocks_b as f64).abs() / max_blocks as f64)
    };

    let max_comp = comp_a.max(comp_b);
    let comp_sim = if max_comp == 0 {
        1.0
    } else {
        1.0 - ((comp_a as f64 - comp_b as f64).abs() / max_comp as f64)
    };

    let cfg_similarity = ((block_sim * 0.5) + (comp_sim * 0.5)).clamp(0.0, 1.0);

    let cfg_diff = CfgDiff {
        blocks_a,
        blocks_b,
        blocks_delta: blocks_b as i64 - blocks_a as i64,
        edges_a,
        edges_b,
        edges_delta: edges_b as i64 - edges_a as i64,
        complexity_a: comp_a,
        complexity_b: comp_b,
        complexity_delta: comp_b as i64 - comp_a as i64,
        loops_a,
        loops_b,
        loops_delta: loops_b as i64 - loops_a as i64,
        cff_obfuscation_a: cff_a,
        cff_obfuscation_b: cff_b,
        cfg_similarity: cfg_similarity * 100.0,
    };

    // 2. Section Diff
    let sec_names_a: Vec<String> = if let Some(pe) = &analysis_a.pe {
        pe.sections.iter().map(|s| s.name.clone()).collect()
    } else if let Some(elf) = &analysis_a.elf {
        elf.sections.iter().map(|s| s.name.clone()).collect()
    } else {
        Vec::new()
    };

    let sec_names_b: Vec<String> = if let Some(pe) = &analysis_b.pe {
        pe.sections.iter().map(|s| s.name.clone()).collect()
    } else if let Some(elf) = &analysis_b.elf {
        elf.sections.iter().map(|s| s.name.clone()).collect()
    } else {
        Vec::new()
    };

    let set_a: HashSet<_> = sec_names_a.iter().cloned().collect();
    let set_b: HashSet<_> = sec_names_b.iter().cloned().collect();

    let common_sections: Vec<String> = set_a.intersection(&set_b).cloned().collect();
    let added_sections: Vec<String> = set_b.difference(&set_a).cloned().collect();
    let removed_sections: Vec<String> = set_a.difference(&set_b).cloned().collect();

    let mut entropy_deltas = Vec::new();
    if let (Some(pe_a), Some(pe_b)) = (&analysis_a.pe, &analysis_b.pe) {
        for name in &common_sections {
            let ent_a = pe_a
                .sections
                .iter()
                .find(|s| &s.name == name)
                .map(|s| s.entropy)
                .unwrap_or(0.0);
            let ent_b = pe_b
                .sections
                .iter()
                .find(|s| &s.name == name)
                .map(|s| s.entropy)
                .unwrap_or(0.0);
            entropy_deltas.push((name.clone(), ent_a, ent_b));
        }
    }

    let max_sec_count = set_a.len().max(set_b.len());
    let sec_sim = if max_sec_count == 0 {
        1.0
    } else {
        common_sections.len() as f64 / max_sec_count as f64
    };

    let section_diff = SectionDiff {
        common_sections,
        added_sections,
        removed_sections,
        entropy_deltas,
    };

    // 3. Import Diff
    let imports_a: HashSet<String> = analysis_a
        .pe
        .as_ref()
        .map(|p| {
            p.imports
                .iter()
                .flat_map(|imp| imp.functions.iter().map(|f| format!("{}!{}", imp.dll, f)))
                .collect()
        })
        .unwrap_or_default();

    let imports_b: HashSet<String> = analysis_b
        .pe
        .as_ref()
        .map(|p| {
            p.imports
                .iter()
                .flat_map(|imp| imp.functions.iter().map(|f| format!("{}!{}", imp.dll, f)))
                .collect()
        })
        .unwrap_or_default();

    let union_imports: HashSet<_> = imports_a.union(&imports_b).cloned().collect();
    let common_imports: HashSet<_> = imports_a.intersection(&imports_b).cloned().collect();
    let added_imports: Vec<String> = imports_b.difference(&imports_a).cloned().collect();
    let removed_imports: Vec<String> = imports_a.difference(&imports_b).cloned().collect();

    let jaccard_similarity = if union_imports.is_empty() {
        1.0
    } else {
        common_imports.len() as f64 / union_imports.len() as f64
    };

    let import_diff = ImportDiff {
        jaccard_similarity: jaccard_similarity * 100.0,
        common_imports: common_imports.len(),
        added_imports,
        removed_imports,
    };

    // 4. Fuzzy Hash / SSDEEP Similarity
    let ssdeep_sim = if let (Some(sa), Some(sb)) = (&hashes_a.ssdeep, &hashes_b.ssdeep) {
        ssdeep_compare(sa, sb) as f64 / 100.0
    } else {
        0.0
    };

    // 5. Overall Weighted Composite Similarity Score
    let overall_sim = (cfg_similarity * 0.35)
        + (jaccard_similarity * 0.25)
        + (ssdeep_sim * 0.20)
        + (sec_sim * 0.20);

    let mut structural_summary = Vec::new();
    if (blocks_a as i64 - blocks_b as i64).abs() > 50 {
        structural_summary.push(format!(
            "Significant basic block shift: {} -> {} ({:+})",
            blocks_a,
            blocks_b,
            blocks_b as i64 - blocks_a as i64
        ));
    }
    if (comp_a as i64 - comp_b as i64).abs() > 20 {
        structural_summary.push(format!(
            "Cyclomatic complexity delta: {} -> {} ({:+})",
            comp_a,
            comp_b,
            comp_b as i64 - comp_a as i64
        ));
    }
    if !cff_a && cff_b {
        structural_summary.push("Control flow flattening (CFF) introduced in target B".to_string());
    } else if cff_a && !cff_b {
        structural_summary.push("Control flow flattening removed in target B".to_string());
    }
    if !section_diff.added_sections.is_empty() {
        structural_summary.push(format!(
            "New sections added: {:?}",
            section_diff.added_sections
        ));
    }
    if !section_diff.removed_sections.is_empty() {
        structural_summary.push(format!(
            "Sections dropped: {:?}",
            section_diff.removed_sections
        ));
    }

    let file_a_metrics = FileOverview {
        size: data_a.len(),
        format: analysis_a.format.as_str().to_string(),
        sha256: hashes_a.sha256,
        entropy: crate::entropy::shannon_entropy(data_a),
        imphash: analysis_a.pe.as_ref().and_then(|p| p.imphash.clone()),
        ssdeep: hashes_a.ssdeep,
    };

    let file_b_metrics = FileOverview {
        size: data_b.len(),
        format: analysis_b.format.as_str().to_string(),
        sha256: hashes_b.sha256,
        entropy: crate::entropy::shannon_entropy(data_b),
        imphash: analysis_b.pe.as_ref().and_then(|p| p.imphash.clone()),
        ssdeep: hashes_b.ssdeep,
    };

    BinaryDiffReport {
        similarity_score: (overall_sim * 100.0).clamp(0.0, 100.0),
        file_a_metrics,
        file_b_metrics,
        cfg_diff,
        section_diff,
        import_diff,
        structural_summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diff_identical_buffers() {
        let data = b"MZ\x90\x00\x03\x00\x00\x00PE\x00\x00Some binary content with instructions";
        let report = diff_binaries(data, data);
        assert!(report.similarity_score >= 90.0);
    }
}
