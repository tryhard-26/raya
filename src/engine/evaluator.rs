use crate::ast::*;
use crate::binary::{ElfSection, PeSection};
use crate::engine::context::{MatchedEvidence, ScanContext};

#[derive(Debug, Clone, PartialEq)]
pub enum EvalValue {
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    PeSec(PeSection),
    ElfSec(ElfSection),
    None,
}

impl EvalValue {
    pub fn is_truthy(&self) -> bool {
        match self {
            EvalValue::Bool(b) => *b,
            EvalValue::Int(i) => *i != 0,
            EvalValue::Float(fl) => *fl != 0.0,
            EvalValue::Str(s) => !s.is_empty(),
            EvalValue::PeSec(_) => true,
            EvalValue::ElfSec(_) => true,
            EvalValue::None => false,
        }
    }

    pub fn to_float(&self) -> Option<f64> {
        match self {
            EvalValue::Float(fl) => Some(*fl),
            EvalValue::Int(i) => Some(*i as f64),
            _ => None,
        }
    }
}

pub struct Evaluator<'a, 'b> {
    pub context: &'a mut ScanContext<'b>,
    pub rule: &'a Rule,
}

impl<'a, 'b> Evaluator<'a, 'b> {
    pub fn new(context: &'a mut ScanContext<'b>, rule: &'a Rule) -> Self {
        Self { context, rule }
    }

    pub fn evaluate(&mut self) -> bool {
        let val = self.eval_expr(&self.rule.condition.clone());
        val.is_truthy()
    }

    fn eval_expr(&mut self, expr: &Expr) -> EvalValue {
        match expr {
            Expr::Boolean(b) => EvalValue::Bool(*b),
            Expr::Integer(i) => EvalValue::Int(*i),
            Expr::Float(fl) => EvalValue::Float(*fl),
            Expr::StringLit(s) => EvalValue::Str(s.clone()),
            Expr::StringRef(id) => {
                if let Some(matches) = self.context.string_matches.get(id) {
                    if !matches.is_empty() {
                        let offsets: Vec<usize> = matches.iter().map(|m| m.offset).collect();
                        self.context.record_evidence(MatchedEvidence::StringMatch {
                            id: id.clone(),
                            count: matches.len(),
                            offsets,
                        });
                        return EvalValue::Bool(true);
                    }
                }
                EvalValue::Bool(false)
            }
            Expr::StringCount(id) => {
                let lookup_id = if let Some(stripped) = id.strip_prefix('#') {
                    format!("${}", stripped)
                } else if !id.starts_with('$') {
                    format!("${}", id)
                } else {
                    id.clone()
                };
                let count = self
                    .context
                    .string_matches
                    .get(&lookup_id)
                    .map(|m| m.len())
                    .unwrap_or(0);
                EvalValue::Int(count as i64)
            }
            Expr::StringOffset(id) => {
                let lookup_id = if let Some(stripped) = id.strip_prefix('@') {
                    format!("${}", stripped)
                } else if !id.starts_with('$') {
                    format!("${}", id)
                } else {
                    id.clone()
                };
                let offset = self
                    .context
                    .string_matches
                    .get(&lookup_id)
                    .and_then(|m| m.first())
                    .map(|m| m.offset as i64)
                    .unwrap_or(-1);
                EvalValue::Int(offset)
            }
            Expr::Not(inner) => {
                let res = self.eval_expr(inner);
                EvalValue::Bool(!res.is_truthy())
            }
            Expr::And(left, right) => {
                let left_val = self.eval_expr(left);
                if !left_val.is_truthy() {
                    return EvalValue::Bool(false);
                }
                let right_val = self.eval_expr(right);
                EvalValue::Bool(right_val.is_truthy())
            }
            Expr::Or(left, right) => {
                let left_val = self.eval_expr(left);
                if left_val.is_truthy() {
                    return EvalValue::Bool(true);
                }
                let right_val = self.eval_expr(right);
                EvalValue::Bool(right_val.is_truthy())
            }
            Expr::Binary { left, op, right } => {
                let left_val = self.eval_expr(left);
                let right_val = self.eval_expr(right);
                self.eval_binary_op(left_val, *op, right_val)
            }
            Expr::CountOf { count, set } => {
                let req_count = match self.eval_expr(count) {
                    EvalValue::Int(i) => i.max(0) as usize,
                    _ => 0,
                };
                let (matched, indicators) = self.eval_set_matches(set);
                let pass = matched >= req_count;
                if pass && req_count > 0 {
                    self.context.record_evidence(MatchedEvidence::Quantifier {
                        required: req_count,
                        matched,
                        indicators,
                    });
                }
                EvalValue::Bool(pass)
            }
            Expr::AnyOf(set) => {
                let (matched, indicators) = self.eval_set_matches(set);
                let pass = matched > 0;
                if pass {
                    self.context.record_evidence(MatchedEvidence::Quantifier {
                        required: 1,
                        matched,
                        indicators,
                    });
                }
                EvalValue::Bool(pass)
            }
            Expr::AllOf(set) => {
                let total = self.get_set_total_count(set);
                let (matched, indicators) = self.eval_set_matches(set);
                let pass = total > 0 && matched == total;
                if pass {
                    self.context.record_evidence(MatchedEvidence::Quantifier {
                        required: total,
                        matched,
                        indicators,
                    });
                }
                EvalValue::Bool(pass)
            }
            Expr::NoneOf(set) => {
                let (matched, _) = self.eval_set_matches(set);
                EvalValue::Bool(matched == 0)
            }
            Expr::FunctionCall {
                module,
                function,
                args,
            } => self.eval_function_call(module, function, args),
            Expr::MemberAccess {
                object,
                property,
                sub_property,
            } => self.eval_member_access(object, property, sub_property.as_deref()),
            Expr::Variable(var) => match var.as_str() {
                "filesize" => EvalValue::Int(self.context.file_size as i64),
                "entropy" => EvalValue::Float(self.context.entropy),
                "is_pe" => EvalValue::Bool(self.context.binary.pe.is_some()),
                "is_elf" => EvalValue::Bool(self.context.binary.elf.is_some()),
                "is_macho" => EvalValue::Bool(self.context.binary.macho.is_some()),
                _ => EvalValue::None,
            },
        }
    }

    fn eval_binary_op(
        &mut self,
        left: EvalValue,
        op: BinaryOperator,
        right: EvalValue,
    ) -> EvalValue {
        match op {
            BinaryOperator::Eq => EvalValue::Bool(left == right),
            BinaryOperator::Neq => EvalValue::Bool(left != right),
            BinaryOperator::Lt => match (left, right) {
                (EvalValue::Int(a), EvalValue::Int(b)) => EvalValue::Bool(a < b),
                (EvalValue::Float(a), EvalValue::Float(b)) => EvalValue::Bool(a < b),
                (EvalValue::Int(a), EvalValue::Float(b)) => EvalValue::Bool((a as f64) < b),
                (EvalValue::Float(a), EvalValue::Int(b)) => EvalValue::Bool(a < (b as f64)),
                _ => EvalValue::Bool(false),
            },
            BinaryOperator::Lte => match (left, right) {
                (EvalValue::Int(a), EvalValue::Int(b)) => EvalValue::Bool(a <= b),
                (EvalValue::Float(a), EvalValue::Float(b)) => EvalValue::Bool(a <= b),
                (EvalValue::Int(a), EvalValue::Float(b)) => EvalValue::Bool((a as f64) <= b),
                (EvalValue::Float(a), EvalValue::Int(b)) => EvalValue::Bool(a <= (b as f64)),
                _ => EvalValue::Bool(false),
            },
            BinaryOperator::Gt => match (left, right) {
                (EvalValue::Int(a), EvalValue::Int(b)) => EvalValue::Bool(a > b),
                (EvalValue::Float(a), EvalValue::Float(b)) => {
                    self.record_entropy_if_applicable(a, b);
                    EvalValue::Bool(a > b)
                }
                (EvalValue::Int(a), EvalValue::Float(b)) => EvalValue::Bool((a as f64) > b),
                (EvalValue::Float(a), EvalValue::Int(b)) => {
                    self.record_entropy_if_applicable(a, b as f64);
                    EvalValue::Bool(a > (b as f64))
                }
                _ => EvalValue::Bool(false),
            },
            BinaryOperator::Gte => match (left, right) {
                (EvalValue::Int(a), EvalValue::Int(b)) => EvalValue::Bool(a >= b),
                (EvalValue::Float(a), EvalValue::Float(b)) => EvalValue::Bool(a >= b),
                (EvalValue::Int(a), EvalValue::Float(b)) => EvalValue::Bool((a as f64) >= b),
                (EvalValue::Float(a), EvalValue::Int(b)) => EvalValue::Bool(a >= (b as f64)),
                _ => EvalValue::Bool(false),
            },
            BinaryOperator::Add => match (left, right) {
                (EvalValue::Int(a), EvalValue::Int(b)) => EvalValue::Int(a + b),
                (EvalValue::Float(a), EvalValue::Float(b)) => EvalValue::Float(a + b),
                _ => EvalValue::None,
            },
            BinaryOperator::Sub => match (left, right) {
                (EvalValue::Int(a), EvalValue::Int(b)) => EvalValue::Int(a - b),
                (EvalValue::Float(a), EvalValue::Float(b)) => EvalValue::Float(a - b),
                _ => EvalValue::None,
            },
            BinaryOperator::Mul => match (left, right) {
                (EvalValue::Int(a), EvalValue::Int(b)) => EvalValue::Int(a * b),
                (EvalValue::Float(a), EvalValue::Float(b)) => EvalValue::Float(a * b),
                _ => EvalValue::None,
            },
            BinaryOperator::Div => match (left, right) {
                (EvalValue::Int(a), EvalValue::Int(b)) if b != 0 => EvalValue::Int(a / b),
                (EvalValue::Float(a), EvalValue::Float(b)) if b != 0.0 => EvalValue::Float(a / b),
                _ => EvalValue::None,
            },
        }
    }

    fn record_entropy_if_applicable(&mut self, val: f64, threshold: f64) {
        if (val - self.context.entropy).abs() < 1e-6 {
            self.context.record_evidence(MatchedEvidence::FileEntropy {
                entropy: val,
                threshold,
            });
        }
    }

    fn eval_set_matches(&self, set: &SetSelector) -> (usize, Vec<String>) {
        let mut matched_count = 0;
        let mut matched_indicators = Vec::new();

        let candidate_ids: Vec<String> = match set {
            SetSelector::Them => self.rule.strings.iter().map(|s| s.id.clone()).collect(),
            SetSelector::Wildcard(pat) => {
                let prefix = pat.trim_end_matches('*');
                self.rule
                    .strings
                    .iter()
                    .map(|s| s.id.clone())
                    .filter(|id| id.starts_with(prefix))
                    .collect()
            }
            SetSelector::List(ids) => ids.clone(),
        };

        for id in candidate_ids {
            if let Some(matches) = self.context.string_matches.get(&id) {
                if !matches.is_empty() {
                    matched_count += 1;
                    matched_indicators.push(id);
                }
            }
        }

        (matched_count, matched_indicators)
    }

    fn get_set_total_count(&self, set: &SetSelector) -> usize {
        match set {
            SetSelector::Them => self.rule.strings.len(),
            SetSelector::Wildcard(pat) => {
                let prefix = pat.trim_end_matches('*');
                self.rule
                    .strings
                    .iter()
                    .filter(|s| s.id.starts_with(prefix))
                    .count()
            }
            SetSelector::List(ids) => ids.len(),
        }
    }

    fn eval_function_call(&mut self, module: &str, function: &str, args: &[Expr]) -> EvalValue {
        let evaluated_args: Vec<EvalValue> = args.iter().map(|a| self.eval_expr(a)).collect();

        if module == "pe" || module.is_empty() {
            if let Some(pe) = &self.context.binary.pe {
                match function {
                    "import" => {
                        if evaluated_args.len() >= 2 {
                            if let (EvalValue::Str(dll), EvalValue::Str(func)) =
                                (&evaluated_args[0], &evaluated_args[1])
                            {
                                let matched = pe.has_import(dll, func);
                                if matched {
                                    self.context.record_evidence(MatchedEvidence::PeImport {
                                        dll: dll.clone(),
                                        function: func.clone(),
                                    });
                                }
                                return EvalValue::Bool(matched);
                            }
                        }
                    }
                    "export" => {
                        if let Some(EvalValue::Str(func)) = evaluated_args.first() {
                            let matched = pe.has_export(func);
                            if matched {
                                self.context.record_evidence(MatchedEvidence::PeExport {
                                    function: func.clone(),
                                });
                            }
                            return EvalValue::Bool(matched);
                        }
                    }
                    "has_instruction" => {
                        if let Some(EvalValue::Str(instr)) = evaluated_args.first() {
                            let matched = pe.has_instruction(self.context.data, instr);
                            if matched {
                                self.context
                                    .record_evidence(MatchedEvidence::Custom(format!(
                                        "Disassembly matched opcode: {}",
                                        instr
                                    )));
                            }
                            return EvalValue::Bool(matched);
                        }
                    }
                    "has_instruction_sequence" => {
                        let seq: Vec<&str> = evaluated_args
                            .iter()
                            .filter_map(|a| match a {
                                EvalValue::Str(s) => Some(s.as_str()),
                                _ => None,
                            })
                            .collect();
                        if !seq.is_empty() {
                            let matched = pe.has_instruction_sequence(self.context.data, &seq);
                            if matched {
                                self.context
                                    .record_evidence(MatchedEvidence::Custom(format!(
                                        "Disassembly matched opcode sequence: [{}]",
                                        seq.join(" -> ")
                                    )));
                            }
                            return EvalValue::Bool(matched);
                        }
                    }
                    "section" => {
                        if let Some(EvalValue::Str(sec_name)) = evaluated_args.first() {
                            if let Some(sec) = pe.get_section(sec_name) {
                                return EvalValue::PeSec(sec.clone());
                            }
                        }
                    }
                    "has_rich_comp_id" => {
                        if let Some(EvalValue::Int(id)) = evaluated_args.first() {
                            return EvalValue::Bool(pe.has_rich_comp_id(*id as u16));
                        }
                    }
                    "has_rich_product_id" => {
                        if let Some(EvalValue::Int(id)) = evaluated_args.first() {
                            return EvalValue::Bool(pe.has_rich_product_id(*id as u16));
                        }
                    }
                    _ => {}
                }
            }
        }

        if module == "elf" || module.is_empty() {
            if let Some(elf) = &self.context.binary.elf {
                if function == "section" {
                    if let Some(EvalValue::Str(sec_name)) = evaluated_args.first() {
                        if let Some(sec) = elf.get_section(sec_name) {
                            return EvalValue::ElfSec(sec.clone());
                        }
                    }
                }
            }
        }

        if module == "macho" || module.is_empty() {
            if let Some(macho) = &self.context.binary.macho {
                match function {
                    "has_dylib" => {
                        if let Some(EvalValue::Str(dylib)) = evaluated_args.first() {
                            return EvalValue::Bool(macho.has_dylib(dylib));
                        }
                    }
                    "has_segment" => {
                        if let Some(EvalValue::Str(seg)) = evaluated_args.first() {
                            return EvalValue::Bool(macho.get_segment(seg).is_some());
                        }
                    }
                    "has_section" => {
                        if evaluated_args.len() >= 2 {
                            if let (EvalValue::Str(seg), EvalValue::Str(sec)) =
                                (&evaluated_args[0], &evaluated_args[1])
                            {
                                return EvalValue::Bool(macho.get_section(seg, sec).is_some());
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        if module == "entropy" {
            match function {
                "max_window" => {
                    let window_size = match evaluated_args.first() {
                        Some(EvalValue::Int(w)) => (*w).max(1) as usize,
                        _ => 512,
                    };
                    let (max_ent, _) =
                        crate::entropy::max_window_entropy(self.context.data, window_size);
                    return EvalValue::Float(max_ent);
                }
                "max_window_exceeds" => {
                    let window_size = match evaluated_args.first() {
                        Some(EvalValue::Int(w)) => (*w).max(1) as usize,
                        _ => 512,
                    };
                    let threshold = match evaluated_args.get(1) {
                        Some(EvalValue::Float(f)) => *f,
                        Some(EvalValue::Int(i)) => *i as f64,
                        _ => 7.0,
                    };
                    let (max_ent, _) =
                        crate::entropy::max_window_entropy(self.context.data, window_size);
                    return EvalValue::Bool(max_ent >= threshold);
                }
                _ => {}
            }
        }

        if module.is_empty() {
            match function {
                "uint16" => {
                    if let Some(EvalValue::Int(offset)) = evaluated_args.first() {
                        let off = *offset as usize;
                        if off + 2 <= self.context.data.len() {
                            let val = u16::from_le_bytes([
                                self.context.data[off],
                                self.context.data[off + 1],
                            ]);
                            return EvalValue::Int(val as i64);
                        }
                    }
                }
                "uint32" => {
                    if let Some(EvalValue::Int(offset)) = evaluated_args.first() {
                        let off = *offset as usize;
                        if off + 4 <= self.context.data.len() {
                            let val = u32::from_le_bytes([
                                self.context.data[off],
                                self.context.data[off + 1],
                                self.context.data[off + 2],
                                self.context.data[off + 3],
                            ]);
                            return EvalValue::Int(val as i64);
                        }
                    }
                }
                _ => {}
            }
        }

        EvalValue::None
    }

    fn eval_member_access(
        &mut self,
        object: &Expr,
        property: &str,
        sub_property: Option<&str>,
    ) -> EvalValue {
        let obj_val = self.eval_expr(object);

        match obj_val {
            EvalValue::PeSec(sec) => match property {
                "entropy" => {
                    self.context
                        .record_evidence(MatchedEvidence::PeSectionEntropy {
                            section: sec.name.clone(),
                            entropy: sec.entropy,
                            threshold: 0.0,
                        });
                    EvalValue::Float(sec.entropy)
                }
                "virtual_size" => EvalValue::Int(sec.virtual_size as i64),
                "virtual_address" => EvalValue::Int(sec.virtual_address as i64),
                "raw_size" => EvalValue::Int(sec.raw_size as i64),
                "executable" => {
                    if sec.is_executable {
                        self.context
                            .record_evidence(MatchedEvidence::PeSectionFlag {
                                section: sec.name.clone(),
                                flag: "executable".to_string(),
                            });
                    }
                    EvalValue::Bool(sec.is_executable)
                }
                "writable" => {
                    if sec.is_writable {
                        self.context
                            .record_evidence(MatchedEvidence::PeSectionFlag {
                                section: sec.name.clone(),
                                flag: "writable".to_string(),
                            });
                    }
                    EvalValue::Bool(sec.is_writable)
                }
                "readable" => EvalValue::Bool(sec.is_readable),
                _ => EvalValue::None,
            },
            EvalValue::ElfSec(sec) => match property {
                "entropy" => EvalValue::Float(sec.entropy),
                "size" => EvalValue::Int(sec.size as i64),
                "executable" => EvalValue::Bool(sec.is_executable),
                "writable" => EvalValue::Bool(sec.is_writable),
                _ => EvalValue::None,
            },
            _ => {
                // object might be Expr::Variable("pe") or Expr::Variable("elf")
                if let Expr::Variable(ref var_name) = object {
                    if var_name == "pe" {
                        if let Some(pe) = &self.context.binary.pe {
                            return match property {
                                "is_pe" => EvalValue::Bool(pe.is_pe),
                                "is_dll" => EvalValue::Bool(pe.is_dll),
                                "is_pe32_plus" => EvalValue::Bool(pe.is_pe32_plus),
                                "number_of_sections" => {
                                    EvalValue::Int(pe.number_of_sections as i64)
                                }
                                "entry_point" => EvalValue::Int(pe.entry_point as i64),
                                "has_rwx" => EvalValue::Bool(pe.has_rwx_section()),
                                "is_signed" => EvalValue::Bool(pe.is_signed),
                                "has_rich_header" => EvalValue::Bool(pe.has_rich_header),
                                "security_dir_size" => EvalValue::Int(pe.security_dir_size as i64),
                                _ => EvalValue::None,
                            };
                        } else {
                            return EvalValue::Bool(false);
                        }
                    } else if var_name == "elf" {
                        if let Some(elf) = &self.context.binary.elf {
                            return match property {
                                "is_elf" => EvalValue::Bool(elf.is_elf),
                                "is_64" => EvalValue::Bool(elf.is_64),
                                "is_executable" => EvalValue::Bool(elf.is_executable),
                                "is_shared_object" => EvalValue::Bool(elf.is_shared_object),
                                "number_of_sections" => {
                                    EvalValue::Int(elf.number_of_sections as i64)
                                }
                                "entry_point" => EvalValue::Int(elf.entry_point as i64),
                                _ => EvalValue::None,
                            };
                        } else {
                            return EvalValue::Bool(false);
                        }
                    } else if var_name == "macho" {
                        if let Some(macho) = &self.context.binary.macho {
                            return match property {
                                "is_macho" => EvalValue::Bool(macho.is_macho),
                                "is_64" => EvalValue::Bool(macho.is_64),
                                "is_fat" => EvalValue::Bool(macho.is_fat),
                                "is_signed" => EvalValue::Bool(macho.is_signed),
                                "number_of_commands" => {
                                    EvalValue::Int(macho.number_of_commands as i64)
                                }
                                "number_of_segments" => EvalValue::Int(macho.segments.len() as i64),
                                "entry_point" => EvalValue::Int(macho.entry_point as i64),
                                "cpu_type" => EvalValue::Int(macho.cpu_type as i64),
                                _ => EvalValue::None,
                            };
                        } else {
                            return EvalValue::Bool(false);
                        }
                    }
                }

                if let Some(sub) = sub_property {
                    if property == "section" {
                        if let Some(pe) = &self.context.binary.pe {
                            if let Some(sec) = pe.get_section(sub) {
                                return EvalValue::PeSec(sec.clone());
                            }
                        }
                    }
                }

                EvalValue::None
            }
        }
    }
}
