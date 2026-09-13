// src/tui/mod.rs
//
// Interactive Terminal TUI Dashboard for Raya 2.0
// Multi-tab interactive forensic triage workstation powered by crossterm.

use crate::binary::BinaryAnalysis;
use crate::entropy::shannon_entropy;
use crate::hash::compute_hashes;
use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    style::{Color, Print, ResetColor, SetBackgroundColor, SetForegroundColor},
    terminal::{self, EnterAlternateScreen, LeaveAlternateScreen},
};
use std::io::{self, stdout, Write};

pub struct TuiSession<'a> {
    pub target_name: &'a str,
    pub data: &'a [u8],
    pub analysis: BinaryAnalysis,
    pub whole_entropy: f64,
    pub active_tab: usize,
    pub scroll_offset: usize,
}

impl<'a> TuiSession<'a> {
    pub fn new(target_name: &'a str, data: &'a [u8]) -> Self {
        let whole_entropy = shannon_entropy(data);
        let analysis = BinaryAnalysis::analyze(data);
        Self {
            target_name,
            data,
            analysis,
            whole_entropy,
            active_tab: 0,
            scroll_offset: 0,
        }
    }

    pub fn run(&mut self) -> io::Result<()> {
        // If not a tty, don't enter raw mode
        if !std::io::IsTerminal::is_terminal(&std::io::stdout()) {
            println!("Terminal does not support interactive TUI. Use 'raya inspect' instead.");
            return Ok(());
        }

        terminal::enable_raw_mode()?;
        let mut out = stdout();
        execute!(out, EnterAlternateScreen, cursor::Hide)?;

        let res = self.event_loop(&mut out);

        execute!(out, cursor::Show, LeaveAlternateScreen)?;
        terminal::disable_raw_mode()?;
        res
    }

    fn event_loop<W: Write>(&mut self, out: &mut W) -> io::Result<()> {
        loop {
            self.draw(out)?;

            if event::poll(std::time::Duration::from_millis(100))? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press {
                        match key.code {
                            KeyCode::Char('q') | KeyCode::Esc => break,
                            KeyCode::Tab => {
                                self.active_tab = (self.active_tab + 1) % 5;
                                self.scroll_offset = 0;
                            }
                            KeyCode::BackTab => {
                                self.active_tab = if self.active_tab == 0 {
                                    4
                                } else {
                                    self.active_tab - 1
                                };
                                self.scroll_offset = 0;
                            }
                            KeyCode::Char('1') => {
                                self.active_tab = 0;
                                self.scroll_offset = 0;
                            }
                            KeyCode::Char('2') => {
                                self.active_tab = 1;
                                self.scroll_offset = 0;
                            }
                            KeyCode::Char('3') => {
                                self.active_tab = 2;
                                self.scroll_offset = 0;
                            }
                            KeyCode::Char('4') => {
                                self.active_tab = 3;
                                self.scroll_offset = 0;
                            }
                            KeyCode::Char('5') => {
                                self.active_tab = 4;
                                self.scroll_offset = 0;
                            }
                            KeyCode::Up | KeyCode::Char('k') => {
                                if self.scroll_offset > 0 {
                                    self.scroll_offset -= 1;
                                }
                            }
                            KeyCode::Down | KeyCode::Char('j') => {
                                self.scroll_offset += 1;
                            }
                            KeyCode::PageUp => {
                                self.scroll_offset = self.scroll_offset.saturating_sub(10);
                            }
                            KeyCode::PageDown => {
                                self.scroll_offset = self.scroll_offset.saturating_add(10);
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn draw<W: Write>(&self, out: &mut W) -> io::Result<()> {
        let (width, height) = terminal::size()?;
        let width = width as usize;
        let height = height as usize;

        execute!(out, cursor::MoveTo(0, 0), ResetColor)?;

        // Title bar
        execute!(
            out,
            SetBackgroundColor(Color::DarkCyan),
            SetForegroundColor(Color::Black)
        )?;
        let title = format!(
            " RAYA 2.0 FORENSIC WORKSTATION | Target: {} ",
            self.target_name
        );
        execute!(out, Print(format!("{:<width$}\r\n", title, width = width)))?;
        execute!(out, ResetColor)?;

        // Tab bar
        let tabs = [
            "[1] Overview",
            "[2] Sections",
            "[3] CFG",
            "[4] Strings & Crypto",
            "[5] Threat Matches",
        ];
        let mut tab_line = String::new();
        for (i, t) in tabs.iter().enumerate() {
            if i == self.active_tab {
                tab_line.push_str(&format!(" [-> {} <-] ", t));
            } else {
                tab_line.push_str(&format!("  {}  ", t));
            }
        }
        execute!(
            out,
            SetForegroundColor(Color::Cyan),
            Print(format!("{:<width$}\r\n", tab_line, width = width)),
            ResetColor
        )?;
        execute!(out, Print(format!("{}\r\n", "-".repeat(width))))?;

        // Render tab body
        let mut body_lines = Vec::new();
        match self.active_tab {
            0 => self.render_overview(&mut body_lines),
            1 => self.render_sections(&mut body_lines),
            2 => self.render_cfg(&mut body_lines),
            3 => self.render_strings_and_crypto(&mut body_lines),
            4 => self.render_threat_matches(&mut body_lines),
            _ => {}
        }

        // Available visible rows
        let visible_rows = height.saturating_sub(5);
        let start = self.scroll_offset.min(body_lines.len().saturating_sub(1));
        let slice = if body_lines.is_empty() {
            &[]
        } else {
            &body_lines[start..body_lines.len().min(start + visible_rows)]
        };

        for line in slice {
            execute!(out, Print(format!("{:<width$}\r\n", line, width = width)))?;
        }

        for _ in slice.len()..visible_rows {
            execute!(out, Print(format!("{:<width$}\r\n", " ", width = width)))?;
        }

        // Status bar
        execute!(
            out,
            SetBackgroundColor(Color::DarkGrey),
            SetForegroundColor(Color::White)
        )?;
        let status = " [Tab/1-5] Switch View | [Up/Down] Scroll | [q/Esc] Exit ";
        execute!(out, Print(format!("{:<width$}", status, width = width)))?;
        execute!(out, ResetColor)?;
        out.flush()?;
        Ok(())
    }

    fn render_overview(&self, lines: &mut Vec<String>) {
        let hashes = compute_hashes(self.data);
        lines.push(format!("File Size:    {} bytes", self.data.len()));
        lines.push(format!("Format:       {}", self.analysis.format.as_str()));
        lines.push(format!("Entropy:      {:.4} / 8.0", self.whole_entropy));
        lines.push(String::new());
        lines.push("Cryptographic Hashes:".to_string());
        lines.push(format!("  MD5:        {}", hashes.md5));
        lines.push(format!("  SHA-1:      {}", hashes.sha1));
        lines.push(format!("  SHA-256:    {}", hashes.sha256));
        if let Some(ref ss) = hashes.ssdeep {
            lines.push(format!("  SSDEEP:     {}", ss));
        }
        if let Some(ref pe) = self.analysis.pe {
            lines.push(String::new());
            lines.push("Portable Executable Details:".to_string());
            lines.push(format!(
                "  Architecture: {}",
                if pe.is_pe32_plus {
                    "PE32+ (64-bit)"
                } else {
                    "PE32 (32-bit)"
                }
            ));
            lines.push(format!("  Entry Point:  0x{:08X}", pe.entry_point));
            lines.push(format!("  Image Base:   0x{:016X}", pe.image_base));
            if let Some(ref imp) = pe.imphash {
                lines.push(format!("  Imphash:      {}", imp));
            }
            if let Some(ref auth) = self.analysis.authenticode {
                lines.push(format!(
                    "  Authenticode: {}",
                    if auth.is_signed { "Signed" } else { "Unsigned" }
                ));
            }
        }
        if let Some(ref go) = self.analysis.golang {
            lines.push(String::new());
            lines.push(format!(
                "Go Toolchain:   {}",
                go.version.as_deref().unwrap_or("Unknown")
            ));
        }
        if let Some(ref rust) = self.analysis.rust {
            lines.push(String::new());
            lines.push(format!(
                "Rust Toolchain: Commit {}",
                rust.rustc_commit.as_deref().unwrap_or("Unknown")
            ));
        }
    }

    fn render_sections(&self, lines: &mut Vec<String>) {
        if let Some(ref pe) = self.analysis.pe {
            lines.push(format!(
                "{:<12} {:<10} {:<10} {:<10} {:<14} Flags",
                "Section", "VirtSize", "RawSize", "Entropy", "Heatmap"
            ));
            lines.push("-".repeat(65));
            for s in &pe.sections {
                let filled = ((s.entropy / 8.0) * 10.0).round() as usize;
                let bar = format!("[{}{}]", "#".repeat(filled), ".".repeat(10 - filled));
                let flags = format!(
                    "{}{}{}",
                    if s.is_readable { "R" } else { "-" },
                    if s.is_writable { "W" } else { "-" },
                    if s.is_executable { "X" } else { "-" }
                );
                lines.push(format!(
                    "{:<12} {:<10} {:<10} {:<10.4} {:<14} {}",
                    s.name, s.virtual_size, s.raw_size, s.entropy, bar, flags
                ));
            }
        } else if let Some(ref elf) = self.analysis.elf {
            lines.push(format!(
                "{:<16} {:<12} {:<12} {:<10} Flags",
                "Section", "Address", "Size", "Entropy"
            ));
            lines.push("-".repeat(60));
            for s in &elf.sections {
                let flags = format!(
                    "{}{}{}",
                    if s.is_readable { "R" } else { "-" },
                    if s.is_writable { "W" } else { "-" },
                    if s.is_executable { "X" } else { "-" }
                );
                lines.push(format!(
                    "{:<16} 0x{:<10X} {:<12} {:<10.4} {}",
                    s.name, s.addr, s.size, s.entropy, flags
                ));
            }
        } else {
            lines.push("No section table present for target format.".to_string());
        }
    }

    fn render_cfg(&self, lines: &mut Vec<String>) {
        if let Some(ref cfg) = self.analysis.cfg {
            lines.push("Control Flow Graph (CFG) Metrics:".to_string());
            lines.push(format!("  Basic Blocks:          {}", cfg.blocks.len()));
            lines.push(format!("  Directed Edges:        {}", cfg.edges.len()));
            lines.push(format!(
                "  Cyclomatic Complexity: {} ({})",
                cfg.cyclomatic_complexity,
                if cfg.cyclomatic_complexity > 500 {
                    "EXTREME: Suspected Obfuscation"
                } else {
                    "Normal"
                }
            ));
            lines.push(format!("  Natural Loops:         {}", cfg.loops.len()));
            lines.push(format!(
                "  CFF Obfuscation:       {}",
                if cfg.is_flattened {
                    "DETECTED (Dispatcher / Switch Pattern)"
                } else {
                    "None detected"
                }
            ));
            lines.push(String::new());
            lines.push("First 15 Basic Blocks Sample:".to_string());
            for (_ip, bb) in cfg.blocks.iter().take(15) {
                lines.push(format!(
                    "  [BB @ 0x{:08X} - 0x{:08X}] ({} instructions)",
                    bb.start_ip, bb.end_ip, bb.instruction_count
                ));
            }
        } else {
            lines.push("No Control Flow Graph reconstructed for target binary.".to_string());
        }
    }

    fn render_strings_and_crypto(&self, lines: &mut Vec<String>) {
        lines.push(format!(
            "Recovered Stack Strings ({}):",
            self.analysis.stack_strings.len()
        ));
        for s in self.analysis.stack_strings.iter().take(12) {
            lines.push(format!("  [-] \"{}\" (VA: 0x{:X})", s.value, s.offset));
        }
        if self.analysis.stack_strings.len() > 12 {
            lines.push(format!(
                "  ... and {} more stack strings",
                self.analysis.stack_strings.len() - 12
            ));
        }
        lines.push(String::new());
        lines.push(format!(
            "Detected Cryptographic Constants ({}):",
            self.analysis.crypto.matches.len()
        ));
        for c in &self.analysis.crypto.matches {
            lines.push(format!(
                "  [-] [{}] {} at offset 0x{:X}",
                c.algorithm, c.description, c.offset
            ));
        }
        lines.push(String::new());
        lines.push(format!(
            "Detected Syscall Stubs ({}):",
            self.analysis.syscalls.len()
        ));
        for sys in &self.analysis.syscalls {
            lines.push(format!(
                "  [-] {:?} (SSN: 0x{:X}) at VA 0x{:X}",
                sys.stub_type,
                sys.ssn.unwrap_or(0),
                sys.address
            ));
        }
    }

    fn render_threat_matches(&self, lines: &mut Vec<String>) {
        lines.push("Active Threat & Rule Matches:".to_string());
        lines.push(
            "Use 'raya scan <target> -R rules/' for full multi-rule evaluation and evidence graph."
                .to_string(),
        );
        lines.push(String::new());
        if let Some(ref cfg) = self.analysis.cfg {
            if cfg.is_flattened {
                lines.push("  [MEDIUM] cfg_flattening_obfuscation (ATT&CK: T1027)".to_string());
                lines.push("    Evidence: CFF state-machine dispatcher detected".to_string());
            }
        }
        if !self.analysis.crypto.matches.is_empty() {
            lines.push("  [LOW] embedded_cryptographic_sboxes (ATT&CK: T1027)".to_string());
            for c in &self.analysis.crypto.matches {
                lines.push(format!(
                    "    Evidence: {} table at offset 0x{:X}",
                    c.algorithm, c.offset
                ));
            }
        }
        if !self.analysis.syscalls.is_empty() {
            lines.push("  [HIGH] direct_syscall_evasion (ATT&CK: T1055)".to_string());
            lines.push(format!(
                "    Evidence: {} raw syscall stubs bypassing ntdll.dll",
                self.analysis.syscalls.len()
            ));
        }
    }
}

pub fn launch_tui(target_name: &str, data: &[u8]) -> i32 {
    let mut session = TuiSession::new(target_name, data);
    if let Err(e) = session.run() {
        eprintln!("TUI Error: {}", e);
        return 1;
    }
    0
}
