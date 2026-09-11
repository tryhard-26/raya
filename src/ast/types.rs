use std::collections::HashMap;
use std::fmt;

/// Severity classification for detection rules and scan alerts.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational indicators or benign environmental markers.
    Info,
    /// Low-priority suspicious indicators.
    Low,
    /// Medium-priority suspicious indicators (default severity).
    Medium,
    /// High-confidence malicious patterns or known threat behaviors.
    High,
    /// Critical confirmed threats (e.g. ransomware, active exploits, backdoors).
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for Severity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "info" => Ok(Severity::Info),
            "low" => Ok(Severity::Low),
            "medium" | "med" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "critical" | "crit" => Ok(Severity::Critical),
            _ => Err(format!("Unknown severity: {}", s)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum MetaValue {
    String(String),
    Integer(i64),
    Float(f64),
    Boolean(bool),
}

impl fmt::Display for MetaValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MetaValue::String(s) => write!(f, "\"{}\"", s),
            MetaValue::Integer(i) => write!(f, "{}", i),
            MetaValue::Float(fl) => write!(f, "{}", fl),
            MetaValue::Boolean(b) => write!(f, "{}", b),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum HexToken {
    Exact(u8),
    Wildcard,                                // ??
    HighNibble(u8),                          // e.g. 4?
    LowNibble(u8),                           // e.g. ?8
    Jump { min: usize, max: Option<usize> }, // e.g. [4-8], [-8], [4-], [4]
    Alternation(Vec<Vec<HexToken>>),         // e.g. ( 11 22 | 33 44 )
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum StringPattern {
    Literal {
        bytes: Vec<u8>,
        ascii: bool,
        wide: bool,
        nocase: bool,
        fullword: bool,
        xor: Option<(u8, u8)>,
        base64: bool,
        base64wide: bool,
    },
    Hex {
        tokens: Vec<HexToken>,
    },
    Regex {
        pattern: String,
        nocase: bool,
        fullword: bool,
    },
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct StringDefinition {
    pub id: String,
    pub pattern: StringPattern,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BinaryOperator {
    Eq,
    Neq,
    Lt,
    Lte,
    Gt,
    Gte,
    Add,
    Sub,
    Mul,
    Div,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum SetSelector {
    Them,
    Wildcard(String),
    List(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum Expr {
    Boolean(bool),
    Integer(i64),
    Float(f64),
    StringLit(String),
    StringRef(String),
    StringCount(String),
    StringOffset(String),
    Not(Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Binary {
        left: Box<Expr>,
        op: BinaryOperator,
        right: Box<Expr>,
    },
    CountOf {
        count: Box<Expr>,
        set: SetSelector,
    },
    AnyOf(SetSelector),
    AllOf(SetSelector),
    NoneOf(SetSelector),
    FunctionCall {
        module: String,
        function: String,
        args: Vec<Expr>,
    },
    MemberAccess {
        object: Box<Expr>,
        property: String,
        sub_property: Option<String>,
    },
    Variable(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct SourceLocation {
    pub line: usize,
    pub column: usize,
}

impl fmt::Display for SourceLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.line, self.column)
    }
}

/// Parsed Abstract Syntax Tree (AST) representation of a Raya detection rule.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Rule {
    /// Unique identifier / rule name.
    pub name: String,
    /// Tags attached to the rule for taxonomy or filtering.
    pub tags: Vec<String>,
    /// Key-value metadata table (`author`, `description`, `severity`, `technique`).
    pub meta: HashMap<String, MetaValue>,
    /// Pattern definitions (`strings:` section).
    pub strings: Vec<StringDefinition>,
    /// Boolean logic expression tree (`condition:` section).
    pub condition: Expr,
    /// Originating line and column in the source file.
    pub location: SourceLocation,
}

impl Rule {
    /// Returns the rule severity extracted from `meta.severity`, defaulting to [`Severity::Medium`].
    pub fn severity(&self) -> Severity {
        if let Some(MetaValue::String(s)) = self.meta.get("severity") {
            s.parse::<Severity>().unwrap_or(Severity::Medium)
        } else {
            Severity::Medium
        }
    }

    pub fn description(&self) -> Option<&str> {
        match self.meta.get("description") {
            Some(MetaValue::String(s)) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn author(&self) -> Option<&str> {
        match self.meta.get("author") {
            Some(MetaValue::String(s)) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn mitre_technique(&self) -> Option<&str> {
        match self.meta.get("technique") {
            Some(MetaValue::String(s)) => Some(s.as_str()),
            _ => None,
        }
    }
}
