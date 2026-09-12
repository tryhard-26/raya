# Raya CLI Reference

Complete reference manual for the `raya` command-line utility.

---

## Global Options

* `-h, --help`: Displays usage information.
* `-V, --version`: Prints version information (`raya 0.3.0`).

---

## Subcommands Summary

| Command | Arguments | Description |
| :--- | :--- | :--- |
| `scan` | `<TARGET> --rules <PATH>` | Scans files, directories, stdin, or process memory against detection rules. |
| `inspect` | `<TARGET> [--json]` | Interactive forensic inspection dashboard (hashes, entropy, headers, crypto, strings, runtimes). |
| `convert` | `<INPUT.yar> -o <OUTPUT.raya>` | Transpiles legacy YARA rules into native Raya detection rules. |
| `check` | `<RULES_PATH>` | Validates rule syntax, AST construction, and pattern compilation. |
| `compile` | `<RULES_PATH> -o <OUTPUT>` | Compiles rules into a serialized binary format for rapid loading. |
| `test` | `<SPEC_PATH>` | Runs automated rule verification against test fixture specifications. |
| `bench` | `--rules <PATH>` | Measures pattern-matching throughput and scan duration across samples. |

---

## Subcommands Reference

### 1. `raya scan`

Scans files or directories against detection rules.

```bash
raya scan <TARGET> [OPTIONS]
```

#### Arguments & Options

| Flag | Type | Description |
| :--- | :--- | :--- |
| `<TARGET>` | Path / `-` | Path to a target file, directory, or `-` for standard input stream. |
| `-r, --rules <PATH>` | Path | Path to a rule file (`.raya`, `.yar`) or directory containing rules. Default: `rules/`. |
| `-f, --format <FMT>` | String | Output format: `terminal` (default), `json`, `sarif`, `stix`. |
| `-o, --output <FILE>` | Path | Write scan report to file instead of standard output. |
| `-p, --password <PWD>` | String | Optional password for decrypting `.zip` archives. (Auto-tries standard malware passwords by default). |
| `-c, --compiled <FILE>` | Path | Loads precompiled binary rule cache instead of parsing text rules. |
| `--save-rules <FILE>` | Path | Serializes compiled rule AST to a fast binary cache file. |
| `--pid <PID>` | Integer | Inspects and scans the virtual memory of a running OS process. |
| `--all` | Flag | Scan all files without skipping known benign extensions. |
| `--max-size <BYTES>` | Integer | Maximum file size in bytes to scan (default: 100MB). |
| `--workers <NUM>` | Integer | Thread pool size for directory scans (default: logical CPU count). |
| `-v, --verbose` | Flag | Enable detailed debug logging and verbose output. |

#### Exit Codes

* `0`: Clean scan. No rules matched across all evaluated targets.
* `1`: Malicious detection. One or more rules matched with evidence.
* `2`: Operational error (invalid arguments, unreadable path, parsing failure).

---

### 2. `raya inspect`

Performs deep forensic binary triage and structural inspection. Generates comprehensive file metrics, cryptographic hashes (including fuzzy and header hashes), visual entropy heatmaps, section permissions, embedded cryptographic constants, deobfuscated stack strings, and runtime metadata (.NET, Go, Rust).

```bash
raya inspect <TARGET> [OPTIONS]
```

#### Arguments & Options

| Flag | Type | Description |
| :--- | :--- | :--- |
| `<TARGET>` | Path | Path to executable file (PE, ELF, Mach-O, or raw binary). |
| `--json` | Flag | Output structured forensic triage data as JSON. |

#### Example

```bash
# Terminal forensic dashboard
raya inspect samples/malware/dropper.exe

# JSON output for automated pipelines
raya inspect samples/malware/dropper.exe --json
```

---

### 3. `raya convert`

Transpiles legacy YARA rules (`.yar` / `.yara`) into native Raya rules (`.raya`), stripping unsupported C-module imports and validating rule syntax.

```bash
raya convert <INPUT> -o <OUTPUT>
```

#### Arguments & Options

| Flag | Type | Description |
| :--- | :--- | :--- |
| `<INPUT>` | Path | Path to input YARA rule file. |
| `-o, --output <OUTPUT>` | Path | Destination path for the converted `.raya` rule file. |

#### Example

```bash
raya convert external_signatures.yar -o rules/transpiled.raya
```

---

### 4. `raya check`

Validates the syntax, AST structure, and compilation of Raya and YARA-compatible rules without performing a scan.

```bash
raya check <PATH> [OPTIONS]
```

#### Options

* `-v, --verbose`: Prints individual validation results for every parsed rule file.

#### Example

```bash
raya check rules/ --verbose
```

---

### 5. `raya compile`

Compiles text-based rules into a serialized binary format (`.bin`) for high-throughput operational deployments, eliminating AST parsing overhead during startup.

```bash
raya compile <RULES_PATH> -o <OUTPUT>
```

#### Example

```bash
raya compile rules/ -o /opt/raya/signatures.bin
raya scan sample.exe -c /opt/raya/signatures.bin
```

---

### 6. `raya test`

Runs an automated test harness validating rules against expected sample fixtures, computing coverage and detecting regressions (false positives and false negatives).

```bash
raya test <SPEC_FILE>
```

#### Test Spec Schema (`test_spec.json`)

```json
[
  {
    "sample": "tests/fixtures/sample_injection.exe",
    "expected_rules": ["process_injection", "advanced_memory_tampering"]
  },
  {
    "sample": "tests/fixtures/clean_application.exe",
    "expected_rules": []
  }
]
```

---

### 7. `raya bench`

Measures execution speed and throughput of Raya's pattern-matching engine across varying payload sizes.

```bash
raya bench --rules rules/
```
