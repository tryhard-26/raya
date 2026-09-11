# Raya CLI Reference

Complete reference manual for the `raya` command-line utility.

---

## Global Options

* `-h, --help`: Displays usage information.
* `-V, --version`: Prints version information (`raya 0.1.0`).

---

## Subcommands

### 1. `raya scan`

Scans files or directories against detection rules.

```bash
raya scan <TARGET> [OPTIONS]
```

#### Arguments & Options

| Flag | Type | Description |
| :--- | :--- | :--- |
| `<TARGET>` | Path / `-` | Path to a target file, directory, or `-` for stdin stream. |
| `-r, --rules <PATH>` | Path | Path to a rule file (`.raya`, `.yar`) or directory containing rules. Default: `rules/`. |
| `-f, --format <FMT>` | String | Output format: `terminal` (default), `json`, `sarif`, `stix`. |
| `-p, --password <PWD>` | String | Optional password for decrypting `.zip` archives. (Auto-tries `infected`, `malware`, `password`, `clean`, `1234` by default). |
| `--save-rules <FILE>` | Path | Serializes compiled rule AST to a fast binary cache file. |
| `--load-rules <FILE>` | Path | Loads precompiled binary rule cache instead of parsing text rules. |
| `--pid <PID>` | Integer | Inspects and scans the virtual memory of a running OS process. |
| `--all` | Flag | Scan all files without skipping known benign extensions. |
| `--max-size <BYTES>` | Integer | Maximum file size in bytes to scan (default: 100MB). |

#### Exit Codes

* `0`: Clean scan. No rules matched across all evaluated targets.
* `1`: Malicious detection. One or more rules matched with evidence.
* `2`: Operational error (invalid arguments, unreadable path, parsing failure).

---

### 2. `raya check`

Validates the syntax and compilation of Raya and YARA-compatible rules.

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

### 3. `raya test`

Runs an automated test harness validating rules against expected sample fixtures.

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

### 4. `raya bench`

Measures execution speed and throughput of Raya's pattern-matching engine across varying payload sizes.

```bash
raya bench --rules rules/
```
