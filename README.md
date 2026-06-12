# ZipCracker-Rust ⚡

[![Rust](https://img.shields.io/badge/language-Rust-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**ZipCracker-Rust** is a high-performance ZIP forensic and password recovery tool designed for security professionals, CTF players, and data recovery tasks. Rebuilt from the ground up in Rust, it delivers extreme concurrency and memory safety while enhancing the logic of the original Python implementation.

---

## 🌟 Core Features

-   **⚡ Extreme Performance**: Powered by the `Rayon` work-stealing parallel engine, achieving cracking speeds several times faster than traditional scripts.
-   **🧩 Full Attack Suite**:
    -   **Dict**: Supports massive dictionaries and a fast built-in `preset` library.
    -   **Mask**: Flexible mask definitions (`?d`, `?l`, `?u`, `?s`) with mixed charset support.
    -   **Brute**: Pure brute-force mode with customizable length ranges.
    -   **CRC32**: Seconds-level plaintext recovery for short files (1-6 bytes) via CRC32 collision.
-   **🛡️ Advanced Forensics**:
    -   **Pseudo-encryption Repair**: Automatically identifies and fixes manipulated `Entry Header` flags.
    -   **Deep Structure Analysis**: Inspect compression algorithms (Deflate/Store), encryption standards (ZipCrypto/AES-256), and file comments.
    -   **SyncTime Recovery**: Automatically synchronizes original filesystem `mtime/atime` during extraction to preserve digital evidence.
-   **🔗 Automated KPA (Known-Plaintext Attack)**:
    -   Deep integration with `bkcrack`, featuring built-in templates for common file headers (PNG, ZIP, EXE, PCAPNG).
    -   Workflow: Template Matching -> Key Collision -> Password Recovery -> Decryption (all-in-one process).

---

## 🚀 Quick Start

### 1. Build from Source
Ensure you have the [Rust](https://www.rust-lang.org/learn/get-started) environment installed:

```bash
git clone https://github.com/your-repo/ZipCracker_Rust.git
cd ZipCracker_Rust
cargo build --release
```
The binary will be located at `target/release/zipcracker`.

### 2. Command Overview

| Command | Description | Typical Use Case |
| :--- | :--- | :--- |
| `info` | Show ZIP structure details | Identify encryption and file composition |
| `dict` | Dictionary attack | Target specific password lists |
| `mask` | Mask attack | When partial password structure is known |
| `brute` | Pure brute-force | No clues available |
| `crc32` | CRC32 collision | For files with extremely short content |
| `fix` | Pseudo-encryption fix | Handle ZIP deception/obfuscation |
| `kpa` | Known-Plaintext Attack | Efficient attack against ZipCrypto |
| `extract` | Extract with time-sync | Final step after obtaining the password |

---

## 💡 Usage Examples

### 1. Analysis & Repair
```bash
# Analyze ZIP internals
zipcracker info test.zip

# Repair pseudo-encryption
zipcracker fix test.zip -D fixed.zip
```

### 2. Versatile Cracking
```bash
# Use built-in common dictionary
zipcracker dict -f secret.zip -d preset

# Mask attack: 4 digits + 2 lowercase letters
zipcracker mask -f secret.zip -m "?d?d?d?d?l?l"

# Brute-force: digits from length 1 to 4
zipcracker brute -f secret.zip --min 1 --max 4
```

### 3. Advanced KPA (Known-Plaintext)
> Requires `bkcrack` to be installed and available in your PATH.

```bash
# Scenario: Known PNG file inside. Automate everything using the built-in template.
zipcracker kpa -f cipher.zip --template png --recover --output result.zip
```

---

## 🛠️ Technical Insights (Why Rust?)

Traditional ZIP crackers are often throttled by interpreter overhead when dealing with massive search spaces. **ZipCracker-Rust** addresses these bottlenecks through:
1.  **Zero GC Overhead**: Zero-cost abstractions ensure CPU cycles are spent on hash computation, not memory management.
2.  **Zero-Copy Data Access**: Utilizes reference counting and smart locks to share ZIP handles across threads without redundant memory bandwidth consumption.
3.  **LLVM Optimization**: Leverages deep inlining and vectorization provided by the Rust compiler in `--release` mode.

---

## ⚠️ Disclaimer
This tool is intended for security research, authorized testing, and data recovery only. Users must comply with all applicable local laws. The author assumes no liability for any unauthorized use or damage caused by this tool.
