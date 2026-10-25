# 🍃 Leaf Mod Analyzer

```text
 ██╗     ███████╗ █████╗ ███████╗
 ██║     ██╔════╝██╔══██╗██╔════╝
 ██║     █████╗  ███████║█████╗  
 ██║     ██╔══╝  ██╔══██║██╔══╝  
 ███████╗███████╗██║  ██║██║     
 ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝     
  █▀▄▀█ █▀█ █▀▄   ▄▀█ █▄░█ ▄▀█ █░░ █▄█ ▀█ █▀▀ █▀█
  █░▀░█ █▄█ █▄▀   █▀█ █░▀█ █▀█ █▄▄ ░█░ █▄ ██▄ █▀▄
   Website: https://mods.merud.online/  • Minecraft Mod & Cheat Scanner
```

**Leaf Mod Analyzer** is a blazing fast static bytecode & security analyzer for Minecraft mods (`.jar` files) written in Rust. It inspects compiled JVM bytecode, constant pools, annotations, and opcodes in sub-millisecond speeds without executing untrusted code or requiring a JVM runtime.

---

## ⚡ Features

* **Zero JVM Dependency**: Parses JVM class files and ZIP archives directly in pure native Rust.
* **Extreme Performance**: Scans dozens of mods in under a second (e.g. 50 mods in ~900ms).
* **Embedded Rule Engine**: Includes out-of-the-box detection signatures:
  * **Obfuscation**: Aggressive single/short-letter renaming, control-flow flattening (CFF switch density).
  * **Packers & Crypters**: High entropy bytecode classes, encrypted string pool literals.
  * **Deception**: Visual confusables and mixed-script homoglyphs (e.g. Cyrillic lookalikes in identifiers).
  * **Combat / Cheat Modifications**: Hitbox expansion (`grow`/`inflate`), entity iterator hooks, Mixin overrides.
* **Loader Auto-Detection**: Detects Fabric, Forge, NeoForge, and Quilt via archive manifests and configurations.
* **Missing Entrypoints Audit**: Validates that all declared mod entrypoints exist in bytecode.
* **Dual Output**: Clean colorized terminal tables or structured JSON (`--json`).

---

## 🚀 Quick Start

### Pre-built Binaries
Download the latest pre-compiled binary for your OS from [GitHub Releases](https://github.com/gemakfy/leaf-mod-analyzer/releases):
* **Windows**: `leaf-mod-analyzer.exe`
* **Linux**: `leaf-mod-analyzer`

---

## 💻 CLI Usage

### Scan a single mod
```bash
leaf-mod-analyzer MyMod.jar
```

### Scan an entire folder of mods
```bash
leaf-mod-analyzer path/to/mods/
```

### Output structured JSON (ideal for CI/CD or scripting)
```bash
leaf-mod-analyzer --json path/to/mods/
```

### Use custom rules
```bash
leaf-mod-analyzer --rules custom_rules.json MyMod.jar
leaf-mod-analyzer --rules ./my_rules_dir/ path/to/mods/
```

### Command-line Options
```text
Usage: leaf-mod-analyzer [OPTIONS] [PATH]

Arguments:
  [PATH]  Path to a .jar file or directory containing .jar files [default: .]

Options:
  -r, --rules <RULES>    Path to custom rule JSON file or directory
  -l, --loader <LOADER>  Override mod loader (fabric, forge, neoforge, quilt, any)
      --json             Output full scan results in JSON format
  -h, --help             Print help
  -V, --version          Print version
```

---

## 🛠 Building from Source

Prerequisites: [Rust 1.80+](https://rustup.rs/)

```bash
# Clone the repository
git clone https://github.com/gemakfy/leaf-mod-analyzer.git
cd leaf-mod-analyzer

# Build standalone release binary
cargo build --release --bin leaf-mod-analyzer

# Binary will be located at:
# target/release/leaf-mod-analyzer (Linux/macOS)
# target/release/leaf-mod-analyzer.exe (Windows)
```

---

## 🌐 Web Service
Prefer a web interface? Check out our online scanner at [mods.merud.online](https://mods.merud.online/).

## 📄 License
MIT License.
