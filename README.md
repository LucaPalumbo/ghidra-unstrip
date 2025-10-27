# Ghidra Unstrip

**Restore symbol table and DWARF debug information to stripped ELF binaries using Ghidra analysis**

Ghidra Unstrip automatically extracts functions, variables, types, and decompiled source code from Ghidra's analysis and adds both **symbol table** (.symtab) and **DWARF debug info** to stripped binaries, making them fully debuggable with GDB and other tools.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## 🚀 Quick Start

### Installation

```bash
# 1. Download the latest release
# Go to: https://github.com/LucaPalumbo/ghidra-unstrip/releases/latest
# Download: ghidra-unstrip-linux.zip

# 2. Extract the archive
unzip ghidra-unstrip-linux.zip
cd ghidra-unstrip/

# 3. Add to Ghidra
# In Ghidra: Window → Script Manager → Manage Script Directories (button with folder icon)
# Click the green "+" button and select the ghidra-unstrip/ folder
```

**That's it!** The script will now appear in Ghidra's Script Manager.

> **Note:** The release includes the pre-built `add_symbols` binary and the required library - libdwarf.so.

### Usage

1. **Rename functions/variables** as you would do
2. **Open Script Manager** (Window → Script Manager)
3. **Run** `unstrip.py` (double-click or right-click → Run)
4. **Wait for completion** (may take a few minutes for large binaries)

**Output files:**

```
binary_symbols.csv         # Extracted symbols (CSV format)
binary_symbols             # ELF with symbol table
binary_symbols.dwarf       # ELF with symbols + DWARF (FINAL)
binary_symbols.c           # Decompiled source code
```

---

## 🔍 Yet another tool

Yes, there are other excellent tools that inspired this project:

### Existing Tools

- **[ghidra2dwarf](https://github.com/cesena/ghidra2dwarf)** by Cesena - Generates DWARF debug info from Ghidra analysis. Excellent tool for adding debug information, but **does not restore the symbol table** (.symtab).

- **[syms2elf](https://github.com/nick0ve/syms2elf)** by nick0ve - Adds symbols to ELF binaries. Great for restoring function names, but **does not generate DWARF debug information**.



**The problem:** None of the existing tools provide **both** symbol table restoration **and** DWARF debug information generation in a single workflow.


**Ghidra Unstrip bridges this gap** by providing both in one tool, making the restored binary maximally compatible with all debugging and analysis tools.

---

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.


---

*Happy Reversing! 🔧*
