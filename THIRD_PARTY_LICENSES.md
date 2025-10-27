# Third Party Licenses

This project uses the following third-party software and libraries:

---

## libdwarf

- **License:** LGPL v2.1 (GNU Lesser General Public License)
- **Source:** https://github.com/davea42/libdwarf-code
- **Copyright:** Copyright (C) 2000-2023 David Anderson
- **Usage:** Dynamically linked via Python ctypes for DWARF generation
- **Files:** `lib/libdwarf.so`

**Note:** This library is dynamically linked and distributed as a separate binary file. Users can replace it with their own version if needed.

Full LGPL v2.1 license text: https://www.gnu.org/licenses/old-licenses/lgpl-2.1.html

---

## ghidra2dwarf (Code Inspiration)

- **License:** MIT License
- **Source:** https://github.com/cesena/ghidra2dwarf
- **Copyright:** Copyright (c) 2021 Cesena
- **Usage:** Code patterns, concepts, and architectural inspiration for DWARF generation

**MIT License Text:**
```
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

---

## syms2elf (Inspiration)

- **License:** MIT License
- **Source:** https://github.com/nick0ve/syms2elf
- **Copyright:** Copyright (c) 2020 nick0ve
- **Usage:** Concepts for symbol table manipulation

---

## Python Dependencies

### LIEF (Library to Instrument Executable Formats)

- **License:** Apache License 2.0
- **Source:** https://github.com/lief-project/LIEF
- **Copyright:** Copyright (c) 2017 - 2023 Quarkslab
- **Usage:** ELF binary manipulation and symbol table creation
- **Installation:** `pip install lief`

Full Apache 2.0 license: https://www.apache.org/licenses/LICENSE-2.0

---

### PyInstaller

- **License:** GPL v2 + exception for bundled applications
- **Source:** https://github.com/pyinstaller/pyinstaller
- **Usage:** Building standalone executables (development/build only)
- **Note:** The GPL exception allows distributing applications built with PyInstaller under any license

---

## Ghidra

- **License:** Apache License 2.0
- **Source:** https://github.com/NationalSecurityAgency/ghidra
- **Copyright:** Copyright (C) 2019 National Security Agency
- **Usage:** Reverse engineering framework that this script extends
- **Website:** https://ghidra-sre.org/

---

## Summary

This project (Ghidra Unstrip) is licensed under **MIT License**.

The dynamically linked library **libdwarf** is licensed under **LGPL v2.1**, which permits dynamic linking with MIT-licensed code. The library is distributed as a separate binary file (`lib/libdwarf.so`) and users are free to replace it with their own version.

All other dependencies and inspirations are either MIT or Apache 2.0 licensed, which are fully compatible with the MIT License.

---

## Compliance

To comply with the above licenses:

1. **libdwarf (LGPL v2.1):**
   - Distributed as separate dynamic library (`.so` file)
   - Users can replace with their own build
   - Source code available at: https://github.com/davea42/libdwarf-code

2. **MIT Licensed components:**
   - Original copyright notices preserved
   - Permission notices included

3. **Apache 2.0 components:**
   - Notice of Apache License included
   - No modifications to Apache-licensed code (used as-is via pip)

---

Last updated: October 27, 2025
