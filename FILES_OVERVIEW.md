# File Overview

## 🎯 File Principali

### `ghidra_add_dwarf.py` ⭐ **MAIN SCRIPT**
Script Ghidra che orchestra tutto:
- Estrae simboli da Ghidra
- Chiama `add_symbols` per aggiungerli al binario
- Genera DWARF con debug info
- Decompila codice sorgente

**Uso**: Run da Ghidra Script Manager

---

### `add_symbols_standalone.py` ⭐ **SIMBOLI (LIEF)**
Script standalone che aggiunge symbol table usando LIEF.
Viene compilato in binario e chiamato da Ghidra.

**Compilazione**:
```bash
./build_add_symbols.sh
```

**Output**: `dist/add_symbols` (binario eseguibile)

---

## 🔧 Script di Build

### `build_add_symbols.sh`
Compila `add_symbols_standalone.py` con PyInstaller.

**Uso**:
```bash
./build_add_symbols.sh
```

### `add_symbols_standalone.spec`
Configurazione PyInstaller per build ottimizzato.

---

## 📚 Librerie (lib/)

### `lib/libdwarf_producer.py`
Wrapper Python per libdwarf Producer API (C library).
Gestisce creazione DWARF: DIEs, attributes, line table.

### `lib/symbol_table.py`
- Estrazione simboli da Ghidra → CSV
- Chiamata binario `add_symbols` via subprocess

### `lib/elf.py`
Manipolazione diretta sezioni ELF (scrittura DWARF).

### `lib/add_symbols_lief.py` (DEPRECATED)
Vecchia versione che importava LIEF direttamente.
Non funziona in Ghidra (Jython). Usare standalone invece.


---

## 📖 Documentazione

### `QUICKSTART.md` ⭐
Guida rapida per iniziare.

### `README_INTEGRATION.md`
Documentazione completa dell'architettura.

### `USAGE.md`
Esempi d'uso dettagliati.

---


## 📦 Workflow Completo

```
1. Setup (una volta):
   ./build_add_symbols.sh

2. Uso normale:
   Ghidra → Run ghidra_add_dwarf.py
   
3. Output:
   binary_symbols.dwarf (con simboli + DWARF)
   binary_symbols.c (sorgente decompilato)
```

---

## 🏗️ Architettura

```
┌──────────────────────────────────────────────┐
│ Ghidra (Jython 2.7)                          │
│                                              │
│  ghidra_add_dwarf.py                         │
│    ├─ Estrae simboli → CSV                   │
│    │   (lib/symbol_table.py)                 │
│    │                                          │
│    ├─ Chiama binario esterno ────────────┐   │
│    │   (subprocess)                       │   │
│    │                                      │   │
│    └─ Genera DWARF                       │   │
│        (lib/libdwarf_producer.py)        │   │
│        (lib/elf.py)                      │   │
└──────────────────────────────────────────┼───┘
                                           │
                                           ↓
                        ┌──────────────────────────────┐
                        │ Processo separato (CPython)  │
                        │                              │
                        │  dist/add_symbols            │
                        │    (da add_symbols_standalone.py) │
                        │                              │
                        │  ├─ Legge CSV                │
                        │  ├─ Usa LIEF                 │
                        │  └─ Scrive ELF + symbols     │
                        └──────────────────────────────┘
```

## ❓ FAQ

**Q: Perché due processi?**
A: Ghidra usa Jython (Python 2 su JVM), LIEF richiede CPython 3.

**Q: Devo ricompilare ogni volta?**
A: No, solo alla prima installazione o se modifichi `add_symbols_standalone.py`.

**Q: Posso usare solo i simboli senza DWARF?**
A: Sì, usa solo `dist/add_symbols` manualmente:
```bash
./dist/add_symbols input.elf symbols.csv output.elf
```

**Q: Posso usare solo DWARF senza simboli?**
A: Sì, modifica `ghidra_add_dwarf.py` e salta lo STEP 1-2.
