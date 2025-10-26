# Quick Start Guide

## Prima volta (setup)

```bash
# 1. Installa dipendenze
pip install lief pyinstaller

# 2. Compila binario add_symbols
./build_add_symbols.sh

# 3. Testa il binario
./test_add_symbols.sh
```

## Uso da Ghidra

1. Apri binario ELF in Ghidra
2. Aspetta analisi automatica
3. **Window** → **Script Manager**
4. Cerca `ghidra_add_dwarf.py`
5. **Run** (doppio click)

## Output

```
binary_symbols.dwarf    ← File finale con simboli + DWARF
binary_symbols.c        ← Codice sorgente decompilato
binary_symbols.csv      ← Simboli estratti
```

## Verifica con GDB

```bash
gdb binary_symbols.dwarf
(gdb) info functions
(gdb) list main
(gdb) break main
```

## Problemi?

### Binario non trovato
```bash
./build_add_symbols.sh
```

### LIEF non installato
```bash
pip install lief
```

### Errori Ghidra
Controlla la console Ghidra per dettagli

## Architettura

```
Ghidra (Jython)
    ↓
1. Estrae simboli → CSV
    ↓
2. Chiama add_symbols (binario esterno)
    ↓ (usa LIEF)
3. ELF + symbol table
    ↓
4. Aggiunge DWARF
    ↓
ELF finale con simboli + DWARF
```
