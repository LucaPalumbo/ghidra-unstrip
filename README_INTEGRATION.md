# Ghidra Unstrip - Symbol Table + DWARF

Script Ghidra per aggiungere **symbol table** e **informazioni DWARF** a binari ELF stripped.

## 📋 Caratteristiche

- ✅ **Estrazione automatica** di funzioni, variabili e tipi da Ghidra
- ✅ **Symbol table** completa con binding e size
- ✅ **DWARF v2** con debug_info, debug_line, debug_abbrev
- ✅ **Decompilazione** automatica del codice sorgente
- ✅ **Type system** completo (struct, array, enum, pointer)
- ✅ **Line table** per mappatura indirizzo → sorgente
- ✅ **Variabili locali** con location expressions

## 🚀 Setup Iniziale

### 1. Installa dipendenze Python

```bash
pip install lief pyinstaller
```

### 2. Compila il binario add_symbols

```bash
./build_add_symbols.sh
```

Questo crea `dist/add_symbols` che verrà chiamato da Ghidra per aggiungere i simboli.

**Nota**: Il binario è necessario perché LIEF non è disponibile nell'ambiente Jython di Ghidra.

### 3. Verifica la compilazione

```bash
./dist/add_symbols
# Dovrebbe mostrare l'help
```

## 📖 Uso

### Da Ghidra Script Manager

1. Apri un binario ELF stripped in Ghidra
2. Aspetta che l'analisi automatica finisca
3. Apri il **Script Manager** (Window → Script Manager)
4. Cerca `ghidra_add_dwarf.py`
5. Esegui lo script (doppio click o tasto Run)

### Output

Lo script crea i seguenti file:

```
binary                          # Input originale
binary_symbols                  # + Symbol table
binary_symbols.dwarf            # + Symbol table + DWARF (FINALE)
binary_symbols.c                # Codice sorgente decompilato
binary_symbols.csv              # CSV con i simboli estratti
```

### Workflow Automatico

```
┌─────────────────────────────────────────────────────┐
│ STEP 1-2: Symbol Table                              │
│ ├─ Estrazione simboli da Ghidra                     │
│ ├─ Generazione CSV                                  │
│ └─ Chiamata binario add_symbols (LIEF)              │
└─────────────────────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────┐
│ STEP 3: DWARF Generation                            │
│ ├─ Creazione Compilation Unit                       │
│ ├─ Funzioni con parametri e variabili locali        │
│ ├─ Variabili globali                                │
│ ├─ Type system (struct, enum, array, pointer)       │
│ ├─ Line table (indirizzo → codice sorgente)         │
│ └─ Decompilazione e salvataggio .c                  │
└─────────────────────────────────────────────────────┘
                       ↓
           binary_symbols.dwarf (FINALE)
```

## 🔍 Verifica

### Symbol table

```bash
# Lista simboli
nm binary_symbols.dwarf | head

# Dettagli symbol table
readelf -s binary_symbols.dwarf | less
```

### DWARF

```bash
# Info debug
readelf --debug-dump=info binary_symbols.dwarf | less

# Line table
readelf --debug-dump=line binary_symbols.dwarf | less

# Tutte le sezioni debug
readelf -S binary_symbols.dwarf | grep debug
```

### Debug con GDB

```bash
gdb binary_symbols.dwarf

(gdb) info functions      # Lista funzioni
(gdb) info variables      # Lista variabili globali
(gdb) list main           # Mostra sorgente di main
(gdb) break main          # Breakpoint su main
(gdb) run
(gdb) backtrace           # Backtrace con nomi simbolici
(gdb) info locals         # Variabili locali
```

## 🛠️ Architettura

### File principali

```
ghidra_add_dwarf.py           # Script Ghidra principale
add_symbols_standalone.py     # Binario standalone per LIEF
add_symbols_standalone.spec   # Config PyInstaller
build_add_symbols.sh          # Script per compilare binario

lib/
├── libdwarf_producer.py      # Wrapper libdwarf Producer API
├── elf.py                    # Manipolazione ELF diretta
├── symbol_table.py           # Estrazione simboli + chiamata binario
└── add_symbols_lief.py       # DEPRECATED (ora usa standalone)
```

### Perché due processi?

- **Ghidra**: Usa **Jython 2.7** (Python 2 su JVM)
- **LIEF**: Richiede **CPython 3.x** con librerie native

**Soluzione**: 
1. Compiliamo `add_symbols_standalone.py` con PyInstaller → binario autonomo
2. Ghidra lo chiama via `subprocess`
3. Il binario legge CSV e scrive ELF con LIEF

## 🐛 Troubleshooting

### Binario add_symbols non trovato

```
[WARN] Binario add_symbols non trovato: dist/add_symbols
```

**Soluzione**: Compila il binario

```bash
./build_add_symbols.sh
```

### LIEF not found durante build

```
ERROR: LIEF not found
```

**Soluzione**:

```bash
pip install lief
```

### Errore durante estrazione simboli

Controlla il CSV generato:

```bash
cat binary_symbols.csv
```

Dovrebbe avere formato:

```csv
name,addr,type,size,binding,ndx
main,0x00400560,Function,100,global,1
printf,0x00400400,Function,,global,0
```

### Script Ghidra non esegue

1. Verifica che il binario sia ELF
2. Aspetta che l'analisi Ghidra finisca
3. Controlla la console Ghidra per errori

## 📚 Riferimenti

- [DWARF Debugging Standard](http://dwarfstd.org/)
- [libdwarf Documentation](https://www.prevanders.net/dwarf.html)
- [LIEF Documentation](https://lief-project.github.io/)
- [Ghidra Documentation](https://ghidra-sre.org/)

## 🤝 Contributi

Benvenuti! Apri una issue o pull request.

## 📄 Licenza

MIT License
