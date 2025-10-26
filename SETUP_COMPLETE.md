# 🎉 Ghidra Unstrip - Setup Completo

## ✅ Completato!

Ho integrato la funzionalità di aggiunta symbol table nello script Ghidra.
Ora quando esegui `ghidra_add_dwarf.py`, lo script:

1. ✅ Estrae simboli da Ghidra
2. ✅ Li aggiunge al binario (tramite LIEF in processo separato)
3. ✅ Aggiunge informazioni DWARF complete
4. ✅ Genera codice sorgente decompilato

---

## 🚀 Setup (prima volta)

### 1. Installa dipendenze

```bash
pip install lief pyinstaller
```

### 2. Compila il binario add_symbols

```bash
cd /home/feld/ghidra_scripts/ghidra-unstrip
./build_add_symbols.sh
```

Questo crea `dist/add_symbols` (binario ~15-20 MB).

### 3. Verifica

```bash
./test_add_symbols.sh
```

---

## 📖 Uso

### Da Ghidra

1. Apri un binario ELF stripped in Ghidra
2. Aspetta che l'analisi automatica finisca (vedi barra progresso in basso)
3. Apri **Script Manager**: `Window` → `Script Manager`
4. Cerca `ghidra_add_dwarf.py` nella lista
5. Esegui con **doppio click** o pulsante **Run**

### Output creato

```
/path/to/binary_symbols           ← ELF + symbol table
/path/to/binary_symbols.dwarf     ← ELF + symbols + DWARF (FINALE)
/path/to/binary_symbols.c         ← Codice sorgente decompilato
/path/to/binary_symbols.csv       ← CSV con simboli (intermedio)
```

### Verifica risultato

```bash
# Simboli
nm binary_symbols.dwarf | head
readelf -s binary_symbols.dwarf

# DWARF
readelf --debug-dump=info binary_symbols.dwarf | head -50
readelf --debug-dump=line binary_symbols.dwarf

# Debug con GDB
gdb binary_symbols.dwarf
(gdb) info functions
(gdb) list main
(gdb) break main
```

---

## 🏗️ Architettura

### Perché processo separato per LIEF?

- **Ghidra** = Jython 2.7 (Python 2 su JVM)
- **LIEF** = Richiede CPython 3.x con librerie native C++

**Soluzione**:
1. Compiliamo `add_symbols_standalone.py` → binario autonomo
2. Ghidra lo chiama via `subprocess.call()`
3. Il binario legge CSV con simboli e scrive ELF usando LIEF

### Workflow

```
┌─────────────────────────────────────────────────┐
│ Ghidra (Jython)                                 │
│                                                 │
│ ghidra_add_dwarf.py:                            │
│  ├─ Estrae funzioni/variabili da analisi       │
│  ├─ Genera CSV con simboli                     │
│  └─ subprocess.call(add_symbols)  ───────────┐ │
└──────────────────────────────────────────────┼─┘
                                               │
                                               ↓
                    ┌──────────────────────────────────┐
                    │ Processo esterno (CPython 3)     │
                    │                                  │
                    │ dist/add_symbols (binario LIEF)  │
                    │  ├─ Legge CSV                    │
                    │  ├─ Crea symbol table            │
                    │  └─ Scrive binary_symbols        │
                    └──────────────────────────────────┘
                                               │
                                               ↓
┌──────────────────────────────────────────────┴─┐
│ Ghidra (continua)                              │
│                                                │
│  ├─ Carica binary_symbols                     │
│  ├─ Genera DWARF (libdwarf)                   │
│  │   ├─ .debug_info (funzioni, var, tipi)    │
│  │   ├─ .debug_line (source mapping)         │
│  │   └─ .debug_abbrev                        │
│  ├─ Scrive sezioni DWARF                      │
│  └─ Salva binary_symbols.dwarf                │
└────────────────────────────────────────────────┘
```

---

## 📁 File Principali

| File | Descrizione |
|------|-------------|
| `ghidra_add_dwarf.py` | **Script Ghidra principale** |
| `add_symbols_standalone.py` | Script per LIEF (compilato → binario) |
| `build_add_symbols.sh` | Compila binario add_symbols |
| `lib/libdwarf_producer.py` | Wrapper libdwarf (genera DWARF) |
| `lib/symbol_table.py` | Estrazione simboli + chiamata binario |
| `lib/elf.py` | Manipolazione sezioni ELF |

**Documentazione**:
- `QUICKSTART.md` - Guida rapida
- `README_INTEGRATION.md` - Architettura completa
- `FILES_OVERVIEW.md` - Descrizione tutti i file

---

## 🐛 Troubleshooting

### ❌ Binario add_symbols non trovato

```
[WARN] Binario add_symbols non trovato: dist/add_symbols
[INFO] Continuo comunque con il DWARF sul binario originale...
```

**Soluzione**: Compila il binario

```bash
./build_add_symbols.sh
```

---

### ❌ LIEF not installed

Durante `./build_add_symbols.sh`:

```
ERROR: LIEF not found
```

**Soluzione**:

```bash
pip install lief
# o con pip3 se hai più versioni Python
pip3 install lief
```

---

### ❌ PyInstaller not found

```
ERROR: PyInstaller not found
```

**Soluzione**:

```bash
pip install pyinstaller
```

---

### ⚠️ Lo script funziona ma non aggiunge simboli

Verifica:

1. Il binario esiste?
   ```bash
   ls -lh dist/add_symbols
   ```

2. È eseguibile?
   ```bash
   chmod +x dist/add_symbols
   ```

3. Testa manualmente:
   ```bash
   ./dist/add_symbols
   # Dovrebbe mostrare usage
   ```

---

### ⚠️ Errore durante DWARF

Lo script salta l'aggiunta simboli ma genera comunque DWARF:

```
[INFO] Continuo comunque con il DWARF sul binario originale...
```

**Cosa succede**: DWARF viene aggiunto al binario originale senza symbol table.

**Risultato**: File con DWARF ma senza simboli in `.symtab`.

**Soluzione**: Risolvi il problema dei simboli e riprova.

---

## 📊 Statistiche Output

Output tipico:

```
STEP 1-2: SYMBOL TABLE
  ✓ Estratti 1543 simboli in CSV
  ✓ Aggiunti 1543 simboli al binario

STEP 3: DWARF
  ✓ 125 funzioni elaborate
  ✓ 87 variabili globali
  ✓ 234 tipi custom (struct, enum, etc.)
  ✓ 5432 line entries
  ✓ Sezioni DWARF: 89 KB

File finale: 2.3 MB → 2.4 MB (+100 KB)
```

---

## 🎓 Cosa viene aggiunto?

### Symbol Table (`.symtab`)

- Nome funzioni: `main`, `printf`, `read_config`, etc.
- Tipo: `FUNC`, `OBJECT`
- Binding: `GLOBAL`, `LOCAL`
- Indirizzo e dimensione

### DWARF Debug Info

#### `.debug_info`
- Funzioni con parametri e variabili locali
- Tipi: `struct`, `enum`, `array`, `pointer`
- Variabili globali
- Source file references

#### `.debug_line`
- Mapping `indirizzo assembly` → `linea codice sorgente`
- Permette a GDB di fare step-by-step nel sorgente

#### `.debug_abbrev`
- Abbreviazioni per compattare DWARF

---

## 🔬 Test con GDB

```bash
$ gdb binary_symbols.dwarf

# Lista funzioni (da symbol table)
(gdb) info functions
main
printf@plt
read_config
process_data
...

# Lista variabili globali (da DWARF)
(gdb) info variables
global_counter
config_buffer
...

# Mostra sorgente (da DWARF + .debug_line)
(gdb) list main
15    int main(int argc, char **argv) {
16        int result;
17        config_t cfg;
18        
19        if (argc < 2) {
...

# Breakpoint (usa symbol table)
(gdb) break main
Breakpoint 1 at 0x400560: file binary.c, line 17.

# Variabili locali in scope (da DWARF)
(gdb) run
(gdb) info locals
result = 0
cfg = {name = 0x0, value = 42, ...}
```

---

## 🎯 Next Steps

1. ✅ **Setup iniziale**: `./build_add_symbols.sh`
2. ✅ **Test**: `./test_add_symbols.sh`
3. ✅ **Usa da Ghidra**: Run `ghidra_add_dwarf.py`
4. ✅ **Verifica**: `gdb binary_symbols.dwarf`

---

## 📞 Support

- Leggi `QUICKSTART.md` per guida veloce
- Leggi `README_INTEGRATION.md` per dettagli architettura
- Controlla `FILES_OVERVIEW.md` per capire i file

Enjoy! 🎉
