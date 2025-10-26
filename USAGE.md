# Ghidra Unstrip - Guida all'Uso

Questo progetto permette di aggiungere **symbol table** e **informazioni DWARF** a binari ELF stripped, estraendo automaticamente le informazioni dall'analisi di Ghidra.

## 🚀 Uso Rapido (Script Ghidra Completo)

### Metodo Consigliato: Script Integrato

Lo script `ghidra_add_dwarf.py` esegue **automaticamente** tutto il processo:

1. **Estrazione simboli** da Ghidra → CSV
2. **Aggiunta symbol table** al binario usando LIEF
3. **Generazione e aggiunta DWARF** con informazioni di debug complete

**Come usare:**

1. Apri il binario stripped in Ghidra
2. Esegui l'analisi automatica (Analisi → Auto Analyze)
3. Esegui lo script: `Window → Script Manager → ghidra_add_dwarf.py`
4. Attendi il completamento (può richiedere alcuni minuti per binari grandi)

**Output:**

```
/path/to/binary_symbols.csv         # CSV con tutti i simboli
/path/to/binary_symbols             # ELF con symbol table
/path/to/binary_symbols.dwarf       # ELF finale con symbol table + DWARF ✓
/path/to/binary_symbols.c           # Codice sorgente decompilato
```

Il file finale è: `binary_symbols.dwarf`

---

## 📦 Componenti del Progetto

### Script Ghidra

- **`ghidra_add_dwarf.py`** - Script principale (esegue tutto il workflow)
- **`unstrip.py`** - Script legacy (solo symbol table)

### Moduli Python (lib/)

- **`symbol_table.py`** - Estrazione simboli da Ghidra
- **`add_symbols_lief.py`** - Aggiunta symbol table usando LIEF
- **`libdwarf_producer.py`** - Wrapper per libdwarf (generazione DWARF)
- **`elf.py`** - Manipolazione diretta sezioni ELF
- **`ghidra2dwarf.py`** - Implementazione di riferimento

---

## 🔧 Uso Modulare

Se preferisci eseguire i passaggi separatamente:

### 1. Solo Symbol Table (Metodo Veloce)

Usa `unstrip.py`:

```bash
# In Ghidra Script Manager
Window → Script Manager → unstrip.py
```

Output: `binary_unstripped` (ELF con symbol table)

### 2. Symbol Table + DWARF (Manuale)

#### Step 1: Estrai simboli
```python
# In Ghidra Python Console
from lib.symbol_table import extract_symbols_to_csv
extract_symbols_to_csv(getCurrentProgram(), "/tmp/symbols.csv")
```

#### Step 2: Aggiungi simboli al binario
```bash
python lib/add_symbols_lief.py binary.elf /tmp/symbols.csv binary_with_symbols
```

#### Step 3: Esegui script DWARF in Ghidra sul binario originale
```bash
# Esegui ghidra_add_dwarf.py modificato per saltare step symbol table
```

---

## 📋 Prerequisiti

### Per lo Script Ghidra Completo

**Python packages** (installati nell'ambiente Python di sistema, **non** in Jython):

```bash
pip install lief
```

> **Nota:** Ghidra usa Jython (Python 2.7) per gli script, ma i moduli Python che chiamano `lief` vengono eseguiti dal Python di sistema tramite subprocess.

### Dipendenze Sistema

- **libdwarf** - libreria C per DWARF
- **Ghidra** - con PyGhidra support
- **Python 3.x** - per i moduli esterni

---

## 🧪 Verifica del Risultato

### Symbol Table

```bash
# Lista simboli
nm binary_symbols.dwarf | head -20

# Dettagli symbol table
readelf -s binary_symbols.dwarf | head -30

# Cerca simbolo specifico
nm binary_symbols.dwarf | grep main
```

### DWARF Debug Info

```bash
# Info compilation units
readelf --debug-dump=info binary_symbols.dwarf | head -50

# Line table
readelf --debug-dump=line binary_symbols.dwarf | head -30

# Abbreviations
readelf --debug-dump=abbrev binary_symbols.dwarf | head -20
```

### Debug con GDB

```bash
gdb binary_symbols.dwarf

(gdb) info functions          # Lista tutte le funzioni
(gdb) info variables          # Lista variabili globali
(gdb) list main              # Mostra sorgente funzione main
(gdb) break main             # Breakpoint su main
(gdb) run
(gdb) backtrace              # Stack trace con nomi funzioni
(gdb) info locals            # Variabili locali
```

---

## 📊 Workflow Dettagliato

```
┌─────────────────────┐
│  Binario Stripped   │
│   (binary.elf)      │
└──────────┬──────────┘
           │
           │ Analisi Ghidra
           ▼
┌─────────────────────┐
│ Ghidra Database     │
│ - Funzioni          │
│ - Variabili         │
│ - Tipi              │
│ - Decompilazione    │
└──────────┬──────────┘
           │
           │ ghidra_add_dwarf.py
           ▼
┌─────────────────────┐
│   STEP 1: Extract   │
│  Symbols → CSV      │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│   STEP 2: Add       │
│  Symbol Table       │
│  (usando LIEF)      │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│   STEP 3: Add       │
│  DWARF Debug Info   │
│  (usando libdwarf)  │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  Binario Completo   │
│  + Symbol Table     │
│  + DWARF v2         │
│  + Source Code      │
└─────────────────────┘
```

---

## 🎯 Cosa Viene Aggiunto

### Symbol Table (.symtab)

- ✓ Nomi funzioni (con indirizzi)
- ✓ Nomi variabili globali
- ✓ Binding (global/local)
- ✓ Tipi (FUNC/OBJECT)
- ✓ Dimensioni
- ✓ Indici sezione

### DWARF Debug Info

**Sezioni create:**
- `.debug_info` - DIE (Debug Information Entries) per:
  - Compilation Unit
  - Funzioni (con parametri e variabili locali)
  - Variabili globali
  - Tipi (base, struct, array, enum, puntatori)
- `.debug_abbrev` - Abbreviazioni DIE
- `.debug_line` - Mapping indirizzo ↔ linea sorgente
- `.debug_str` - Stringhe (nomi)

**Informazioni incluse:**
- ✓ Nomi funzioni/variabili
- ✓ Tipi completi (con conversione da Ghidra → DWARF)
- ✓ Posizioni variabili (registri, stack, memoria)
- ✓ Indirizzi funzioni
- ✓ Codice sorgente decompilato (.c file)
- ✓ Line table (address → source line mapping)

---

## ⚙️ Configurazione Avanzata

### Solo DWARF (senza symbol table)

Modifica `ghidra_add_dwarf.py`, cambia l'entry point:

```python
if __name__ == "__main__":
    # Usa solo DWARF
    result = create_dwarf_from_ghidra()
```

### Personalizzare Output

Nel modulo `create_dwarf_from_ghidra()`, puoi modificare:

- `output_path` - percorso file output
- `source_file` - percorso sorgente decompilato
- Filtri funzioni/variabili da includere

---

## 🐛 Troubleshooting

### Errore: "Import lief could not be resolved"

LIEF deve essere installato nel Python di **sistema**, non in Jython:

```bash
# Verifica installazione
python3 -c "import lief; print('OK')"

# Se non funziona, installa
pip3 install lief
```

### Errore: "libdwarf.so not found"

Assicurati che `lib/libdwarf.so` sia presente:

```bash
ls lib/libdwarf.so

# Se manca, compila libdwarf o copia dalla tua installazione
```

### Script lento su binari grandi

È normale. La decompilazione richiede tempo. Puoi:

1. Filtrare solo funzioni specifiche
2. Disabilitare decompilazione per alcune funzioni
3. Eseguire solo su sezioni eseguibili (già implementato)

### Errori "DW_AT_* has no attribute"

Mancano costanti DWARF. Aggiungi in `lib/libdwarf_producer.py` nella classe `DW_AT`:

```python
DW_AT_missing_constant = 0xNN  # Trova valore in DWARF spec
```

---

## 📝 Note

- **Jython vs Python:** Ghidra usa Jython (Python 2.7), ma i moduli esterni vengono eseguiti con Python 3
- **DWARF v2:** Usa DWARF versione 2 (compatibilità massima con GDB)
- **Tipi supportati:** Base types, Pointers, Arrays, Structures, Enums
- **Architetture:** Funziona con x86, x86_64, ARM (usa DWARF register mappings di Ghidra)

---

## 🔗 File Correlati

- `README.md` - Panoramica generale progetto
- `add_symbols.spec` - Spec per PyInstaller (se usato)
- `test.py` - Script di test
