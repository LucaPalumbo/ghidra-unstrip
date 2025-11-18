#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script standalone per aggiungere simboli a un binario ELF usando LIEF.
Questo script può essere compilato con PyInstaller per essere chiamato da Ghidra.

Usage:
    add_symbols_standalone <input-elf> <symbols-csv> <output-elf>
"""

import sys
import csv
import os


def parse_addr(addr_str):
    """Parse indirizzo da string (supporta 0x prefix)"""
    if addr_str.startswith("0x"):
        return int(addr_str, 16)
    return int(addr_str, 16)


def load_symbols_from_csv(csv_path):
    """
    Carica simboli da un file CSV.
    
    CSV Format:
        addr,name,type,binding,size,ndx
    
    Returns:
        Lista di dizionari con info sui simboli
    """
    print(f"[INFO] Caricamento simboli da: {csv_path}")
    
    if not os.path.exists(csv_path):
        print(f"[ERRORE] File CSV non trovato: {csv_path}")
        return []
    
    syms = []
    with open(csv_path, 'r', newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row_num, r in enumerate(reader, start=2):
            try:
                # Parse indirizzo
                addr_str = r.get("addr", "").strip()
                if not addr_str:
                    print(f"[WARN] Riga {row_num}: indirizzo mancante, skip")
                    continue
                
                if addr_str.startswith("0x") or addr_str.startswith("0X"):
                    addr = int(addr_str, 16)
                else:
                    # Prova prima hex poi decimal
                    try:
                        addr = int(addr_str, 16)
                    except ValueError:
                        addr = int(addr_str, 10)
                
                name = r.get("name", "").strip()
                if not name:
                    print(f"[WARN] Riga {row_num}: nome mancante, skip")
                    continue
                
                sym_type = r.get("type", "Label").strip()
                binding = r.get("binding", "local").strip()
                size = int(r.get("size", "0").strip() or "0")
                ndx = int(r.get("ndx", "0").strip() or "0")
                
                syms.append({
                    "name": name,
                    "addr": addr,
                    "type": sym_type,
                    "size": size,
                    "binding": binding,
                    "ndx": ndx,
                })
            
            except Exception as e:
                print(f"[WARN] Riga {row_num}: errore parsing - {e}")
                continue
    
    print(f"[INFO] Caricati {len(syms)} simboli validi")
    return syms


def add_symbols_to_elf(input_elf, symbols, output_elf):
    """
    Aggiunge simboli a un file ELF usando LIEF.
    
    Args:
        input_elf: Path del file ELF di input
        symbols: Lista di dizionari con info sui simboli
        output_elf: Path del file ELF di output
    
    Returns:
        Numero di simboli aggiunti
    """
    try:
        import lief
    except ImportError:
        print("[ERRORE] LIEF non installato!")
        print("        Installa con: pip install lief")
        return 0
    
    print(f"[INFO] Parsing ELF: {input_elf}")
    
    if not os.path.exists(input_elf):
        print(f"[ERRORE] File ELF non trovato: {input_elf}")
        return 0
    
    elf = lief.parse(input_elf)
    if not isinstance(elf, lief.ELF.Binary):
        print("[ERRORE] Non è un binario ELF valido")
        return 0
    
    print(f"[INFO] ELF parsato: {elf.header.machine_type}")
    
    added = 0
    failed = 0
    
    for s in symbols:
        name = s["name"]
        addr = s["addr"]
        sym_type = s["type"]
        size = s["size"]
        binding = s["binding"]
        ndx = s["ndx"]
        
        # Crea simbolo LIEF
        sym = lief.ELF.Symbol()
        sym.name = name
        sym.value = addr
        
        # Imposta tipo
        if sym_type.lower() in ["function", "func"]:
            sym.type = lief.ELF.Symbol.TYPE.FUNC
        elif sym_type.lower() in ["object", "data"]:
            sym.type = lief.ELF.Symbol.TYPE.OBJECT
        else:
            # Default: NOTYPE
            sym.type = lief.ELF.Symbol.TYPE.NOTYPE
        
        sym.size = size
        
        # Imposta binding
        binding_lower = binding.lower()
        if binding_lower == "global":
            sym.binding = lief.ELF.Symbol.BINDING.GLOBAL
        elif binding_lower == "local":
            sym.binding = lief.ELF.Symbol.BINDING.LOCAL
        elif binding_lower == "weak":
            sym.binding = lief.ELF.Symbol.BINDING.WEAK
        else:
            sym.binding = lief.ELF.Symbol.BINDING.LOCAL
        
        # Imposta section index
        if ndx > 0:
            sym.shndx = ndx
        
        try:
            elf.add_symtab_symbol(sym)
            added += 1
            if added % 100 == 0:
                print(f"[INFO] Aggiunti {added} simboli...")
        except Exception as e:
            failed += 1
            if failed <= 5:  # Mostra solo i primi 5 errori
                print(f"[WARN] Impossibile aggiungere '{name}': {e}")
    
    print(f"[INFO] Simboli aggiunti: {added}/{len(symbols)}")
    if failed > 0:
        print(f"[WARN] Simboli falliti: {failed}")
    
    # Scrivi output
    print(f"[INFO] Scrittura ELF: {output_elf}")
    elf.write(output_elf)
    print(f"[INFO] ✓ Completato: {output_elf}")
    
    return added


def add_sections_to_elf(from_file, to_file, sections):
    """
    Aggiunge sezioni a un file ELF usando LIEF.
    
    Args:
        from_file: Path del file ELF di input
        to_file: Path del file ELF di output
        sections: Lista di tuple (name, content) dove:
                  - name: Nome della sezione (str)
                  - content: Contenuto della sezione (bytes)
    
    Returns:
        True se l'operazione ha successo, False altrimenti
    """
    try:
        import lief
    except ImportError:
        print("[ERRORE] LIEF non installato!")
        print("        Installa con: pip install lief")
        return False
    
    print(f"[INFO] Parsing ELF: {from_file}")
    
    if not os.path.exists(from_file):
        print(f"[ERRORE] File ELF non trovato: {from_file}")
        return False
    
    elf = lief.parse(from_file)
    if not isinstance(elf, lief.ELF.Binary):
        print("[ERRORE] Non è un binario ELF valido")
        return False
    
    print(f"[INFO] ELF parsato: {elf.header.machine_type}")
    
    added = 0
    updated = 0
    
    for name, content in sections:
        # Assicurati che name sia una stringa e content sia bytes
        if isinstance(name, bytes):
            name = name.decode('utf-8')
        if isinstance(content, str):
            content = content.encode('utf-8')
        
        # Verifica se la sezione esiste già
        existing_section = None
        try:
            existing_section = elf.get_section(name)
        except:
            pass
        
        if existing_section:
            # Aggiorna sezione esistente
            print(f"[INFO] Aggiornamento sezione esistente: {name}")
            existing_section.content = list(content)
            updated += 1
        else:
            # Crea nuova sezione
            print(f"[INFO] Aggiunta nuova sezione: {name} ({len(content)} bytes)")
            section = lief.ELF.Section()
            section.name = name
            section.content = list(content)
            section.type = lief.ELF.Section.TYPE.PROGBITS
            section.flags = lief.ELF.Section.FLAGS.ALLOC
            
            try:
                elf.add(section)
                added += 1
            except Exception as e:
                print(f"[WARN] Impossibile aggiungere sezione '{name}': {e}")
    
    print(f"[INFO] Sezioni aggiunte: {added}, aggiornate: {updated}")
    
    # Scrivi output
    print(f"[INFO] Scrittura ELF: {to_file}")
    elf.write(to_file)
    print(f"[INFO] ✓ Completato: {to_file}")
    
    return True


def main():
    """Entry point principale"""
    print("=" * 70)
    print("ADD SYMBOLS AND DWARF TO ELF - Standalone Script")
    print("=" * 70)
    
    if len(sys.argv) != 5:
        print("\nUsage:")
        print(f"  {sys.argv[0]} <input-elf> <symbols-csv> <sections-pickle> <output-elf>")
        print("\nExample:")
        print(f"  {sys.argv[0]} binary.elf symbols.csv sections.pkl binary_with_symbols.elf")
        print("\nCSV Format:")
        print("  addr,name,type,binding,size,ndx")
        print("  0x00400560,main,Function,global,100,1")
        print("\nSections Pickle:")
        print("  File pickle contenente lista di tuple (name, content)")
        return 1
    
    input_elf = sys.argv[1]
    csv_path = sys.argv[2]
    pickle_path = sys.argv[3]
    output_elf = sys.argv[4]
    
    print(f"\nInput:   {input_elf}")
    print(f"CSV:     {csv_path}")
    print(f"Pickle:  {pickle_path}")
    print(f"Output:  {output_elf}")
    print()
    
    # Carica simboli
    symbols = load_symbols_from_csv(csv_path)
    if not symbols:
        print("\n[ERRORE] Nessun simbolo caricato!")
        return 1
    
    # Carica sezioni DWARF dal pickle
    print(f"[INFO] Caricamento sezioni DWARF da: {pickle_path}")
    if not os.path.exists(pickle_path):
        print(f"[ERRORE] File pickle non trovato: {pickle_path}")
        return 1
    
    try:
        import pickle
        with open(pickle_path, 'rb') as f:
            sections = pickle.load(f)
        print(f"[INFO] Caricate {len(sections)} sezioni dal pickle")
    except Exception as e:
        print(f"[ERRORE] Impossibile leggere il file pickle: {e}")
        return 1
    
    # Step 1: Aggiungi simboli
    print("\n" + "=" * 70)
    print("STEP 1: Aggiunta simboli")
    print("=" * 70)
    num_added = add_symbols_to_elf(input_elf, symbols, output_elf)
    
    if num_added == 0:
        print("\n[ERRORE] Nessun simbolo aggiunto!")
        return 1
    
    # Step 2: Aggiungi sezioni DWARF
    print("\n" + "=" * 70)
    print("STEP 2: Aggiunta sezioni DWARF")
    print("=" * 70)
    success = add_sections_to_elf(output_elf, output_elf+'1', sections)
    
    if not success:
        print("\n[ERRORE] Errore nell'aggiunta delle sezioni DWARF!")
        return 1
    
    # Completato
    print("\n" + "=" * 70)
    print(f"✓ Completato con successo!")
    print(f"  - Aggiunti {num_added} simboli")
    print(f"  - Aggiunte {len(sections)} sezioni DWARF")
    print(f"  - File generato: {output_elf}")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
