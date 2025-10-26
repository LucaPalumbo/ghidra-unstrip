# -*- coding: utf-8 -*-
# Add DWARF debug info from Ghidra analysis
# @author Feld
# @category PWN
# @keybinding
# @menupath
# @toolbar
# @runtime PyGhidra


"""
Ghidra script per aggiungere symbol table e informazioni DWARF a un binario stripped.
Estrae automaticamente funzioni, variabili e codice sorgente decompilato da Ghidra.
"""

try:
    from ghidra_builtins import *
except:
    pass

import os
import sys

from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.app.decompiler.component import DecompilerUtils
from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.data import (
    Pointer, Structure, DefaultDataType, BuiltInDataType, 
    Array, Enum
)
from ghidra.app.util.bin.format.dwarf import DWARFRegisterMappingsManager
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.util.opinion import ElfLoader

# Carica il modulo dalla directory lib/
script_path = sourceFile.absolutePath
lib_dir = os.path.join(os.path.dirname(script_path), 'lib')
sys.path.insert(0, lib_dir)

from libdwarf_producer import (
    DwarfProducer,
    GhidraDwarfBuilder,
    DW_TAG,
    DW_AT,
    DW_LANG,
    DW_ATE,
    DW_OP_call_frame_cfa,
    DW_OP_regx,
    DW_OP_fbreg,
)
import libdwarf_producer  # Per accedere dinamicamente a DW_OP_bregN
from elf import add_sections_to_elf

# Import per symbol table (CSV e subprocess)
import csv
import subprocess


# Variabili globali
curr = getCurrentProgram()
decomp_lines = []
record = {}
register_mappings = {}
stack_reg_dwarf = None


# ============================================================================
# FUNZIONI PER SYMBOL TABLE (integrate da symbol_table.py)
# ============================================================================

def extract_symbols_to_csv(program, output_csv_path):
    """
    Estrae simboli da un programma Ghidra e li salva in formato CSV.
    
    Args:
        program: Il programma Ghidra corrente
        output_csv_path: Path del file CSV di output
    
    Returns:
        Numero di simboli estratti
    """
    print("\n[SYMBOL_TABLE] Inizio estrazione simboli...")
    
    # Import Ghidra modules (dentro la funzione per evitare errori di import quando non in Ghidra)
    from ghidra.app.util.bin.format.elf import ElfHeader
    from ghidra.app.util.bin import FileByteProvider
    import java.io.File as JFile
    from java.nio.file import AccessMode
    
    elf_path = program.getExecutablePath()
    jfile = JFile(elf_path)
    provider = FileByteProvider(jfile, None, AccessMode.READ)
    base_address = program.getImageBase().getOffset()
    
    def onError(e):
        print("  [WARN] ELF parsing error: %s" % str(e))
    
    # Parse ELF header
    elf_header = ElfHeader(provider, onError)
    elf_header.parse()
    sections = elf_header.getSections()
    
    # Precompute section map for fast index lookup
    section_map = []
    for i, s in enumerate(sections):
        start = s.getAddress()
        end = start + s.getSize()
        section_map.append((start, end, i))
    
    def getNdx(symbol):
        """Trova l'indice della sezione per un simbolo"""
        addr = symbol.getAddress().getOffset() - base_address
        for start, end, idx in section_map:
            if start <= addr < end:
                return idx
        return 0  # SHN_UNDEF
    
    # Precompute function lengths
    func_manager = program.getFunctionManager()
    func_lens = {
        f.getName(): f.getBody().getNumAddresses() 
        for f in func_manager.getFunctions(True)
    }
    
    listing = program.getListing()
    
    def getSymbolSize(symbol):
        """Ottiene la dimensione di un simbolo (per variabili)"""
        try:
            data = listing.getDataAt(symbol.getAddress())
            return data.getLength()
        except:
            return None
    
    def gather_information(symbol):
        """Raccoglie tutte le informazioni su un simbolo"""
        name = symbol.getName()
        addr = max(symbol.getAddress().getOffset() - base_address, 0)
        sym_type = symbol.getSymbolType().toString()
        ndx = getNdx(symbol)
        binding = None
        size = None
        
        if sym_type == "Function":
            size = func_lens.get(name)
            binding = "global"
        elif sym_type == "Label":
            size = getSymbolSize(symbol)
            binding = "global" if size is not None else "local"
        
        return {
            "name": name,
            "addr": addr,
            "type": sym_type,
            "size": size,
            "binding": binding,
            "ndx": ndx,
        }
    
    # Filter symbols early
    symbol_table = program.getSymbolTable()
    symbols = [
        s for s in symbol_table.getDefinedSymbols()
        if not s.isDynamic() and not s.isExternal()
    ]
    
    print("  Trovati %d simboli da esportare" % len(symbols))
    
    # Prepare CSV rows
    rows = [["name", "addr", "type", "size", "binding", "ndx"]]
    
    for symbol in symbols:
        info = gather_information(symbol)
        rows.append([
            info["name"],
            hex(info["addr"]),
            info["type"],
            info["size"] if info["size"] is not None else "",
            info["binding"] if info["binding"] is not None else "",
            info["ndx"],
        ])
    
    # Write CSV
    with open(output_csv_path, "w") as f:
        w = csv.writer(f)
        w.writerows(rows)
    
    print("  CSV salvato: %s" % output_csv_path)
    
    return len(symbols)


def call_add_symbols_binary(binary_path, input_elf, csv_path, output_elf):
    """
    Chiama il binario add_symbols compilato con PyInstaller.
    
    Args:
        binary_path: Path del binario add_symbols
        input_elf: Path del file ELF di input
        csv_path: Path del CSV con i simboli
        output_elf: Path del file ELF di output
    
    Returns:
        True se successo, False altrimenti
    """
    if not os.path.exists(binary_path):
        print("  [ERRORE] Binario add_symbols non trovato: %s" % binary_path)
        print("  Compila con: ./build_add_symbols.sh")
        return False
    
    print("  Esecuzione binario add_symbols...")
    print("    Binary: %s" % binary_path)
    print("    Input:  %s" % input_elf)
    print("    CSV:    %s" % csv_path)
    print("    Output: %s" % output_elf)
    
    try:
        # Esegui il binario
        result = subprocess.call([binary_path, input_elf, csv_path, output_elf])
        
        if result == 0:
            print("  ✓ Simboli aggiunti con successo")
            return True
        else:
            print("  ✗ Errore durante l'aggiunta dei simboli (exit code: %d)" % result)
            return False
    
    except Exception as e:
        print("  ✗ Errore durante l'esecuzione: %s" % str(e))
        return False


# ============================================================================
# FUNZIONI PER DWARF
# ============================================================================

def get_real_address(addr):
    """
    Converte un indirizzo Ghidra nell'indirizzo reale del binario.
    Gestisce PIE (Position Independent Executables).
    """
    if addr is None:
        return None
    
    is_pie = curr.relocationTable.relocatable
    if is_pie:
        orig_base = ElfLoader.getElfOriginalImageBase(curr)
        image_base = curr.imageBase.offset
        return addr.offset - image_base + orig_base
    else:
        return addr.offset


def get_function_range(func):
    """Ottiene l'indirizzo di inizio e fine di una funzione"""
    return get_real_address(func.entryPoint), get_real_address(func.body.maxAddress)


def is_function_executable(func):
    """Verifica se la funzione è in una sezione eseguibile"""
    f_start, f_end = get_function_range(func)
    for s in curr.memory.executeSet.addressRanges:
        if f_start >= get_real_address(s.minAddress) and f_end <= get_real_address(s.maxAddress):
            return True
    return False


def get_decompiled_function(func):
    """Decompila una funzione usando il decompiler di Ghidra"""
    options = DecompileOptions()
    monitor = ConsoleTaskMonitor()
    ifc = DecompInterface()
    ifc.setOptions(options)
    ifc.openProgram(curr)
    res = ifc.decompileFunction(func, 60, monitor)
    return res


def get_decompiled_variables(decomp):
    """
    Estrae variabili e parametri dal risultato della decompilazione.
    Ritorna: (name, datatype, addr, storage, is_parameter)
    """
    high_func = decomp.highFunction
    if high_func is None:
        return []
    
    variables = []
    
    # Parametri
    for param in high_func.localSymbolMap.symbols:
        if param.isParameter():
            variables.append((
                param.name,
                param.dataType,
                param.getPCAddress(),
                param.storage,
                True  # is_parameter
            ))
    
    # Variabili locali
    for var in high_func.localSymbolMap.symbols:
        if not var.isParameter():
            variables.append((
                var.name,
                var.dataType,
                var.getPCAddress(),
                var.storage,
                False  # is_parameter
            ))
    
    return variables


def generate_register_mappings():
    """Genera le mappature tra registri Ghidra e DWARF"""
    global register_mappings, stack_reg_dwarf
    
    d2g_mapping = DWARFRegisterMappingsManager.getMappingForLang(curr.language)
    g2d_mapping = {}
    
    DW_FRAME_LAST_REG_NUM = 100  # Valore approssimativo
    for i in range(DW_FRAME_LAST_REG_NUM):
        reg = d2g_mapping.getGhidraReg(i)
        if reg:
            g2d_mapping[reg.offset] = i
    
    stack_reg_num = d2g_mapping.getDWARFStackPointerRegNum()
    # Accedi dinamicamente al DW_OP specifico per lo stack pointer
    stack_reg_dwarf_op = getattr(libdwarf_producer, "DW_OP_breg%d" % stack_reg_num, None)
    
    register_mappings = g2d_mapping
    stack_reg_dwarf = stack_reg_dwarf_op
    
    return g2d_mapping, stack_reg_dwarf_op


def ghidra_type_to_dwarf_type(cu, builder, producer, ghidra_type, parent=None):
    """
    Converte un tipo di dato Ghidra in un DIE DWARF.
    Gestisce ricorsivamente tipi complessi (puntatori, array, struct).
    """
    global record
    
    if parent is None:
        parent = cu
    
    # Gestisci tipi None (undefined)
    if ghidra_type is None:
        print("  [WARN] Tipo None incontrato, uso 'void' generico")
        if "void" in record:
            return record["void"]
        void_die = builder.create_base_type("void", 0, DW_ATE.DW_ATE_address, parent)
        record["void"] = void_die
        return void_die
    
    type_name = str(ghidra_type)
    
    # Controlla se il tipo è già stato creato
    if type_name in record:
        return record[type_name]
    
    # Tipi puntatore
    if isinstance(ghidra_type, Pointer):
        pointed_type = ghidra_type.dataType
        pointed_die = ghidra_type_to_dwarf_type(cu, builder, producer, pointed_type, parent)
        ptr_die = builder.create_pointer_type(pointed_die, parent)
        record[type_name] = ptr_die
        return ptr_die
    
    # Tipi array
    elif isinstance(ghidra_type, Array):
        element_type = ghidra_type.dataType
        element_die = ghidra_type_to_dwarf_type(cu, builder, producer, element_type, parent)
        
        # Crea array type
        array_die = producer.create_die(DW_TAG.DW_TAG_array_type, parent)
        array_die.add_reference(DW_AT.DW_AT_type, element_die)
        
        # Subrange per la dimensione
        count = ghidra_type.numElements
        subrange = producer.create_die(DW_TAG.DW_TAG_subrange_type, array_die)
        subrange.add_unsigned_constant(DW_AT.DW_AT_upper_bound, count - 1)
        
        record[type_name] = array_die
        return array_die
    
    # Tipi struct
    elif isinstance(ghidra_type, Structure):
        struct_die = producer.create_die(DW_TAG.DW_TAG_structure_type, parent)
        struct_die.add_name(ghidra_type.name)
        struct_die.add_unsigned_constant(DW_AT.DW_AT_byte_size, ghidra_type.length)
        
        # Membri della struct
        for component in ghidra_type.getComponents():
            member_die = producer.create_die(DW_TAG.DW_TAG_member, struct_die)
            member_die.add_name(component.getFieldName())
            member_die.add_unsigned_constant(DW_AT.DW_AT_data_member_location, component.getOffset())
            
            member_type_die = ghidra_type_to_dwarf_type(cu, builder, producer, component.getDataType(), parent)
            member_die.add_reference(DW_AT.DW_AT_type, member_type_die)
        
        record[type_name] = struct_die
        return struct_die
    
    # Tipi enum
    elif isinstance(ghidra_type, Enum):
        enum_die = producer.create_die(DW_TAG.DW_TAG_enumeration_type, parent)
        enum_die.add_name(ghidra_type.name)
        enum_die.add_unsigned_constant(DW_AT.DW_AT_byte_size, ghidra_type.length)
        
        for name in ghidra_type.names:
            value = ghidra_type.getValue(name)
            enumerator = producer.create_die(DW_TAG.DW_TAG_enumerator, enum_die)
            enumerator.add_name(name)
            enumerator.add_signed_constant(DW_AT.DW_AT_const_value, value)
        
        record[type_name] = enum_die
        return enum_die
    
    # Tipi base (int, char, float, ecc.)
    elif isinstance(ghidra_type, (BuiltInDataType, DefaultDataType)):
        size = ghidra_type.length
        name = ghidra_type.name
        
        # Determina encoding
        if "float" in name.lower() or "double" in name.lower():
            encoding = DW_ATE.DW_ATE_float
        elif "unsigned" in name.lower() or name.lower() in ["byte", "uchar"]:
            encoding = DW_ATE.DW_ATE_unsigned
        elif "char" in name.lower():
            encoding = DW_ATE.DW_ATE_signed_char
        elif name.lower() == "void":
            encoding = DW_ATE.DW_ATE_address
            size = 0
        elif "bool" in name.lower():
            encoding = DW_ATE.DW_ATE_boolean
        else:
            encoding = DW_ATE.DW_ATE_signed
        
        base_die = builder.create_base_type(name, size, encoding, parent)
        record[type_name] = base_die
        return base_die
    
    else:
        # Fallback: tratta come tipo base sconosciuto
        print("  [WARN] Tipo sconosciuto: %s, uso tipo base generico" % type_name)
        base_die = builder.create_base_type(str(ghidra_type), ghidra_type.length, DW_ATE.DW_ATE_signed, parent)
        record[type_name] = base_die
        return base_die


def add_variable_location(producer, var_die, storage):
    """
    Aggiunge informazione sulla location di una variabile.
    Gestisce: registri, stack, memoria.
    """
    varnode = storage.firstVarnode
    if varnode is None:
        return
    
    varnode_addr = varnode.getAddress()
    expr = producer.create_expr()
    
    try:
        if varnode_addr.isRegisterAddress():
            # Variabile in registro
            reg = curr.getRegister(varnode_addr, varnode.size)
            if reg.offset in register_mappings:
                reg_dwarf = register_mappings[reg.offset]
                producer.add_expr_op(expr, DW_OP_regx, reg_dwarf, 0)
                var_die.add_location_expr(DW_AT.DW_AT_location, expr)
        
        elif varnode_addr.isStackAddress():
            # Variabile nello stack
            offset = varnode_addr.offset - varnode_addr.pointerSize
            producer.add_expr_op(expr, DW_OP_fbreg, offset, 0)
            var_die.add_location_expr(DW_AT.DW_AT_location, expr)
        
        elif varnode_addr.isMemoryAddress():
            # Variabile globale in memoria
            addr = get_real_address(varnode_addr)
            producer.add_expr_addr(expr, addr)
            var_die.add_location_expr(DW_AT.DW_AT_location, expr)
    
    except Exception as e:
        print("  [WARN] Impossibile aggiungere location per variabile: %s" % str(e))


def add_function_dwarf(cu, builder, producer, func, file_index, source_output):
    """
    Aggiunge informazioni DWARF per una singola funzione.
    Ritorna: (die, addr_to_line_mapping)
    """
    print("  Elaborazione funzione: %s" % func.name)
    
    # Crea DIE per la funzione
    f_start, f_end = get_function_range(func)
    
    func_die = builder.create_function(
        name=func.name,
        low_pc=f_start,
        high_pc=f_end + 1,
        parent=cu
    )
    
    # Frame base (necessario per variabili locali sullo stack)
    frame_expr = producer.create_expr()
    producer.add_expr_op(frame_expr, DW_OP_call_frame_cfa, 0, 0)
    func_die.add_location_expr(DW_AT.DW_AT_frame_base, frame_expr)
    
    # Linea di inizio della funzione nel file sorgente
    func_line = len(decomp_lines) + 1
    
    # Decompila la funzione
    res = get_decompiled_function(func)
    
    if res.decompiledFunction is None:
        # Errore nella decompilazione
        decompiled_code = "/* Error decompiling %s: %s */" % (func.getName(True), res.errorMessage)
        decomp_lines.extend(decompiled_code.split("\n"))
        addr_to_line = {f_start: func_line + 1}
    else:
        # Decompilazione riuscita
        decompiled_code = res.decompiledFunction.c
        decomp_lines.extend(decompiled_code.split("\n"))
        
        # Tipo di ritorno
        ret_type_die = ghidra_type_to_dwarf_type(cu, builder, producer, func.returnType, cu)
        func_die.add_reference(DW_AT.DW_AT_type, ret_type_die)
        
        # Informazioni sul file sorgente
        func_die.add_unsigned_constant(DW_AT.DW_AT_decl_file, file_index)
        func_die.add_unsigned_constant(DW_AT.DW_AT_decl_line, func_line + 1)
        
        # Variabili e parametri
        for name, datatype, addr, storage, is_param in get_decompiled_variables(res):
            tag = DW_TAG.DW_TAG_formal_parameter if is_param else DW_TAG.DW_TAG_variable
            var_die = producer.create_die(tag, func_die)
            var_die.add_name(name)
            
            # Tipo della variabile
            var_type_die = ghidra_type_to_dwarf_type(cu, builder, producer, datatype, cu)
            var_die.add_reference(DW_AT.DW_AT_type, var_type_die)
            
            # Location (registro, stack, memoria)
            add_variable_location(producer, var_die, storage)
        
        # Estrai mapping indirizzo → linea dal decompiled code
        addr_to_line = extract_line_mappings(res, func_line)
        addr_to_line[f_start] = func_line + 1  # Assicura che l'entry point sia mappato
    
    return func_die, addr_to_line


def extract_line_mappings(decomp_result, func_line_offset):
    """
    Estrae il mapping indirizzo → linea dal codice decompilato.
    Usa i token del ClangMarkup per trovare gli indirizzi.
    """
    addr_to_line = {}
    
    try:
        cmarkup = decomp_result.getCCodeMarkup()
        lines = DecompilerUtils.toLines(cmarkup)
        
        for line in lines:
            for token in line.allTokens:
                if token.minAddress:
                    real_addr = get_real_address(token.minAddress)
                    line_num = line.lineNumber + func_line_offset - 1
                    addr_to_line[real_addr] = line_num
    
    except Exception as e:
        print("  [WARN] Impossibile estrarre line mappings: %s" % str(e))
    
    return addr_to_line


def add_global_variables(cu, builder, producer):
    """Aggiunge variabili globali al DWARF"""
    print("\nAggiunta variabili globali...")
    count = 0
    
    for symbol in curr.symbolTable.getAllSymbols(True):
        if symbol.symbolType in [SymbolType.LABEL, SymbolType.GLOBAL, SymbolType.GLOBAL_VAR]:
            data = curr.listing.getDataAt(symbol.address)
            if data:
                var_die = producer.create_die(DW_TAG.DW_TAG_variable, cu)
                var_die.add_name(symbol.name)
                var_die.add_flag(DW_AT.DW_AT_external, True)
                
                # Tipo
                var_type_die = ghidra_type_to_dwarf_type(cu, builder, producer, data.dataType, cu)
                var_die.add_reference(DW_AT.DW_AT_type, var_type_die)
                
                # Location
                loc_expr = producer.create_expr()
                real_addr = get_real_address(data.getAddress())
                producer.add_expr_addr(loc_expr, real_addr)
                var_die.add_location_expr(DW_AT.DW_AT_location, loc_expr)
                
                count += 1
    
    print("  Aggiunte %d variabili globali" % count)


def create_dwarf_from_ghidra(input_path_override=None):
    """
    Funzione principale che crea il DWARF estraendo informazioni da Ghidra.
    
    Args:
        input_path_override: Se specificato, usa questo path invece di curr.executablePath
    
    Returns:
        Path del file di output con DWARF
    """
    global decomp_lines, record
    
    print("=" * 70)
    print("CREAZIONE DWARF DA ANALISI GHIDRA")
    print("=" * 70)
    
    # Verifica che sia un ELF
    if curr.executableFormat != ElfLoader.ELF_NAME:
        print("\n[ERRORE] Solo binari ELF sono supportati!")
        return None
    
    # Inizializza registri
    print("\n1. Inizializzazione mappature registri...")
    generate_register_mappings()
    
    # Determina il file di output
    input_path = input_path_override if input_path_override else curr.executablePath
    output_path = input_path + ".dwarf"
    
    print("\n2. File:")
    print("   Input:  %s" % input_path)
    print("   Output: %s" % output_path)
    
    # Path per il file sorgente decompilato
    source_file = input_path + ".c"
    source_dir = os.path.dirname(source_file)
    source_name = os.path.basename(source_file)
    
    print("   Source: %s" % source_file)
    
    with DwarfProducer() as producer:
        builder = GhidraDwarfBuilder(producer)
        
        # 3. COMPILATION UNIT
        print("\n3. Creazione Compilation Unit...")
        cu = builder.create_compile_unit(
            name=source_name,
            comp_dir=source_dir,
            language=DW_LANG.DW_LANG_C
        )
        
        # 4. FUNZIONI
        print("\n4. Elaborazione funzioni...")
        fm = curr.functionManager
        funcs = list(fm.getFunctions(True))
        
        # Filtra solo funzioni eseguibili
        exec_funcs = [f for f in funcs if is_function_executable(f)]
        print("   Trovate %d funzioni (%d eseguibili)" % (len(funcs), len(exec_funcs)))
        
        addr_to_line = {}
        max_addr = 0
        
        for i, func in enumerate(exec_funcs):
            try:
                func_die, func_addr_to_line = add_function_dwarf(cu, builder, producer, func, 1, source_file)
                addr_to_line.update(func_addr_to_line)
                
                f_start, f_end = get_function_range(func)
                max_addr = max(max_addr, f_end + 1)
                
                if (i + 1) % 10 == 0:
                    print("   Elaborate %d/%d funzioni..." % (i + 1, len(exec_funcs)))
            
            except Exception as e:
                print("   [ERRORE] Funzione %s: %s" % (func.name, str(e)))
                import traceback
                traceback.print_exc()
        
        print("   Completate %d funzioni" % len(exec_funcs))
        
        # 5. VARIABILI GLOBALI
        print("\n5. Elaborazione variabili globali...")
        add_global_variables(cu, builder, producer)
        
        # 6. LINE TABLE
        print("\n6. Creazione line table...")
        dir_index = producer.add_directory(source_dir)
        file_index = producer.add_file(source_name, dir_index, 0, 0)
        cu.add_unsigned_constant(DW_AT.DW_AT_stmt_list, 0)
        
        # Aggiungi line entries in ordine di indirizzo
        sorted_addrs = sorted(addr_to_line.keys())
        for addr in sorted_addrs:
            line = addr_to_line[addr]
            producer.add_line_entry(file_index, addr, line, 0, True, False)
            max_addr = max(max_addr, addr + 1)
        
        producer.end_line_sequence(max_addr)
        print("   Aggiunte %d line entries" % len(sorted_addrs))
        
        # 7. SALVA CODICE SORGENTE
        print("\n7. Salvataggio codice sorgente decompilato...")
        with open(source_file, "w") as f:
            f.write("\n".join(decomp_lines))
        print("   Salvato: %s (%d righe)" % (source_file, len(decomp_lines)))
        
        # 8. FINALIZZA DWARF
        print("\n8. Finalizzazione DWARF...")
        producer.add_cu_die(cu)
        
        n_sections = producer.transform_to_disk()
        print("   Sezioni create: %d" % n_sections)
        
        # 9. ESTRAI BYTES
        print("\n9. Estrazione bytes sezioni...")
        sections_data = {}
        
        for i in range(n_sections):
            try:
                section_bytes, elf_idx = producer.get_section_bytes(i)
                
                if elf_idx < len(producer.sections):
                    section_name = producer.sections[elf_idx]['name']
                else:
                    section_name = "section_%d" % elf_idx
                
                if section_name not in sections_data:
                    sections_data[section_name] = b""
                sections_data[section_name] += section_bytes
                
            except Exception as e:
                print("   [WARN] Errore sezione %d: %s" % (i, str(e)))
        
        print("\n10. Sezioni DWARF create:")
        total_size = 0
        for name, data in sections_data.items():
            print("   ✓ %s: %d bytes" % (name, len(data)))
            total_size += len(data)
        print("   Totale: %d bytes" % total_size)
        
        # 10. SCRIVI NELL'ELF
        print("\n11. Scrittura DWARF nell'ELF...")
        
        # Filtra sezioni di relocazione
        filtered_sections = []
        for section_name, section_bytes in sections_data.items():
            if not section_name.startswith('.rel.') and not section_name.startswith('.rela.'):
                filtered_sections.append((section_name, section_bytes))
        
        try:
            add_sections_to_elf(input_path, output_path, filtered_sections)
            print("   ✓ ELF scritto: %s" % output_path)
        except Exception as e:
            print("   ✗ ERRORE scrittura ELF: %s" % str(e))
            import traceback
            traceback.print_exc()
            return None
        
        print("\n" + "=" * 70)
        print("✓✓✓ COMPLETATO CON SUCCESSO!")
        print("=" * 70)
        print("\nFile creati:")
        print("  - %s (ELF con DWARF)" % output_path)
        print("  - %s (codice sorgente)" % source_file)
        print("\nVerifica con GDB:")
        print("  $ gdb %s" % output_path)
        print("  (gdb) info functions")
        print("  (gdb) list main")
        print("  (gdb) break main")
        
        return output_path


def add_symbols_and_dwarf():
    """
    Funzione principale che aggiunge sia symbol table che DWARF al binario.
    Workflow completo:
      1. Estrai simboli da Ghidra -> CSV
      2. Aggiungi simboli al binario usando LIEF -> binario_symbols
      3. Aggiungi DWARF al binario con simboli -> binario_symbols.dwarf (finale)
    
    Returns:
        Path del file finale (con simboli + DWARF)
    """
    print("=" * 70)
    print("GHIDRA UNSTRIP: SYMBOL TABLE + DWARF")
    print("=" * 70)
    
    # Verifica che sia un ELF
    if curr.executableFormat != ElfLoader.ELF_NAME:
        print("\n[ERRORE] Solo binari ELF sono supportati!")
        return None
    
    input_path = curr.executablePath
    
    # Determina il path del binario add_symbols e del CSV
    script_dir = os.path.dirname(script_path)
    add_symbols_binary = os.path.join(script_dir, "dist", "add_symbols")
    csv_path = input_path + "_symbols.csv"
    
    # STEP 1 & 2: Estrai simboli da Ghidra e aggiungili al binario
    print("\n" + "=" * 70)
    print("STEP 1-2: SYMBOL TABLE EXTRACTION & ADDITION")
    print("=" * 70)
    
    symbols_elf_path = input_path + "_symbols"
    
    # Determina il path del binario add_symbols
    script_dir = os.path.dirname(script_path)
    add_symbols_binary = os.path.join(script_dir, "dist", "add_symbols")
    
    # Verifica se il binario esiste
    if not os.path.exists(add_symbols_binary):
        print("\n[WARN] Binario add_symbols non trovato: %s" % add_symbols_binary)
        print("[WARN] Compila con: ./build_add_symbols.sh")
        print("[INFO] Continuo comunque con il DWARF sul binario originale...")
        symbols_elf_path = input_path  # Fallback: usa il binario originale
    else:
        try:
            print("\n[SYMBOL_TABLE] Estrazione simboli da Ghidra...")
            
            # Estrai simboli da Ghidra e salva in CSV
            num_symbols = extract_symbols_to_csv(curr, csv_path)
            print("  Estratti %d simboli" % num_symbols)
            
            if num_symbols == 0:
                print("  [WARN] Nessun simbolo estratto da Ghidra")
                print("[INFO] Continuo comunque con il DWARF sul binario originale...")
                symbols_elf_path = input_path
            else:
                # Chiama binario esterno per aggiungere simboli
                print("\n[SYMBOL_TABLE] Chiamata binario add_symbols...")
                success = call_add_symbols_binary(add_symbols_binary, input_path, csv_path, symbols_elf_path)
                
                if success:
                    print("\n✓ Simboli aggiunti al binario: %s" % symbols_elf_path)
                else:
                    print("\n✗ ERRORE durante l'aggiunta dei simboli")
                    print("[INFO] Continuo comunque con il DWARF sul binario originale...")
                    symbols_elf_path = input_path  # Fallback
                    
        except Exception as e:
            print("\n✗✗✗ ECCEZIONE durante l'aggiunta dei simboli!")
            print("Tipo errore: %s" % type(e).__name__)
            print("Messaggio: %s" % str(e))
            import traceback
            traceback.print_exc()
            print("\n[INFO] Continuo comunque con il DWARF sul binario originale...")
            symbols_elf_path = input_path  # Fallback: usa il binario originale
    
    # STEP 3: Aggiungi DWARF al binario con simboli
    print("\n" + "=" * 70)
    print("STEP 3: AGGIUNTA DWARF")
    print("=" * 70)
    
    try:
        dwarf_output = create_dwarf_from_ghidra(input_path_override=symbols_elf_path)
        
        if dwarf_output:
            print("\n" + "=" * 70)
            print("✓✓✓ PROCESSO COMPLETO!")
            print("=" * 70)
            print("\nFile creati:")
            print("  1. %s (CSV simboli)" % csv_path)
            print("  2. %s (ELF + symbol table)" % symbols_elf_path)
            print("  3. %s (ELF + symbol table + DWARF) ← FINALE" % dwarf_output)
            print("  4. %s.c (codice sorgente decompilato)" % symbols_elf_path)
            print("\nVerifica simboli:")
            print("  $ nm %s | head" % dwarf_output)
            print("  $ readelf -s %s | head" % dwarf_output)
            print("\nVerifica DWARF:")
            print("  $ readelf --debug-dump=info %s | head -50" % dwarf_output)
            print("\nDebug con GDB:")
            print("  $ gdb %s" % dwarf_output)
            print("  (gdb) info functions")
            print("  (gdb) info variables")
            print("  (gdb) list main")
            print("  (gdb) break main")
            
            return dwarf_output
        else:
            print("\n✗ ERRORE durante la creazione del DWARF")
            return None
    
    except Exception as e:
        print("\n✗✗✗ ERRORE FATALE durante la creazione del DWARF: %s" % str(e))
        import traceback
        traceback.print_exc()
        return None


# Entry point dello script Ghidra
if __name__ == "__main__":
    try:
        # Usa la funzione combinata che fa tutto
        result = add_symbols_and_dwarf()
        if result:
            print("\n✓✓✓ Script completato con successo!")
        else:
            print("\n✗✗✗ Script terminato con errori")
    except Exception as e:
        print("\n✗✗✗ ERRORE FATALE: %s" % str(e))
        import traceback
        traceback.print_exc()
