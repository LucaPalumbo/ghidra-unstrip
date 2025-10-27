# Add symbols and dwarf back to stripped binary
# -*- coding: utf-8 -*-
# Add DWARF debug info from Ghidra analysis
# @author Feld
# @category PWN & REV
# @keybinding
# @menupath
# @toolbar
# @runtime PyGhidra


"""
Ghidra script to add symbol table and DWARF information to a stripped binary.
Automatically extracts functions, variables and decompiled source code from Ghidra.
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

# Load module from lib/ directory
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

# Import for symbol table (CSV and subprocess)
import csv
import subprocess


# Global variables
curr = getCurrentProgram()
decomp_lines = []
record = {}
register_mappings = {}
stack_reg_dwarf = None


# ============================================================================
# FUNCTIONS FOR SYMBOL TABLE (integrated from symbol_table.py)
# ============================================================================

def extract_symbols_to_csv(program, output_csv_path):
    """
    Extracts symbols from a Ghidra program and saves them in CSV format.
    
    Args:
        program: The current Ghidra program
        output_csv_path: Path to the output CSV file
    
    Returns:
        Number of extracted symbols
    """
    print("\n[SYMBOL_TABLE] Starting symbol extraction...")
    
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
        """Finds the section index for a symbol"""
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
        """Gets the size of a symbol (for variables)"""
        try:
            data = listing.getDataAt(symbol.getAddress())
            return data.getLength()
        except:
            return None
    
    def gather_information(symbol):
        """Gathers all information about a symbol"""
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
    
    print("  Found %d symbols to export" % len(symbols))
    
    # Prepare CSV rows
    rows = [["name", "addr", "type", "size", "binding", "ndx"]]
    
    # Add existing symbols
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
    
    # Extract strings from data sections (.rodata, .data, etc.)
    print("  Extracting strings from data sections...")
    string_count = 0
    memory = program.getMemory()
    
    # Search for strings in all data sections
    for block in memory.getBlocks():
        # Only data sections (not executable, not overlay, not external)
        if not block.isExecute() and not block.isOverlay() and not block.isExternalBlock():
            print("    Scanning section: %s" % block.getName())
            
            # Iterate over all defined data in this section
            data_iter = listing.getDefinedData(block.getStart(), True)
            
            try:
                while data_iter.hasNext():
                    data = data_iter.next()
                    
                    # Check if it's a string
                    if data.hasStringValue():
                        try:
                            # Get the string value
                            string_value = data.getValue()
                            if string_value is None:
                                continue
                            
                            # Convert to Python string
                            str_content = str(string_value)
                            
                            # Skip empty or too short strings
                            if len(str_content) < 2:
                                continue
                            
                            # Create symbol name from string
                            # First 22 chars + "..." if longer than 25
                            if len(str_content) > 25:
                                symbol_name = str_content[:22] + "..."
                            else:
                                symbol_name = str_content
                            
                            # Sanitize the name (remove problematic characters)
                            # Replace spaces and special characters with underscores
                            symbol_name = symbol_name.replace(" ", "_")
                            symbol_name = symbol_name.replace("\n", "\\n")
                            symbol_name = symbol_name.replace("\t", "\\t")
                            symbol_name = symbol_name.replace("\r", "\\r")
                            symbol_name = symbol_name.replace("\"", "\\\"")
                            symbol_name = symbol_name.replace("'", "\\'")
                            symbol_name = symbol_name.replace(",", " ")
                            
                            # Check that a symbol doesn't already exist at this address
                            # Use max(..., 0) to avoid negative addresses
                            addr = max(data.getAddress().getOffset() - base_address, 0)
                            
                            # Check if there's already a symbol with this address in rows
                            already_exists = False
                            for row in rows[1:]:  # Skip header
                                if row[1] == hex(addr):
                                    already_exists = True
                                    break
                            
                            if already_exists:
                                continue
                            
                            # Determine section index
                            ndx = 0
                            for start, end, idx in section_map:
                                if start <= addr < end:
                                    ndx = idx
                                    break
                            
                            # Add the string as a symbol
                            rows.append([
                                symbol_name,
                                hex(addr),
                                "Label",  # Special type for strings
                                data.getLength(),
                                "local",  # Strings are typically local
                                ndx,
                            ])
                            
                            string_count += 1
                            
                        except Exception as e:
                            # Ignore errors on individual strings
                            pass
                            
            except Exception as e:
                print("    [WARN] Error scanning section %s: %s" % (block.getName(), str(e)))
    
    print("  Found %d additional strings" % string_count)
    print("  Total symbols: %d" % (len(rows) - 1))  # -1 for header
    
    # Write CSV
    with open(output_csv_path, "w") as f:
        w = csv.writer(f)
        w.writerows(rows)
    
    print("  CSV saved: %s" % output_csv_path)
    
    return len(symbols)


def call_add_symbols_binary(binary_path, input_elf, csv_path, output_elf):
    """
    Calls the add_symbols binary compiled with PyInstaller.
    
    Args:
        binary_path: Path to the add_symbols binary
        input_elf: Path to the input ELF file
        csv_path: Path to the CSV with symbols
        output_elf: Path to the output ELF file
    
    Returns:
        True if successful, False otherwise
    """
    if not os.path.exists(binary_path):
        print("  [ERROR] add_symbols binary not found: %s" % binary_path)
        print("  Compile with: ./build_add_symbols.sh")
        return False
    
    print("  Running add_symbols binary...")
    print("    Binary: %s" % binary_path)
    print("    Input:  %s" % input_elf)
    print("    CSV:    %s" % csv_path)
    print("    Output: %s" % output_elf)
    
    try:
        # Run the binary
        result = subprocess.call([binary_path, input_elf, csv_path, output_elf])
        
        if result == 0:
            print("  ✓ Symbols added successfully")
            return True
        else:
            print("  ✗ Error adding symbols (exit code: %d)" % result)
            return False
    
    except Exception as e:
        print("  ✗ Execution error: %s" % str(e))
        return False


# ============================================================================
# FUNCTIONS FOR DWARF
# ============================================================================

def get_real_address(addr):
    """
    Converts a Ghidra address to the real binary address.
    Handles PIE (Position Independent Executables).
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
    """Gets the start and end address of a function"""
    return get_real_address(func.entryPoint), get_real_address(func.body.maxAddress)


def is_function_executable(func):
    """Checks if the function is in an executable section"""
    f_start, f_end = get_function_range(func)
    for s in curr.memory.executeSet.addressRanges:
        if f_start >= get_real_address(s.minAddress) and f_end <= get_real_address(s.maxAddress):
            return True
    return False


def get_decompiled_function(func):
    """Decompiles a function using Ghidra's decompiler"""
    options = DecompileOptions()
    monitor = ConsoleTaskMonitor()
    ifc = DecompInterface()
    ifc.setOptions(options)
    ifc.openProgram(curr)
    res = ifc.decompileFunction(func, 60, monitor)
    return res


def get_decompiled_variables(decomp):
    """
    Extracts variables and parameters from decompilation result.
    Returns: (name, datatype, addr, storage, is_parameter)
    """
    high_func = decomp.highFunction
    if high_func is None:
        return []
    
    variables = []
    
    # Parameters
    for param in high_func.localSymbolMap.symbols:
        if param.isParameter():
            variables.append((
                param.name,
                param.dataType,
                param.getPCAddress(),
                param.storage,
                True  # is_parameter
            ))
    
    # Local variables
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
    """Generates mappings between Ghidra and DWARF registers"""
    global register_mappings, stack_reg_dwarf
    
    d2g_mapping = DWARFRegisterMappingsManager.getMappingForLang(curr.language)
    g2d_mapping = {}
    
    DW_FRAME_LAST_REG_NUM = 100  # Approximate value
    for i in range(DW_FRAME_LAST_REG_NUM):
        reg = d2g_mapping.getGhidraReg(i)
        if reg:
            g2d_mapping[reg.offset] = i
    
    stack_reg_num = d2g_mapping.getDWARFStackPointerRegNum()
    # Dynamically access the specific DW_OP for the stack pointer
    stack_reg_dwarf_op = getattr(libdwarf_producer, "DW_OP_breg%d" % stack_reg_num, None)
    
    register_mappings = g2d_mapping
    stack_reg_dwarf = stack_reg_dwarf_op
    
    return g2d_mapping, stack_reg_dwarf_op


def ghidra_type_to_dwarf_type(cu, builder, producer, ghidra_type, parent=None):
    """
    Converts a Ghidra data type to a DWARF DIE.
    Recursively handles complex types (pointers, arrays, structs).
    """
    global record
    
    if parent is None:
        parent = cu
    
    # Handle None types (undefined)
    if ghidra_type is None:
        print("  [WARN] None type encountered, using generic 'void'")
        if "void" in record:
            return record["void"]
        void_die = builder.create_base_type("void", 0, DW_ATE.DW_ATE_address, parent)
        record["void"] = void_die
        return void_die
    
    type_name = str(ghidra_type)
    
    # Check if the type has already been created
    if type_name in record:
        return record[type_name]
    
    # Pointer types
    if isinstance(ghidra_type, Pointer):
        pointed_type = ghidra_type.dataType
        pointed_die = ghidra_type_to_dwarf_type(cu, builder, producer, pointed_type, parent)
        ptr_die = builder.create_pointer_type(pointed_die, parent)
        record[type_name] = ptr_die
        return ptr_die
    
    # Array types
    elif isinstance(ghidra_type, Array):
        element_type = ghidra_type.dataType
        element_die = ghidra_type_to_dwarf_type(cu, builder, producer, element_type, parent)
        
        # Create array type
        array_die = producer.create_die(DW_TAG.DW_TAG_array_type, parent)
        array_die.add_reference(DW_AT.DW_AT_type, element_die)
        
        # Subrange for size
        count = ghidra_type.numElements
        subrange = producer.create_die(DW_TAG.DW_TAG_subrange_type, array_die)
        subrange.add_unsigned_constant(DW_AT.DW_AT_upper_bound, count - 1)
        
        record[type_name] = array_die
        return array_die
    
    # Struct types
    elif isinstance(ghidra_type, Structure):
        struct_die = producer.create_die(DW_TAG.DW_TAG_structure_type, parent)
        struct_die.add_name(ghidra_type.name)
        struct_die.add_unsigned_constant(DW_AT.DW_AT_byte_size, ghidra_type.length)
        
        # Struct members
        for component in ghidra_type.getComponents():
            member_die = producer.create_die(DW_TAG.DW_TAG_member, struct_die)
            member_die.add_name(component.getFieldName())
            member_die.add_unsigned_constant(DW_AT.DW_AT_data_member_location, component.getOffset())
            
            member_type_die = ghidra_type_to_dwarf_type(cu, builder, producer, component.getDataType(), parent)
            member_die.add_reference(DW_AT.DW_AT_type, member_type_die)
        
        record[type_name] = struct_die
        return struct_die
    
    # Enum types
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
    
    # Base types (int, char, float, etc.)
    elif isinstance(ghidra_type, (BuiltInDataType, DefaultDataType)):
        size = ghidra_type.length
        name = ghidra_type.name
        
        # Determine encoding
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
        # Fallback: treat as unknown base type
        print("  [WARN] Unknown type: %s, using generic base type" % type_name)
        base_die = builder.create_base_type(str(ghidra_type), ghidra_type.length, DW_ATE.DW_ATE_signed, parent)
        record[type_name] = base_die
        return base_die


def add_variable_location(producer, var_die, storage):
    """
    Adds location information for a variable.
    Handles: registers, stack, memory.
    """
    varnode = storage.firstVarnode
    if varnode is None:
        return
    
    varnode_addr = varnode.getAddress()
    expr = producer.create_expr()
    
    try:
        if varnode_addr.isRegisterAddress():
            # Variable in register
            reg = curr.getRegister(varnode_addr, varnode.size)
            if reg.offset in register_mappings:
                reg_dwarf = register_mappings[reg.offset]
                producer.add_expr_op(expr, DW_OP_regx, reg_dwarf, 0)
                var_die.add_location_expr(DW_AT.DW_AT_location, expr)
        
        elif varnode_addr.isStackAddress():
            # Variable on stack
            offset = varnode_addr.offset - varnode_addr.pointerSize
            producer.add_expr_op(expr, DW_OP_fbreg, offset, 0)
            var_die.add_location_expr(DW_AT.DW_AT_location, expr)
        
        elif varnode_addr.isMemoryAddress():
            # Global variable in memory
            addr = get_real_address(varnode_addr)
            producer.add_expr_addr(expr, addr)
            var_die.add_location_expr(DW_AT.DW_AT_location, expr)
    
    except Exception as e:
        print("  [WARN] Unable to add location for variable: %s" % str(e))


def add_function_dwarf(cu, builder, producer, func, file_index, source_output):
    """
    Adds DWARF information for a single function.
    Returns: (die, addr_to_line_mapping)
    """
    print("  Processing function: %s" % func.name)
    
    # Create DIE for the funciton
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
    
    # Starting line of the function in the source file
    func_line = len(decomp_lines) + 1
    
    # Decompile the function
    res = get_decompiled_function(func)
    
    if res.decompiledFunction is None:
        # Decompilation error
        decompiled_code = "/* Error decompiling %s: %s */" % (func.getName(True), res.errorMessage)
        decomp_lines.extend(decompiled_code.split("\n"))
        addr_to_line = {f_start: func_line + 1}
    else:
        # Decompilation successful
        decompiled_code = res.decompiledFunction.c
        decomp_lines.extend(decompiled_code.split("\n"))
        
        # Return type
        ret_type_die = ghidra_type_to_dwarf_type(cu, builder, producer, func.returnType, cu)
        func_die.add_reference(DW_AT.DW_AT_type, ret_type_die)
        
        # Source file information
        func_die.add_unsigned_constant(DW_AT.DW_AT_decl_file, file_index)
        func_die.add_unsigned_constant(DW_AT.DW_AT_decl_line, func_line + 1)
        
        # Variables and parameters
        for name, datatype, addr, storage, is_param in get_decompiled_variables(res):
            tag = DW_TAG.DW_TAG_formal_parameter if is_param else DW_TAG.DW_TAG_variable
            var_die = producer.create_die(tag, func_die)
            var_die.add_name(name)
            
            # Variable type
            var_type_die = ghidra_type_to_dwarf_type(cu, builder, producer, datatype, cu)
            var_die.add_reference(DW_AT.DW_AT_type, var_type_die)
            
            # Location (register, stack, memory)
            add_variable_location(producer, var_die, storage)
        
        # Extract address → line mapping from decompiled code
        addr_to_line = extract_line_mappings(res, func_line)
        addr_to_line[f_start] = func_line + 1  # Ensure entry point is mapped
    
    return func_die, addr_to_line


def extract_line_mappings(decomp_result, func_line_offset):
    """
    Extracts address → line mapping from decompiled code.
    Uses ClangMarkup tokens to find addresses.
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
        print("  [WARN] Unable to extract line mappings: %s" % str(e))
    
    return addr_to_line


def add_global_variables(cu, builder, producer):
    """Adds global variables to DWARF"""
    print("\nAdding global variables...")
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
    
    print("  Added %d global variables" % count)


def create_dwarf_from_ghidra(input_path_override=None):
    """
    Main function that creates DWARF by extracting information from Ghidra.
    
    Args:
        input_path_override: If specified, use this path instead of curr.executablePath
    
    Returns:
        Path to output file with DWARF
    """
    global decomp_lines, record
    
    print("=" * 70)
    print("CREATING DWARF FROM GHIDRA ANALYSIS")
    print("=" * 70)
    
    # Verify it's an ELF
    if curr.executableFormat != ElfLoader.ELF_NAME:
        print("\n[ERROR] Only ELF binaries are supported!")
        return None
    
    # Initialize registers
    print("\n1. Initializing register mappings...")
    generate_register_mappings()
    
    # Determine output file
    input_path = input_path_override if input_path_override else curr.executablePath
    output_path = input_path + ".dwarf"
    
    print("\n2. Files:")
    print("   Input:  %s" % input_path)
    print("   Output: %s" % output_path)
    
    # Path for decompiled source file
    source_file = input_path + ".c"
    source_dir = os.path.dirname(source_file)
    source_name = os.path.basename(source_file)
    
    print("   Source: %s" % source_file)
    
    with DwarfProducer() as producer:
        builder = GhidraDwarfBuilder(producer)
        
        # 3. COMPILATION UNIT
        print("\n3. Creating Compilation Unit...")
        cu = builder.create_compile_unit(
            name=source_name,
            comp_dir=source_dir,
            language=DW_LANG.DW_LANG_C
        )
        
        # 4. FUNCTIONS
        print("\n4. Processing functions...")
        fm = curr.functionManager
        funcs = list(fm.getFunctions(True))
        
        # Filter only executable functions
        exec_funcs = [f for f in funcs if is_function_executable(f)]
        print("   Found %d functions (%d executable)" % (len(funcs), len(exec_funcs)))
        
        addr_to_line = {}
        max_addr = 0
        
        for i, func in enumerate(exec_funcs):
            try:
                func_die, func_addr_to_line = add_function_dwarf(cu, builder, producer, func, 1, source_file)
                addr_to_line.update(func_addr_to_line)
                
                f_start, f_end = get_function_range(func)
                max_addr = max(max_addr, f_end + 1)
                
                if (i + 1) % 10 == 0:
                    print("   Processed %d/%d functions..." % (i + 1, len(exec_funcs)))
            
            except Exception as e:
                print("   [ERROR] Function %s: %s" % (func.name, str(e)))
                import traceback
                traceback.print_exc()
        
        print("   Completed %d functions" % len(exec_funcs))
        
        # 5. GLOBAL VARIABLES
        print("\n5. Processing global variables...")
        add_global_variables(cu, builder, producer)
        
        # 6. LINE TABLE
        print("\n6. Creating line table...")
        dir_index = producer.add_directory(source_dir)
        file_index = producer.add_file(source_name, dir_index, 0, 0)
        cu.add_unsigned_constant(DW_AT.DW_AT_stmt_list, 0)
        
        # Add line entries in address order
        sorted_addrs = sorted(addr_to_line.keys())
        for addr in sorted_addrs:
            line = addr_to_line[addr]
            producer.add_line_entry(file_index, addr, line, 0, True, False)
            max_addr = max(max_addr, addr + 1)
        
        producer.end_line_sequence(max_addr)
        print("   Added %d line entries" % len(sorted_addrs))
        
        # 7. SAVE SOURCE CODE
        print("\n7. Saving decompiled source code...")
        with open(source_file, "w") as f:
            f.write("\n".join(decomp_lines))
        print("   Saved: %s (%d lines)" % (source_file, len(decomp_lines)))
        
        # 8. FINALIZE DWARF
        print("\n8. Finalizing DWARF...")
        producer.add_cu_die(cu)
        
        n_sections = producer.transform_to_disk()
        print("   Sections created: %d" % n_sections)
        
        # 9. EXTRACT BYTES
        print("\n9. Extracting section bytes...")
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
                print("   [WARN] Section %d error: %s" % (i, str(e)))
        
        print("\n10. DWARF sections created:")
        total_size = 0
        for name, data in sections_data.items():
            print("   ✓ %s: %d bytes" % (name, len(data)))
            total_size += len(data)
        print("   Total: %d bytes" % total_size)
        
        # 10. WRITE TO ELF
        print("\n11. Writing DWARF to ELF...")
        
        # Filter relocation sections
        filtered_sections = []
        for section_name, section_bytes in sections_data.items():
            if not section_name.startswith('.rel.') and not section_name.startswith('.rela.'):
                filtered_sections.append((section_name, section_bytes))
        
        try:
            add_sections_to_elf(input_path, output_path, filtered_sections)
            print("   ✓ ELF written: %s" % output_path)
        except Exception as e:
            print("   ✗ ELF write ERROR: %s" % str(e))
            import traceback
            traceback.print_exc()
            return None
        
        print("\n" + "=" * 70)
        print("✓✓✓ COMPLETED SUCCESSFULLY!")
        print("=" * 70)
        print("\nFiles created:")
        print("  - %s (ELF with DWARF)" % output_path)
        print("  - %s (source code)" % source_file)
        print("\nVerify with GDB:")
        print("  $ gdb %s" % output_path)
        print("  (gdb) info functions")
        print("  (gdb) list main")
        print("  (gdb) break main")
        
        return output_path


def add_symbols_and_dwarf():
    """
    Main function that adds both symbol table and DWARF to the binary.
    Complete workflow:
      1. Extract symbols from Ghidra -> CSV
      2. Add symbols to binary using LIEF -> binary_symbols
      3. Add DWARF to binary with symbols -> binary_symbols.dwarf (final)
    
    Returns:
        Path to final file (with symbols + DWARF)
    """
    print("=" * 70)
    print("GHIDRA UNSTRIP: SYMBOL TABLE + DWARF")
    print("=" * 70)
    
    # Verify it's an ELF
    if curr.executableFormat != ElfLoader.ELF_NAME:
        print("\n[ERROR] Only ELF binaries are supported!")
        return None
    
    input_path = curr.executablePath
    
    # Determine path to add_symbols binary and CSV
    script_dir = os.path.dirname(script_path)
    add_symbols_binary = os.path.join(script_dir, "dist", "add_symbols")
    csv_path = input_path + "_symbols.csv"
    
    # STEP 1 & 2: Extract symbols from Ghidra and add them to binary
    print("\n" + "=" * 70)
    print("STEP 1-2: SYMBOL TABLE EXTRACTION & ADDITION")
    print("=" * 70)
    
    symbols_elf_path = input_path + "_symbols"
    
    # Determine path to add_symbols binary
    script_dir = os.path.dirname(script_path)
    add_symbols_binary = os.path.join(script_dir, "dist", "add_symbols")
    
    # Check if binary exists
    if not os.path.exists(add_symbols_binary):
        print("\n[WARN] add_symbols binary not found: %s" % add_symbols_binary)
        print("[WARN] Compile with: ./build_add_symbols.sh")
        print("[INFO] Continuing with DWARF on original binary...")
        symbols_elf_path = input_path  # Fallback: use original binary
    else:
        try:
            print("\n[SYMBOL_TABLE] Extracting symbols from Ghidra...")
            
            # Extract symbols from Ghidra and save to CSV
            num_symbols = extract_symbols_to_csv(curr, csv_path)
            print("  Extracted %d symbols" % num_symbols)
            
            if num_symbols == 0:
                print("  [WARN] No symbols extracted from Ghidra")
                print("[INFO] Continuing with DWARF on original binary...")
                symbols_elf_path = input_path
            else:
                # Call external binary to add symbols
                print("\n[SYMBOL_TABLE] Calling add_symbols binary...")
                success = call_add_symbols_binary(add_symbols_binary, input_path, csv_path, symbols_elf_path)
                
                if success:
                    print("\n✓ Symbols added to binary: %s" % symbols_elf_path)
                else:
                    print("\n✗ ERROR adding symbols")
                    print("[INFO] Continuing with DWARF on original binary...")
                    symbols_elf_path = input_path  # Fallback
                    
        except Exception as e:
            print("\n✗✗✗ EXCEPTION adding symbols!")
            print("Error type: %s" % type(e).__name__)
            print("Message: %s" % str(e))
            import traceback
            traceback.print_exc()
            print("\n[INFO] Continuing with DWARF on original binary...")
            symbols_elf_path = input_path  # Fallback: use original binary
    
    # STEP 3: Add DWARF to binary with symbols
    print("\n" + "=" * 70)
    print("STEP 3: ADDING DWARF")
    print("=" * 70)
    
    try:
        dwarf_output = create_dwarf_from_ghidra(input_path_override=symbols_elf_path)
        
        if dwarf_output:
            print("\n" + "=" * 70)
            print("✓✓✓ COMPLETE PROCESS!")
            print("=" * 70)
            print("\nFiles created:")
            print("  1. %s (CSV symbols)" % csv_path)
            print("  2. %s (ELF + symbol table)" % symbols_elf_path)
            print("  3. %s (ELF + symbol table + DWARF) ← FINAL" % dwarf_output)
            print("  4. %s.c (decompiled source code)" % symbols_elf_path)
            print("\nVerify symbols:")
            print("  $ nm %s | head" % dwarf_output)
            print("  $ readelf -s %s | head" % dwarf_output)
            print("\nVerify DWARF:")
            print("  $ readelf --debug-dump=info %s | head -50" % dwarf_output)
            print("\nDebug with GDB:")
            print("  $ gdb %s" % dwarf_output)
            print("  (gdb) info functions")
            print("  (gdb) info variables")
            print("  (gdb) list main")
            print("  (gdb) break main")
            
            return dwarf_output
        else:
            print("\n✗ ERROR creating DWARF")
            return None
    
    except Exception as e:
        print("\n✗✗✗ FATAL ERROR creating DWARF: %s" % str(e))
        import traceback
        traceback.print_exc()
        return None


# Entry point of the Ghidra script
if __name__ == "__main__":
    try:
        # Use combined function that does everything
        result = add_symbols_and_dwarf()
        if result:
            print("\n✓✓✓ Script completed successfully!")
        else:
            print("\n✗✗✗ Script terminated with errors")
    except Exception as e:
        print("\n✗✗✗ FATAL ERROR: %s" % str(e))
        import traceback
        traceback.print_exc()
