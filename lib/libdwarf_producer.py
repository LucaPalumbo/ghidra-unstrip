#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Python wrapper for libdwarf Producer API - Creating DWARF from scratch
For rebuilding debug info from Ghidra analysis
"""

import ctypes
from ctypes import *
from enum import IntEnum
import struct

# Load the library
try:
    libdwarf = ctypes.CDLL("libdwarf.so")
except OSError:
    try:
        libdwarf = ctypes.CDLL("libdwarf.so.1")
    except OSError:
        libdwarf = ctypes.CDLL("/usr/lib/x86_64-linux-gnu/libdwarf.so")

# ============================================================================
# Base types
# ============================================================================
Dwarf_P_Debug = c_void_p
Dwarf_Error = c_void_p
Dwarf_P_Die = c_void_p
Dwarf_P_Attribute = c_void_p
Dwarf_P_Expr = c_void_p
Dwarf_Unsigned = c_uint64
Dwarf_Signed = c_int64
Dwarf_Half = c_uint16
Dwarf_Small = c_uint8
Dwarf_Addr = c_uint64
Dwarf_Bool = c_ubyte

# Return codes
DW_DLV_ERROR = -1
DW_DLV_OK = 0
DW_DLV_NO_ENTRY = 1

# ============================================================================
# DWARF constants
# ============================================================================


# Tags
class DW_TAG(IntEnum):
    DW_TAG_compile_unit = 0x11
    DW_TAG_subprogram = 0x2E
    DW_TAG_variable = 0x34
    DW_TAG_formal_parameter = 0x05
    DW_TAG_base_type = 0x24
    DW_TAG_pointer_type = 0x0F
    DW_TAG_structure_type = 0x13
    DW_TAG_union_type = 0x17
    DW_TAG_typedef = 0x16
    DW_TAG_member = 0x0D
    DW_TAG_array_type = 0x01
    DW_TAG_subrange_type = 0x21
    DW_TAG_enumeration_type = 0x04
    DW_TAG_enumerator = 0x28
    DW_TAG_lexical_block = 0x0B
    DW_TAG_class_type = 0x02


# Attributes
class DW_AT(IntEnum):
    DW_AT_name = 0x03
    DW_AT_low_pc = 0x11
    DW_AT_high_pc = 0x12
    DW_AT_language = 0x13
    DW_AT_comp_dir = 0x1B
    DW_AT_const_value = 0x1C
    DW_AT_producer = 0x25
    DW_AT_upper_bound = 0x2F
    DW_AT_type = 0x49
    DW_AT_byte_size = 0x0B
    DW_AT_decl_file = 0x3A
    DW_AT_decl_line = 0x3B
    DW_AT_encoding = 0x3E
    DW_AT_external = 0x3F
    DW_AT_location = 0x02
    DW_AT_frame_base = 0x40
    DW_AT_data_member_location = 0x38
    DW_AT_stmt_list = 0x10
    DW_AT_prototyped = 0x27
    DW_AT_declaration = 0x3C
    DW_AT_specification = 0x47


# Attribute forms
class DW_FORM(IntEnum):
    DW_FORM_addr = 0x01
    DW_FORM_block2 = 0x03
    DW_FORM_block4 = 0x04
    DW_FORM_data2 = 0x05
    DW_FORM_data4 = 0x06
    DW_FORM_data8 = 0x07
    DW_FORM_string = 0x08
    DW_FORM_block = 0x09
    DW_FORM_block1 = 0x0A
    DW_FORM_data1 = 0x0B
    DW_FORM_flag = 0x0C
    DW_FORM_sdata = 0x0D
    DW_FORM_strp = 0x0E
    DW_FORM_udata = 0x0F
    DW_FORM_ref_addr = 0x10
    DW_FORM_ref1 = 0x11
    DW_FORM_ref2 = 0x12
    DW_FORM_ref4 = 0x13
    DW_FORM_ref8 = 0x14
    DW_FORM_ref_udata = 0x15
    DW_FORM_indirect = 0x16
    DW_FORM_sec_offset = 0x17
    DW_FORM_exprloc = 0x18
    DW_FORM_flag_present = 0x19
    DW_FORM_ref_sig8 = 0x20


# Encoding for base types
class DW_ATE(IntEnum):
    DW_ATE_address = 0x01
    DW_ATE_boolean = 0x02
    DW_ATE_complex_float = 0x03
    DW_ATE_float = 0x04
    DW_ATE_signed = 0x05
    DW_ATE_signed_char = 0x06
    DW_ATE_unsigned = 0x07
    DW_ATE_unsigned_char = 0x08


# Languages
class DW_LANG(IntEnum):
    DW_LANG_C = 0x0002
    DW_LANG_C89 = 0x0001
    DW_LANG_C99 = 0x000C
    DW_LANG_C11 = 0x001D
    DW_LANG_C_plus_plus = 0x0004
    DW_LANG_C_plus_plus_03 = 0x0019
    DW_LANG_C_plus_plus_11 = 0x001A
    DW_LANG_C_plus_plus_14 = 0x0021


# Access modes
DW_DLC_READ = 0
DW_DLC_WRITE = 1
DW_DLC_RDWR = 2

# Producer flags
DW_DLC_SYMBOLIC_RELOCATIONS = 0x04
DW_DLC_POINTER64 = 0x200
DW_DLC_OFFSET32 = 0x400
DW_DLC_TARGET_LITTLEENDIAN = 0x10000

# ISA
DW_ISA_IA32 = 0
DW_ISA_IA64 = 1
DW_ISA_X86_64 = 2
DW_ISA_ARM = 3
DW_ISA_AARCH64 = 4

# Endianness
DW_ENDIAN_LITTLE = 0
DW_ENDIAN_BIG = 1

# DWARF Expression Opcodes
DW_OP_addr = 0x03
DW_OP_deref = 0x06
DW_OP_const1u = 0x08
DW_OP_const1s = 0x09
DW_OP_const2u = 0x0A
DW_OP_const2s = 0x0B
DW_OP_const4u = 0x0C
DW_OP_const4s = 0x0D
DW_OP_const8u = 0x0E
DW_OP_const8s = 0x0F
DW_OP_constu = 0x10
DW_OP_consts = 0x11
DW_OP_dup = 0x12
DW_OP_drop = 0x13
DW_OP_over = 0x14
DW_OP_pick = 0x15
DW_OP_swap = 0x16
DW_OP_rot = 0x17
DW_OP_xderef = 0x18
DW_OP_abs = 0x19
DW_OP_and = 0x1A
DW_OP_div = 0x1B
DW_OP_minus = 0x1C
DW_OP_mod = 0x1D
DW_OP_mul = 0x1E
DW_OP_neg = 0x1F
DW_OP_not = 0x20
DW_OP_or = 0x21
DW_OP_plus = 0x22
DW_OP_plus_uconst = 0x23
DW_OP_shl = 0x24
DW_OP_shr = 0x25
DW_OP_shra = 0x26
DW_OP_xor = 0x27
DW_OP_bra = 0x28
DW_OP_eq = 0x29
DW_OP_ge = 0x2A
DW_OP_gt = 0x2B
DW_OP_le = 0x2C
DW_OP_lt = 0x2D
DW_OP_ne = 0x2E
DW_OP_skip = 0x2F
DW_OP_lit0 = 0x30
DW_OP_reg0 = 0x50
DW_OP_fbreg = 0x91
DW_OP_regx = 0x90
DW_OP_call_frame_cfa = 0x9C

# ============================================================================
# Callback per producer
# ============================================================================

# Callback function types
CALLBACK_FUNC = ctypes.CFUNCTYPE(
    c_int,  # return type
    c_char_p,  # name
    c_int,  # size
    Dwarf_Unsigned,  # type
    Dwarf_Unsigned,  # flags
    Dwarf_Unsigned,  # link
    Dwarf_Unsigned,  # info
    POINTER(Dwarf_Unsigned),  # sect_name_index
    c_void_p,  # user data
    POINTER(c_int),  # error
)

# ============================================================================
# Funzioni Producer API
# ============================================================================

# dwarf_producer_init
libdwarf.dwarf_producer_init.argtypes = [
    Dwarf_Unsigned,  # flags (DW_DLC_WRITE, etc)
    CALLBACK_FUNC,  # callback function
    c_void_p,  # errhand
    c_void_p,  # errarg
    c_void_p,  # user_data
    c_char_p,  # isa_name (es. "x86_64")
    c_char_p,  # dwarf_version (es. "V4")
    c_void_p,  # extra (NULL)
    POINTER(Dwarf_P_Debug),  # dbg
    POINTER(Dwarf_Error),  # error
]
libdwarf.dwarf_producer_init.restype = c_int

# dwarf_producer_finish
libdwarf.dwarf_producer_finish.argtypes = [Dwarf_P_Debug, POINTER(Dwarf_Error)]
libdwarf.dwarf_producer_finish.restype = c_int

# dwarf_producer_finish_a (versione alternativa)
libdwarf.dwarf_producer_finish_a.argtypes = [Dwarf_P_Debug]
libdwarf.dwarf_producer_finish_a.restype = c_int

# dwarf_pro_set_default_string_form
libdwarf.dwarf_pro_set_default_string_form.argtypes = [
    Dwarf_P_Debug,
    Dwarf_Half,  # form (DW_FORM_string, etc)
    POINTER(Dwarf_Error),
]
libdwarf.dwarf_pro_set_default_string_form.restype = c_int

# dwarf_new_die
libdwarf.dwarf_new_die.argtypes = [
    Dwarf_P_Debug,
    Dwarf_Unsigned,  # tag
    Dwarf_P_Die,  # parent
    Dwarf_P_Die,  # child
    Dwarf_P_Die,  # left_sibling
    Dwarf_P_Die,  # right_sibling
    POINTER(Dwarf_Error),
]
libdwarf.dwarf_new_die.restype = Dwarf_P_Die

# dwarf_add_die_to_debug
libdwarf.dwarf_add_die_to_debug.argtypes = [
    Dwarf_P_Debug,
    Dwarf_P_Die,
    POINTER(Dwarf_Error),
]
libdwarf.dwarf_add_die_to_debug.restype = Dwarf_Unsigned

# dwarf_add_die_to_debug_a (versione alternativa)
libdwarf.dwarf_add_die_to_debug_a.argtypes = [
    Dwarf_P_Debug,
    Dwarf_P_Die,
    POINTER(Dwarf_Error),
]
libdwarf.dwarf_add_die_to_debug_a.restype = c_int

# dwarf_add_AT_name
libdwarf.dwarf_add_AT_name.argtypes = [
    Dwarf_P_Die,
    c_char_p,  # name
    POINTER(Dwarf_Error),
]
libdwarf.dwarf_add_AT_name.restype = Dwarf_P_Attribute

# dwarf_add_AT_comp_dir
libdwarf.dwarf_add_AT_comp_dir.argtypes = [Dwarf_P_Die, c_char_p, POINTER(Dwarf_Error)]
libdwarf.dwarf_add_AT_comp_dir.restype = Dwarf_P_Attribute

# dwarf_add_AT_producer
libdwarf.dwarf_add_AT_producer.argtypes = [Dwarf_P_Die, c_char_p, POINTER(Dwarf_Error)]
libdwarf.dwarf_add_AT_producer.restype = Dwarf_P_Attribute

# dwarf_add_AT_unsigned_const
libdwarf.dwarf_add_AT_unsigned_const.argtypes = [
    Dwarf_P_Debug,
    Dwarf_P_Die,
    Dwarf_Half,  # attribute
    Dwarf_Unsigned,  # value
    POINTER(Dwarf_Error),
]
libdwarf.dwarf_add_AT_unsigned_const.restype = Dwarf_P_Attribute

# dwarf_add_AT_signed_const
libdwarf.dwarf_add_AT_signed_const.argtypes = [
    Dwarf_P_Debug,
    Dwarf_P_Die,
    Dwarf_Half,
    Dwarf_Signed,
    POINTER(Dwarf_Error),
]
libdwarf.dwarf_add_AT_signed_const.restype = Dwarf_P_Attribute

# dwarf_add_AT_targ_address
libdwarf.dwarf_add_AT_targ_address.argtypes = [
    Dwarf_P_Debug,
    Dwarf_P_Die,
    Dwarf_Half,  # attribute
    Dwarf_Unsigned,  # pc_value
    Dwarf_Unsigned,  # sym_index
    POINTER(Dwarf_Error),
]
libdwarf.dwarf_add_AT_targ_address.restype = Dwarf_P_Attribute

# dwarf_add_AT_reference
libdwarf.dwarf_add_AT_reference.argtypes = [
    Dwarf_P_Debug,
    Dwarf_P_Die,
    Dwarf_Half,  # attribute
    Dwarf_P_Die,  # referenced_die
    POINTER(Dwarf_Error),
]
libdwarf.dwarf_add_AT_reference.restype = Dwarf_P_Attribute

# dwarf_add_AT_flag
libdwarf.dwarf_add_AT_flag.argtypes = [
    Dwarf_P_Debug,
    Dwarf_P_Die,
    Dwarf_Half,
    Dwarf_Small,  # flag value (0 or 1)
    POINTER(Dwarf_Error),
]
libdwarf.dwarf_add_AT_flag.restype = Dwarf_P_Attribute

# dwarf_add_AT_string
libdwarf.dwarf_add_AT_string.argtypes = [
    Dwarf_P_Debug,
    Dwarf_P_Die,
    Dwarf_Half,
    c_char_p,
    POINTER(Dwarf_Error),
]
libdwarf.dwarf_add_AT_string.restype = Dwarf_P_Attribute

# dwarf_new_expr
libdwarf.dwarf_new_expr.argtypes = [
    Dwarf_P_Debug,
    POINTER(Dwarf_Error),
]
libdwarf.dwarf_new_expr.restype = Dwarf_P_Expr

# dwarf_add_expr_gen
libdwarf.dwarf_add_expr_gen.argtypes = [
    Dwarf_P_Expr,
    Dwarf_Small,  # opcode
    Dwarf_Unsigned,  # val1
    Dwarf_Unsigned,  # val2
    POINTER(Dwarf_Error),
]
libdwarf.dwarf_add_expr_gen.restype = Dwarf_Unsigned

# dwarf_add_expr_addr_b
libdwarf.dwarf_add_expr_addr_b.argtypes = [
    Dwarf_P_Expr,
    Dwarf_Unsigned,  # address
    Dwarf_Unsigned,  # sym_index
    POINTER(Dwarf_Error),
]
libdwarf.dwarf_add_expr_addr_b.restype = Dwarf_Unsigned

# dwarf_add_AT_location_expr
libdwarf.dwarf_add_AT_location_expr.argtypes = [
    Dwarf_P_Debug,
    Dwarf_P_Die,
    Dwarf_Half,  # attribute
    Dwarf_P_Expr,
    POINTER(Dwarf_Error),
]
libdwarf.dwarf_add_AT_location_expr.restype = Dwarf_P_Attribute

# dwarf_add_directory_decl
libdwarf.dwarf_add_directory_decl.argtypes = [
    Dwarf_P_Debug,
    c_char_p,  # directory name
    POINTER(Dwarf_Error),
]
libdwarf.dwarf_add_directory_decl.restype = Dwarf_Unsigned

# dwarf_add_file_decl
libdwarf.dwarf_add_file_decl.argtypes = [
    Dwarf_P_Debug,
    c_char_p,  # file name
    Dwarf_Unsigned,  # directory index
    Dwarf_Unsigned,  # modification time
    Dwarf_Unsigned,  # file length
    POINTER(Dwarf_Error),
]
libdwarf.dwarf_add_file_decl.restype = Dwarf_Unsigned

# dwarf_add_line_entry
libdwarf.dwarf_add_line_entry.argtypes = [
    Dwarf_P_Debug,
    Dwarf_Unsigned,  # file index
    Dwarf_Addr,  # address
    Dwarf_Unsigned,  # line number
    Dwarf_Signed,  # column number
    Dwarf_Bool,  # is_stmt
    Dwarf_Bool,  # basic_block
    POINTER(Dwarf_Error),
]
libdwarf.dwarf_add_line_entry.restype = Dwarf_Unsigned

# dwarf_lne_end_sequence_a
libdwarf.dwarf_lne_end_sequence_a.argtypes = [
    Dwarf_P_Debug,
    Dwarf_Addr,  # end address
    POINTER(Dwarf_Error),
]
libdwarf.dwarf_lne_end_sequence_a.restype = Dwarf_Unsigned

# dwarf_transform_to_disk_form
libdwarf.dwarf_transform_to_disk_form.argtypes = [Dwarf_P_Debug, POINTER(Dwarf_Error)]
libdwarf.dwarf_transform_to_disk_form.restype = Dwarf_Signed

# dwarf_get_section_bytes
libdwarf.dwarf_get_section_bytes.argtypes = [
    Dwarf_P_Debug,
    Dwarf_Signed,  # section index
    POINTER(Dwarf_Signed),  # elf_section_index
    POINTER(Dwarf_Unsigned),  # length
    POINTER(Dwarf_Error),
]
libdwarf.dwarf_get_section_bytes.restype = POINTER(c_ubyte)

# ============================================================================
# High-level Python wrapper
# ============================================================================


class DwarfProducerError(Exception):
    """Exception for libdwarf producer errors"""

    pass


class DwarfProducer:
    """Wrapper to create DWARF from scratch"""

    def __init__(self, isa="x86_64", dwarf_version="V2", endian=DW_ENDIAN_LITTLE):
        self.dbg = Dwarf_P_Debug()
        self.sections = []
        self.dies = []
        self.isa = isa
        self.dwarf_version = dwarf_version

        # Dummy callback to handle sections
        def section_callback(
            name, size, type, flags, link, info, sect_name_index, user_data, error
        ):
            # Store section information
            section_info = {
                "name": name.decode("utf-8") if name else "",
                "size": size,
                "type": type,
                "flags": flags,
            }
            self.sections.append(section_info)
            # Return the index of the just-added section (as in ghidra2dwarf)
            section_index = len(self.sections) - 1
            if sect_name_index:
                sect_name_index[0] = section_index
            return section_index

        self.callback = CALLBACK_FUNC(section_callback)
        error = Dwarf_Error()

        # Use same flags as ghidra2dwarf
        flags = DW_DLC_WRITE | DW_DLC_SYMBOLIC_RELOCATIONS | DW_DLC_POINTER64 | DW_DLC_OFFSET32
        if endian == DW_ENDIAN_LITTLE:
            flags |= DW_DLC_TARGET_LITTLEENDIAN

        res = libdwarf.dwarf_producer_init(
            flags,
            self.callback,
            None,
            None,
            None,
            isa.encode("utf-8"),
            dwarf_version.encode("utf-8"),
            None,
            byref(self.dbg),
            byref(error),
        )

        if res != DW_DLV_OK:
            raise DwarfProducerError("dwarf_producer_init failed: %s" % res)
        
        # Set default form for strings (important!)
        res = libdwarf.dwarf_pro_set_default_string_form(
            self.dbg, DW_FORM.DW_FORM_string, byref(error)
        )
        if res != DW_DLV_OK:
            raise DwarfProducerError("dwarf_pro_set_default_string_form failed: %s" % res)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.finish()

    def finish(self):
        """Closes the producer"""
        if self.dbg:
            # Use dwarf_producer_finish_a as in ghidra2dwarf
            libdwarf.dwarf_producer_finish_a(self.dbg)
            self.dbg = None

    def create_die(self, tag, parent=None):
        """Creates a new DIE"""
        error = Dwarf_Error()

        die = libdwarf.dwarf_new_die(
            self.dbg,
            tag,
            parent.die if parent else None,
            None,  # child
            None,  # left_sibling
            None,  # right_sibling
            byref(error),
        )

        if not die:
            raise DwarfProducerError("dwarf_new_die failed")

        die_wrapper = ProducerDie(self, die, tag)
        self.dies.append(die_wrapper)
        return die_wrapper

    def add_cu_die(self, die):
        """Adds a compilation unit DIE to debug"""
        error = Dwarf_Error()
        # Use dwarf_add_die_to_debug_a as in ghidra2dwarf
        res = libdwarf.dwarf_add_die_to_debug_a(self.dbg, die.die, byref(error))
        if res != DW_DLV_OK:
            raise DwarfProducerError("dwarf_add_die_to_debug_a failed")
        return res

    def transform_to_disk(self):
        """Transforms DWARF to disk format"""
        error = Dwarf_Error()
        n_sections = libdwarf.dwarf_transform_to_disk_form(self.dbg, byref(error))
        if n_sections == DW_DLV_ERROR:
            raise DwarfProducerError("dwarf_transform_to_disk_form failed")
        return n_sections

    def get_section_bytes(self, section_idx):
        """Gets bytes of a section"""
        error = Dwarf_Error()
        elf_section_index = Dwarf_Signed()
        length = Dwarf_Unsigned()

        data = libdwarf.dwarf_get_section_bytes(
            self.dbg, section_idx, byref(elf_section_index), byref(length), byref(error)
        )

        if not data:
            raise DwarfProducerError("dwarf_get_section_bytes failed")

        # Convert to Python bytes
        return bytes(data[0 : length.value]), elf_section_index.value

    def create_expr(self):
        """Creates a new DWARF expression"""
        error = Dwarf_Error()
        expr = libdwarf.dwarf_new_expr(self.dbg, byref(error))
        if not expr:
            raise DwarfProducerError("dwarf_new_expr failed")
        return expr

    def add_expr_addr(self, expr, address, sym_index=0):
        """Adds an address to a DWARF expression"""
        error = Dwarf_Error()
        res = libdwarf.dwarf_add_expr_addr_b(expr, address, sym_index, byref(error))
        if res == DW_DLV_ERROR:
            raise DwarfProducerError("dwarf_add_expr_addr_b failed")
        return res

    def add_expr_op(self, expr, opcode, val1=0, val2=0):
        """Adds an operation to a DWARF expression"""
        error = Dwarf_Error()
        res = libdwarf.dwarf_add_expr_gen(expr, opcode, val1, val2, byref(error))
        if res == DW_DLV_ERROR:
            raise DwarfProducerError("dwarf_add_expr_gen failed")
        return res

    def add_directory(self, directory):
        """Adds a directory to the line table"""
        error = Dwarf_Error()
        dir_idx = libdwarf.dwarf_add_directory_decl(
            self.dbg, directory.encode("utf-8"), byref(error)
        )
        if dir_idx == DW_DLV_ERROR:
            raise DwarfProducerError("dwarf_add_directory_decl failed")
        return dir_idx

    def add_file(self, filename, dir_index, mod_time=0, file_len=0):
        """Adds a source file to the line table"""
        error = Dwarf_Error()
        file_idx = libdwarf.dwarf_add_file_decl(
            self.dbg,
            filename.encode("utf-8"),
            dir_index,
            mod_time,
            file_len,
            byref(error),
        )
        if file_idx == DW_DLV_ERROR:
            raise DwarfProducerError("dwarf_add_file_decl failed")
        return file_idx

    def add_line_entry(self, file_index, address, line_number, column=0, is_stmt=True, basic_block=False):
        """Adds an entry to the line table (maps address → line)"""
        error = Dwarf_Error()
        res = libdwarf.dwarf_add_line_entry(
            self.dbg,
            file_index,
            address,
            line_number,
            column,
            is_stmt,
            basic_block,
            byref(error),
        )
        if res == DW_DLV_ERROR:
            raise DwarfProducerError("dwarf_add_line_entry failed")
        return res

    def end_line_sequence(self, end_address):
        """Ends the line entry sequence"""
        error = Dwarf_Error()
        res = libdwarf.dwarf_lne_end_sequence_a(self.dbg, end_address, byref(error))
        if res == DW_DLV_ERROR:
            raise DwarfProducerError("dwarf_lne_end_sequence_a failed")
        return res


class ProducerDie:
    """Wrapper for a DIE being created"""

    def __init__(self, producer, die, tag):
        self.producer = producer
        self.die = die
        self.tag = tag

    def add_name(self, name):
        """Adds DW_AT_name attribute"""
        error = Dwarf_Error()
        attr = libdwarf.dwarf_add_AT_name(self.die, name.encode("utf-8"), byref(error))
        if not attr:
            raise DwarfProducerError("dwarf_add_AT_name failed")
        return attr

    def add_comp_dir(self, comp_dir):
        """Adds DW_AT_comp_dir attribute"""
        error = Dwarf_Error()
        attr = libdwarf.dwarf_add_AT_comp_dir(
            self.die, comp_dir.encode("utf-8"), byref(error)
        )
        if not attr:
            raise DwarfProducerError("dwarf_add_AT_comp_dir failed")
        return attr

    def add_producer(self, producer):
        """Adds DW_AT_producer attribute"""
        error = Dwarf_Error()
        attr = libdwarf.dwarf_add_AT_producer(
            self.die, producer.encode("utf-8"), byref(error)
        )
        if not attr:
            raise DwarfProducerError("dwarf_add_AT_producer failed")
        return attr

    def add_unsigned_constant(self, attribute, value):
        """Adds an attribute with unsigned value"""
        error = Dwarf_Error()
        attr = libdwarf.dwarf_add_AT_unsigned_const(
            self.producer.dbg, self.die, attribute, value, byref(error)
        )
        if not attr:
            raise DwarfProducerError("dwarf_add_AT_unsigned_const failed")
        return attr

    def add_signed_constant(self, attribute, value):
        """Adds an attribute with signed value"""
        error = Dwarf_Error()
        attr = libdwarf.dwarf_add_AT_signed_const(
            self.producer.dbg, self.die, attribute, value, byref(error)
        )
        if not attr:
            raise DwarfProducerError("dwarf_add_AT_signed_const failed")
        return attr

    def add_address(self, attribute, address, sym_index=0):
        """Adds an address attribute (e.g., DW_AT_low_pc)"""
        error = Dwarf_Error()
        attr = libdwarf.dwarf_add_AT_targ_address(
            self.producer.dbg, self.die, attribute, address, sym_index, byref(error)
        )
        if not attr:
            raise DwarfProducerError("dwarf_add_AT_targ_address failed")
        return attr

    def add_reference(self, attribute, target_die):
        """Adds a reference to another DIE (e.g., DW_AT_type)"""
        error = Dwarf_Error()
        attr = libdwarf.dwarf_add_AT_reference(
            self.producer.dbg, self.die, attribute, target_die.die, byref(error)
        )
        if not attr:
            raise DwarfProducerError("dwarf_add_AT_reference failed")
        return attr

    def add_flag(self, attribute, value):
        """Adds a flag (0 or 1)"""
        error = Dwarf_Error()
        attr = libdwarf.dwarf_add_AT_flag(
            self.producer.dbg, self.die, attribute, 1 if value else 0, byref(error)
        )
        if not attr:
            raise DwarfProducerError("dwarf_add_AT_flag failed")
        return attr

    def add_string(self, attribute, value):
        """Adds a string"""
        error = Dwarf_Error()
        attr = libdwarf.dwarf_add_AT_string(
            self.producer.dbg, self.die, attribute, value.encode("utf-8"), byref(error)
        )
        if not attr:
            raise DwarfProducerError("dwarf_add_AT_string failed")
        return attr

    def add_location_expr(self, attribute, expr):
        """Adds a location expression (e.g., for DW_AT_location)"""
        error = Dwarf_Error()
        attr = libdwarf.dwarf_add_AT_location_expr(
            self.producer.dbg, self.die, attribute, expr, byref(error)
        )
        if not attr:
            raise DwarfProducerError("dwarf_add_AT_location_expr failed")
        return attr


# ============================================================================
# Integration with existing ELF file
# ============================================================================


def write_dwarf_to_elf(elf_path, sections_data, output_path):
    """
    Adds DWARF sections to an existing ELF file
    Requires: pyelftools
    """
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.sections import Section
    except ImportError:
        print("Error: install pyelftools with: pip install pyelftools")
        return

    # Read the original ELF file
    with open(elf_path, "rb") as f:
        elf_data = bytearray(f.read())

    # Here you should implement the logic to:
    # 1. Parse the ELF header
    # 2. Add the new DWARF sections
    # 3. Update the section header table
    # 4. Write the new file

    # This is complex and requires detailed handling of the ELF format
    # For simplicity, save sections as separate files

    import os

    output_dir = os.path.dirname(output_path) or "."

    for section_name, data in sections_data.items():
        section_file = os.path.join(output_dir, "%s.bin" % section_name)
        with open(section_file, "wb") as f:
            f.write(data)
        print("Saved section: %s" % section_file)

    print("\nTo add sections to ELF use objcopy:")
    for section_name in sections_data.keys():
        print(
            "  objcopy --add-section %s=%s.bin %s %s" % (section_name, section_name, elf_path, output_path)
        )


# ============================================================================
# Helpers for building common structures from Ghidra
# ============================================================================


class GhidraDwarfBuilder:
    """Helper for building DWARF from Ghidra information"""

    def __init__(self, producer):
        self.producer = producer
        self.type_cache = {}  # Cache for already created types

    def create_compile_unit(self, name, comp_dir="/tmp", language=DW_LANG.DW_LANG_C):
        """Creates a compilation unit"""
        cu_die = self.producer.create_die(DW_TAG.DW_TAG_compile_unit)
        cu_die.add_name(name)
        cu_die.add_comp_dir(comp_dir)
        cu_die.add_producer("Ghidra DWARF Generator")
        cu_die.add_unsigned_constant(DW_AT.DW_AT_language, language)
        return cu_die

    def create_base_type(self, name, byte_size, encoding, parent=None):
        """Creates a base type (int, char, float, etc)"""
        cache_key = "base_%s_%s_%s" % (name, byte_size, encoding)
        if cache_key in self.type_cache:
            return self.type_cache[cache_key]

        type_die = self.producer.create_die(DW_TAG.DW_TAG_base_type, parent)
        type_die.add_name(name)
        type_die.add_unsigned_constant(DW_AT.DW_AT_byte_size, byte_size)
        type_die.add_unsigned_constant(DW_AT.DW_AT_encoding, encoding)

        self.type_cache[cache_key] = type_die
        return type_die

    def create_pointer_type(self, target_type, parent=None):
        """Creates a pointer type"""
        ptr_die = self.producer.create_die(DW_TAG.DW_TAG_pointer_type, parent)
        if target_type:
            ptr_die.add_reference(DW_AT.DW_AT_type, target_type)
        ptr_die.add_unsigned_constant(DW_AT.DW_AT_byte_size, 8)  # 64-bit
        return ptr_die

    def create_function(self, name, low_pc, high_pc, parent=None):
        """Creates a subprogram (function)"""
        func_die = self.producer.create_die(DW_TAG.DW_TAG_subprogram, parent)
        func_die.add_name(name)
        func_die.add_address(DW_AT.DW_AT_low_pc, low_pc)
        # Use add_address for high_pc (absolute address) as ghidra2dwarf does
        func_die.add_address(DW_AT.DW_AT_high_pc, high_pc + 1)
        func_die.add_flag(DW_AT.DW_AT_external, True)
        return func_die

    def create_parameter(self, name, param_type, parent):
        """Creates a function parameter"""
        param_die = self.producer.create_die(DW_TAG.DW_TAG_formal_parameter, parent)
        param_die.add_name(name)
        if param_type:
            param_die.add_reference(DW_AT.DW_AT_type, param_type)
        return param_die

    def create_variable(self, name, var_type, parent=None):
        """Creates a variable"""
        var_die = self.producer.create_die(DW_TAG.DW_TAG_variable, parent)
        var_die.add_name(name)
        if var_type:
            var_die.add_reference(DW_AT.DW_AT_type, var_type)
        return var_die

    def create_struct(self, name, byte_size, parent=None):
        """Creates a structure"""
        struct_die = self.producer.create_die(DW_TAG.DW_TAG_structure_type, parent)
        struct_die.add_name(name)
        struct_die.add_unsigned_constant(DW_AT.DW_AT_byte_size, byte_size)
        return struct_die

    def create_struct_member(self, name, member_type, offset, parent):
        """Creates a structure member"""
        member_die = self.producer.create_die(DW_TAG.DW_TAG_member, parent)
        member_die.add_name(name)
        member_die.add_reference(DW_AT.DW_AT_type, member_type)
        member_die.add_unsigned_constant(DW_AT.DW_AT_data_member_location, offset)
        return member_die
