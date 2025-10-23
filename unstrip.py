#Add back symbol to stripped ELF file
#@author Feld
#@category Symbols
#@keybinding 
#@menupath 
#@toolbar 
#@runtime PyGhidra

# from __main__ import getCurrentProgram, getState
from ghidra.app.util.bin.format.elf import ElfHeader
from ghidra.app.util.bin import MemoryByteProvider
from ghidra.app.util.bin import FileByteProvider
import java.io.File as JFile
from java.nio.file import AccessMode
import csv


program = getCurrentProgram()

elf_path = program.getExecutablePath()

jfile = JFile(elf_path)
provider = FileByteProvider(jfile, None, AccessMode.READ)
memory = program.getMemory()
base_address = program.getImageBase().getOffset()
# memory_byte_provider = MemoryByteProvider(memory, program.getImageBase())
# elf_header = ElfHeader(memory_byte_provider, onError)

def onError(e):
    print("Error:", e)
elf_header = ElfHeader(provider, onError)
file_size = provider.length()


def getFunctionLen(function_name):
    func_manager = program.getFunctionManager()
    functions = func_manager.getFunctions(True)
    for func in functions:
        if func.getName() == function_name:
            return func.getBody().getNumAddresses()


def getNdx(symbol):
    addr = symbol.getAddress().getOffset() - base_address  
    section = elf_header.getSectionLoadHeaderContaining(addr + 1)  # temporary fix for off-by-one error in getSectionLoadHeaderContaining
    section_index = elf_header.getSectionIndex(section) if section else 0  # SHN_UNDEF
    return section_index


def getLableSize(symbol):
    listing = program.getListing()
    try:
        data = listing.getDataAt(symbol.getAddress())
        return data.getLength()
    except Exception as e:
        print("Error getting size of Label %s: %s" % (symbol.getName(), e))
        return None

def gather_information(symbol):
    name = symbol.getName()
    addr = symbol.getAddress().getOffset() - base_address if symbol.getAddress().getOffset() - base_address >= 0 else 0  
    sym_type = symbol.getSymbolType().toString()
    ndx = getNdx(symbol)

    binding = None
    size = None
    # print("Gathering info for symbol:", name, "Type:", sym_type)
    if sym_type == "Function":
        size = getFunctionLen(name)
        binding = "global"

    if sym_type == "Label":
        size = getLableSize(symbol)
        binding = "global" if size is not None else "local"

    return {
        "name": name,
        "addr": addr,
        "type": sym_type,
        "size": size,
        "binding": binding,
        "ndx": ndx
    }



if __name__ == "__main__":

    elf_header.parse()
    sections = elf_header.getSections()
    
    symbol_table = program.getSymbolTable()
    symbols = symbol_table.getDefinedSymbols()

    out_name = elf_path + "_sym.csv"
    print("Writing symbols to:", out_name)
    with open(out_name, 'w') as f:
        w = csv.writer(f)
        w.writerow(["name", "addr", "type", "size", "binding", "ndx"])
        for s in symbols:
            if s.isDynamic() or s.isExternal():
                continue
            info = gather_information(s)
            w.writerow([
                info["name"],
                hex(info["addr"]),
                info["type"],
                info["size"] if info["size"] is not None else "",
                info["binding"] if info["binding"] is not None else "",
                info["ndx"]
            ])
            