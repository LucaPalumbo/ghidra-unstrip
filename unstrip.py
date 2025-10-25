# Add back symbol to stripped ELF file
# @author Feld # @category Symbols
# @keybinding
# @menupath
# @toolbar
# @runtime PyGhidra

from ghidra.app.util.bin.format.elf import ElfHeader
from ghidra.app.util.bin import FileByteProvider
import java.io.File as JFile
from java.nio.file import AccessMode
import csv
import os
import subprocess

program = getCurrentProgram()
elf_path = program.getExecutablePath()
jfile = JFile(elf_path)
provider = FileByteProvider(jfile, None, AccessMode.READ)
base_address = program.getImageBase().getOffset()


def onError(e):
    print("Error:", e)


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
    addr = symbol.getAddress().getOffset() - base_address
    for start, end, idx in section_map:
        if start <= addr < end:
            return idx
    return 0  # SHN_UNDEF


# Precompute function lengths
func_manager = program.getFunctionManager()
func_lens = {
    f.getName(): f.getBody().getNumAddresses() for f in func_manager.getFunctions(True)
}

listing = program.getListing()


def getSymbolSize(symbol):
    try:
        data = listing.getDataAt(symbol.getAddress())
        return data.getLength()
    except:
        return None


def gather_information(symbol):
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


def spawn_add_symbol_subroutine(file_origin, file_symbols, file_out):
    """
    Finds the path of the script `add_symbol` and executes:
    ./add_symbol <file_origin> <file_symbols> <file_out>
    """
    # Assume `add_symbol` is in the same directory as this script
    script_dir = os.path.dirname(os.path.realpath(__file__))
    add_symbol_path = os.path.join(script_dir, "add_symbols")

    if not os.path.isfile(add_symbol_path):
        print(f"Error: {add_symbol_path} not found.")
        return

    # Build the command
    cmd = [add_symbol_path, file_origin, file_symbols, file_out]

    print(f"Executing: {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        print("Output:", result.stdout)
        if result.stderr:
            print("Errors:", result.stderr)
    except subprocess.CalledProcessError as e:
        print("Failed to run add_symbol:", e)
        print("Output:", e.stdout)
        print("Errors:", e.stderr)


# Filter symbols early
symbol_table = program.getSymbolTable()
symbols = [
    s
    for s in symbol_table.getDefinedSymbols()
    if not s.isDynamic() and not s.isExternal()
]

out_name = elf_path + "_sym.csv"
print("Writing symbols to:", out_name)

rows = [["name", "addr", "type", "size", "binding", "ndx"]]

for i, symbol in enumerate(symbols):
    if i % 1000 == 0:
        print(f"Processing symbol {i} of {len(symbols)}")
    info = gather_information(symbol)
    rows.append(
        [
            info["name"],
            hex(info["addr"]),
            info["type"],
            info["size"] if info["size"] is not None else "",
            info["binding"] if info["binding"] is not None else "",
            info["ndx"],
        ]
    )

with open(out_name, "w") as f:
    w = csv.writer(f)
    w.writerows(rows)

spawn_add_symbol_subroutine(elf_path, out_name, elf_path + "_unstripped")
