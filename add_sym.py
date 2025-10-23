
import sys
import csv
import lief


def parse_addr(addr_str):
    # addr_str may be like '0x400560' or '400560'
    if addr_str.startswith('0x'):
        return int(addr_str, 16)
    return int(addr_str, 16)


def load_csv(csv_path):
    syms = []
    with open(csv_path, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for r in reader:
            try:
                addr = int(r['addr'], 16) if r['addr'].startswith('0x') else int(r['addr'], 10)
            except Exception:
                # try to parse ghidra style address like '00400560'
                addr = int(r['addr'], 10)
            name = r['name']
            type = r['type']
            binding = r['binding']
            size = int(r.get('size', 0)) if r.get('size') else 0
            ndx = int(r.get('ndx', 0)) if r.get('ndx') else 0
            syms.append({'name': name,'addr': addr, 'type': type, 'size': size, 'binding': binding, 'ndx': ndx})
    return syms


def add_symbols_to_elf(input_elf, symbols, output_elf):
    print('[*] Parsing ELF:', input_elf)
    elf = lief.parse(input_elf)
    if not isinstance(elf, lief.ELF.Binary):
        raise SystemExit('Not an ELF binary or failed to parse')

    # Make a shallow copy to modify
    builder = lief.ELF.Builder(elf)

    # LIEF offers add_static_symbol (and add_dynamic_symbol) on Binary
    # We'll create Symbol objects and add them via add_static_symbol.

    added = 0
    for s in symbols:
        name = s['name']
        addr = s['addr']
        type = s['type']
        size = s['size']
        binding = s['binding']
        ndx =  s['ndx']

        # # Skip empty/auto names from Ghidra
        # if not name or name.startswith('FUN_') and len(name) < 6:
        #     # allow common 'FUN_' but skip very generic short names
        #     pass
        
        sym = lief.ELF.Symbol()
        sym.name = name
        sym.value = addr 
        if type == 'Function':
            sym.type = sym.TYPE.FUNC
        elif type == 'Label':
            sym.type = sym.TYPE.OBJECT
        sym.size = size
        if binding == 'global':
            sym.binding = sym.BINDING.GLOBAL
        elif binding == 'local':
            sym.binding = sym.BINDING.LOCAL
        elif binding == 'weak':
            sym.binding = sym.BINDING.WEAK

        # sym.binding =  sym.BINDING.GLOBAL  
        # sym.type = sym.TYPE.FUNC
        sym.shndx = ndx

        try:
            elf.add_symtab_symbol(sym)
            added += 1
        except Exception as e:
            print('[!] failed to add', name, hex(addr), '->', e)

    print('[*] Added symbols:', added)

    # Rebuild and write
    print('[*] Building new ELF...')
    builder.build()
    builder.write(output_elf)
    print('[+] Wrote patched ELF to', output_elf)


if __name__ == '__main__':
    if len(sys.argv) != 4:
        print('Usage: python3 add_symbols_lief.py <input-binary> <ghidra-csv> <output-binary>')
        sys.exit(1)

    input_bin = sys.argv[1]
    csv_file = sys.argv[2]
    output_bin = sys.argv[3]

    syms = load_csv(csv_file)
    print('[*] Loaded', len(syms), 'symbols from', csv_file)

    add_symbols_to_elf(input_bin, syms, output_bin)
