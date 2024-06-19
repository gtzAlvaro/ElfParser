import argparse
from tabulate import tabulate
import elf as elf


def dump_file_header(file_header):
    print('ELF Header:')
    matrix = [
        ['Magic:', file_header.magic_number],
        ['Class:', file_header.ei_class],
        ['Data:', file_header.ei_class],
        ['Version:', file_header.version],
        ['OS/ABI:', file_header.osabi],
        ['ABI Version:', file_header.abiversion],
        ['Type:', file_header.type],
        ['Machine:', file_header.machine],
        ['Version:', hex(file_header.e_version)],
        ['Entry point address:', hex(file_header.entry)],
        ['Start of program headers:', f'{file_header.phoff} (bytes into file)'],
        ['Start of section headers:', f'{file_header.shoff} (bytes into file)'],
        ['Flags:', hex(file_header.flags)],
        ['Size of this header:', f'{file_header.ehsize} (bytes)'],
        ['Size of program headers:', f'{file_header.phentsize} (bytes)'],
        ['Number of program headers:', file_header.phnum],
        ['Size of section headers:', f'{file_header.shentsize} (bytes)'],
        ['Number of section headers:', file_header.shnum],
        ['Section header string table index:', file_header.shstrndx],
    ]
    print(tabulate(matrix, tablefmt="plain"))


def dump_program_headers(file_header, program_headers):
    print(f'\nElf file type is {file_header.type}')
    print(f'Entry point {hex(file_header.entry)}')
    print(f'There are {len(program_headers)} program headers, starting at offset {file_header.phoff}')
    matrix = []
    for ph in program_headers:
        matrix.append([ph.type, hex(ph.offset), hex(ph.vaddr), hex(ph.paddr), hex(ph.filesz), hex(ph.memsz), ph.flags, ph.align])
    print('Program Headers:')
    headers = ['Type', 'Offset', 'VirtAddr', 'PhysAddr', 'FileSiz', 'MemSiz', 'Flg', 'Align']
    print(tabulate(matrix, headers=headers, tablefmt="plain"))


def dump_section_headers(file_header, section_headers):
    print(f'There are {len(section_headers)} section headers, starting at offset {hex(file_header.shoff)}:\n')
    matrix = []
    for section in section_headers:
        name, sh = section_headers[section]
        matrix.append([f"[{str(section).rjust(2, ' ')}]", name, sh.type, f'{sh.addr:08x}', hex(sh.offset), hex(sh.size), f'{sh.entsize:02x}', sh.flags, sh.link, sh.info, sh.addralign])
        section += 1
    print('Section Headers:')
    headers = ['[Nr]', 'Name', 'Type', 'Addr', 'Off', 'Size', 'ES', 'Flg', 'Lk', 'Inf', 'Al']
    print(tabulate(matrix, headers=headers, tablefmt="plain"))


def dump_symbol_table(symbols):
    matrix = []
    for num in symbols:
        name, symbol = symbols[num]
        st_type = symbol.info & 0x0f
        st_bind = symbol.info >> 4
        ndx = symbol.shndx
        if symbol.shndx in elf.eh.SHN:
            ndx = elf.eh.SHN[symbol.shndx]
        matrix.append([f'{num}:', f'{symbol.value:08x}', symbol.size, elf.eh.ST_TYPE[st_type], elf.eh.ST_BIND[st_bind], 'DEFAULT', ndx, name])
    print(f'\nSymbol table \'.symtab\' contains {len(symbols)} entries:')
    headers = ['Num:', 'Value', 'Size', 'Type', 'Bind', 'Vis', 'Ndx', 'Name']
    print(tabulate(matrix, headers=headers, tablefmt="plain"))


def dump_abbreviation_tables(abbreviation_tables):
    print('Contents of the .debug_abbrev section:\n')
    at_pad = len(max(list(elf.dh.DW_AT.values()), key=len))
    tag_pad = len(max(list(elf.dh.DW_TAG.values()), key=len))
    for num in abbreviation_tables:
        print(f'  Number TAG ({hex(num)})')
        abbreviation_table = abbreviation_tables[num]
        for code in abbreviation_table:
            tag, has_children, attrs = abbreviation_table[code]
            print(f"   {str(code).ljust(7, ' ')}{elf.dh.DW_TAG[tag].ljust(tag_pad, ' ')}{elf.dh.DW_CHILDREN[has_children]}")
            for name, form in attrs:
                if name == 0 and form == 0:
                    dw_at_value = f'{elf.dh.DW_AT[name]}: {name}'
                    print(f"    {dw_at_value.ljust(at_pad, ' ')}{elf.dh.DW_FORM[form]}: {form}")
                else:
                    print(f"    {elf.dh.DW_AT[name].ljust(at_pad, ' ')}{elf.dh.DW_FORM[form]}")

def dump_address_range_table(address_range_table):
    print('Contents of the .debug_aranges section:\n')
    for num in address_range_table:
        arh, values = address_range_table[num]
        print(f'  Length:                   {arh.length}')
        print(f'  Version:                  {arh.version}')
        print(f'  Offset into .debug_info:  {hex(arh.info_offset)}')
        print(f'  Pointer Size:             {arh.ptr_size}')
        print(f'  Segment Size:             {arh.seg_size}\n')
        print('    Address    Length')
        for address, length in values:
            print(f'    {address:08x} {length:08x}')
    print()

def dump_name_lookup_table(name_lookup_table):
    print('Contents of the .debug_pubnames section:\n')
    for num in name_lookup_table:
        nlh, values = name_lookup_table[num]
        print(f'  Length:                              {nlh.length}')
        print(f'  Version:                             {nlh.version}')
        print(f'  Offset into .debug_info section:     {hex(nlh.info_offset)}')
        print(f'  Size of area in .debug_info section: {nlh.info_size}\n')
        print('    Offset   Name')
        for offset, name in values:
            offset_str = f'{offset:x}'
            print(f"    {offset_str.ljust(9, ' ')}{name}")
    print()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("elf_file", help="path to elf file")
    parser.add_argument("-f", "--file-header", help="Display the ELF file header",
                        action="store_true")
    parser.add_argument("-l", "--program-headers", help="Display the program headers",
                        action="store_true")
    parser.add_argument("-S", "--section-headers", help="Display the sections' header",
                        action="store_true")
    parser.add_argument("-e", "--headers", help="Equivalent to: -h -l -S",
                        action="store_true")
    parser.add_argument("-s", "--syms", help="Display the symbol table",
                        action="store_true")
    parser.add_argument("-wa", help="Display the contents of DWARF debug_abbrev section",
                        action="store_true")
    parser.add_argument("-wr", help="Display the contents of DWARF debug_aranges section",
                        action="store_true")
    parser.add_argument("-wp", help="Display the contents of DWARF debug_pubnames section",
                        action="store_true")
    args = parser.parse_args()

    my_elf = elf.elf(args.elf_file)
    my_elf.read_file()

    if args.file_header or args.headers:
        my_elf.get_file_header()
        dump_file_header(my_elf.file_header)

    if args.program_headers or args.headers:
        my_elf.get_program_headers()
        dump_program_headers(my_elf.file_header, my_elf.program_headers)

    if args.section_headers or args.headers:
        my_elf.get_section_headers()
        dump_section_headers(my_elf.file_header, my_elf.section_headers)

    if args.syms:
        my_elf.get_symbols()
        dump_symbol_table(my_elf.symbols)

    if args.wa:
        my_elf.get_abbreviation_tables()
        dump_abbreviation_tables(my_elf.abbreviation_tables)

    if args.wr:
        my_elf.get_address_range_table()
        dump_address_range_table(my_elf.address_range_table)

    if args.wp:
        my_elf.get_name_lookup_table()
        dump_name_lookup_table(my_elf.name_lookup_table)

    # cus = my_elf.get_compilation_units(shs, ats)
    # my_elf.dump_compilation_units(cus)

if __name__ == "__main__":
    main()