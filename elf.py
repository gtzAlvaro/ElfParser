import sys
import time
from ctypes import sizeof
from tabulate import tabulate
import elf_h as h

class elf:
    def __init__(self, file) -> None:
        self.file = file

    def read_file(self):
        f = open(self.file, 'rb')
        self.data = f.read()
        f.close()

    def get_string(self, base, offset):
        char = 0xff
        address = base + offset
        address_cpy = address
        while char != 0x00:
            char = self.data[address]
            address += 1

        return self.data[address_cpy : address - 1].decode('utf-8')

    def get_file_header(self):
        return h.FileHeader.from_buffer_copy(self.data[0:sizeof(h.FileHeader)])

    def dump_file_header(self, file_header):
        print('ELF Header:')
        matrix = [
            ['Magic:', self.data[0:16]],
            ['Class:', file_header.ei_class],
            ['Data:', file_header.ei_class],
            ['Version:', file_header.version],
            ['OS/ABI:', file_header.osabi],
            ['ABI Version:', file_header.abiversion],
            ['Type:', file_header.type],
            ['Machine:', file_header.machine],
            ['Version:', hex(file_header.e_version)],
            ['Entry point address:', hex(file_header.entry)],
            ['Start of program headers:', file_header.phoff],
            ['Start of section headers:', file_header.shoff],
            ['Flags:', hex(file_header.flags)],
            ['Size of this header:', file_header.ehsize],
            ['Size of program headers:', file_header.phentsize],
            ['Number of program headers:', file_header.phnum],
            ['Size of section headers:', file_header.shentsize],
            ['Number of section headers:', file_header.shnum],
            ['Section header string table index:', file_header.shstrndx],
        ]
        print(tabulate(matrix, tablefmt="plain"))
        print()

    def get_program_headers(self, file_header):
        program_headers = []
        for num in range(file_header.phnum):
            src_cpy = file_header.phoff + file_header.phentsize*num
            dst_cpy = file_header.phoff + file_header.phentsize*(num + 1)
            ph = h.ProgramHeader.from_buffer_copy(self.data[src_cpy : dst_cpy])
            program_headers.append(ph)

        return program_headers

    def dump_program_headers(self, program_headers):
        matrix = []
        for ph in program_headers:
            matrix.append([ph.type, hex(ph.offset), hex(ph.vaddr), hex(ph.paddr), hex(ph.filesz), hex(ph.memsz), ph.flags, ph.align])
        print('Program Headers:')
        headers = ['type', 'offset', 'VirtAddr', 'PhysAddr', 'FileSiz', 'MemSiz', 'Flg', 'Align']
        print(tabulate(matrix, headers=headers, tablefmt="plain"))
        print()

    def get_section_headers(self, file_header):
        src_cpy = file_header.shoff + file_header.shentsize*file_header.shstrndx
        dst_cpy = file_header.shoff + file_header.shentsize*(file_header.shstrndx + 1)
        shstrtab = h.SectionHeader.from_buffer_copy(self.data[src_cpy : dst_cpy])
        base = shstrtab.offset

        section_headers = {}
        for num in range(file_header.shnum):
            src_cpy = file_header.shoff + file_header.shentsize*num
            dst_cpy = file_header.shoff + file_header.shentsize*(num + 1)
            sh = h.SectionHeader.from_buffer_copy(self.data[src_cpy : dst_cpy])
            name = self.get_string(base, sh.name)
            section_headers[num] = (name, sh)

        return section_headers

    def get_section_from_name(self, name, section_headers):
        for section in section_headers:
            sh_name, sh = section_headers[section]
            if sh_name == name:
                return sh_name, sh

    def dump_section_headers(self, section_headers):        
        matrix = []
        for section in section_headers:
            name, sh = section_headers[section]
            matrix.append([section, name, sh.type, hex(sh.addr), hex(sh.offset), hex(sh.size), hex(sh.entsize), sh.flags, sh.link, sh.info, sh.addralign])
            section += 1
        print('Section Headers:')
        headers = ['Nr', 'Name', 'Type', 'Addr', 'off', 'Size', 'ES', 'Flg', 'Lk', 'Inf', 'Al']
        print(tabulate(matrix, headers=headers, tablefmt="plain"))
        print()

    def get_symbols(self, section_headers):
        symbols = {}
        name1, symtab = self.get_section_from_name('.symtab', section_headers)
        name2, strtab = self.get_section_from_name('.strtab', section_headers)
        num_symbols = symtab.size // sizeof(h.SymbolEntry)
        for num in range(num_symbols):
            src_cpy = symtab.offset + sizeof(h.SymbolEntry) * num
            dst_cpy = symtab.offset + sizeof(h.SymbolEntry) * (num + 1)
            symbol = h.SymbolEntry.from_buffer_copy(self.data[src_cpy : dst_cpy])
            st_type = symbol.info & 0x0f
            st_bind = symbol.info >> 4

            name = ''
            if st_type != 3:
                name = self.get_string(strtab.offset, symbol.name)

            symbols[num] = (name, symbol)
        
        return symbols

    def dump_symbol_table(self, symbols):
        matrix = []
        for num in symbols:
            name, symbol = symbols[num]
            st_type = symbol.info & 0x0f
            st_bind = symbol.info >> 4
            matrix.append([num, hex(symbol.value), symbol.size, st_type, st_bind, symbol.other, symbol.shndx, name])
        print(f'Symbol table \'.symtab\' contains {len(symbols)} entries:')
        headers = ['Num', 'Value', 'Size', 'Type', 'Bind', 'Vis', 'Ndx', 'Name']
        print(tabulate(matrix, headers=headers, tablefmt="plain"))

    def get_abbreviation_tables(self, section_headers):
        abbreviation_tables = {}
        name, debug_abbrev = self.get_section_from_name('.debug_abbrev', section_headers)
        offset = debug_abbrev.offset
        limit = debug_abbrev.offset + debug_abbrev.size

        num = 0
        while offset < limit:
            abbreviation_tables[num] = {}
            while True:
                code = self.data[offset]
                tag = self.data[offset + 1]
                has_children = self.data[offset + 2]
                if code == 0:
                    offset += 1
                    break
                abbreviation_tables[num][code] = [tag, has_children, []]
                offset += 3
                while True:
                    name = self.data[offset]
                    form = self.data[offset + 1]
                    offset += 2
                    # TODO: LBE128 encoding not handled properly in TAG and AT
                    if name > 0x7f:
                        name = self.data[offset - 2]
                        form = self.data[offset]
                        offset += 1
                    attr = (name, form)
                    abbreviation_tables[num][code][2].append(attr)
                    if name == 0 and form == 0:
                        break
            num = offset - debug_abbrev.offset
        
        return abbreviation_tables

    def dump_abbreviation_tables(self, abbreviation_tables):
        for num in abbreviation_tables:
            print(f'  Number Tag ({hex(num)})')
            abbreviation_table = abbreviation_tables[num]
            for code in abbreviation_table:
                tag, has_children, attrs = abbreviation_table[code]
                print(f'   {code}      {h.DW_TAG[tag]}    {h.DW_CHILDREN[has_children]}')
                matrix = []
                for name, form in attrs:
                    matrix.append([h.DW_AT[name], h.DW_FORM[form]])
                print(tabulate(matrix, tablefmt="plain"))

    def get_compilation_units(self, section_headers):
        name, debug_info = self.get_section_from_name('.debug_info', section_headers)
        cu_size = sizeof(h.CompilationUnitHeader)

        num = 0
        compilation_units = {}
        offset = debug_info.offset
        limit = debug_info.offset + debug_info.size
        while offset < limit:
            cu = h.CompilationUnitHeader.from_buffer_copy(self.data[offset : offset + cu_size])
            compilation_units[num] = cu
            num += 1
            offset += cu.length + 4

        return compilation_units

    def dump_compilation_units(self, compilation_units):
        offset = 0
        for num in compilation_units:
            matrix = []
            cu = compilation_units[num]
            matrix.append(['Length:', hex(cu.length)])
            matrix.append(['Version:', cu.version])
            matrix.append(['Abbrev Offset:', hex(cu.abbrev_offset)])
            matrix.append(['Pointer Size:', cu.ptr_size])
            print(f'  Compilation Unit @ offset {hex(offset):}')
            print(tabulate(matrix, tablefmt="plain"))
            offset += cu.length + 4

def main(args):
    elf_path = args[1]
    my_elf = elf(elf_path)
    my_elf.read_file()
    fh = my_elf.get_file_header()
    my_elf.dump_file_header(fh)

    phs = my_elf.get_program_headers(fh)
    my_elf.dump_program_headers(phs)

    shs = my_elf.get_section_headers(fh)
    my_elf.dump_section_headers(shs)

    symbols = my_elf.get_symbols(shs)
    my_elf.dump_symbol_table(symbols)

    ats = my_elf.get_abbreviation_tables(shs)
    my_elf.dump_abbreviation_tables(ats)

    cus = my_elf.get_compilation_units(shs)
    my_elf.dump_compilation_units(cus)

if __name__ == "__main__":
    main(sys.argv)