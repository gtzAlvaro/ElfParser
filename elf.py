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
        print()

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
        print(f'Contents of the .debug_abbrev section:\n')
        at_pad = len(max(list(h.DW_AT.values()), key=len))
        tag_pad = len(max(list(h.DW_TAG.values()), key=len))
        for num in abbreviation_tables:
            print(f'  Number Tag ({hex(num)})')
            abbreviation_table = abbreviation_tables[num]
            for code in abbreviation_table:
                tag, has_children, attrs = abbreviation_table[code]
                print(f"   {str(code).ljust(7, ' ')}{h.DW_TAG[tag].ljust(tag_pad, ' ')}{h.DW_CHILDREN[has_children]}")
                for name, form in attrs:
                    print(f"    {h.DW_AT[name].ljust(at_pad, ' ')}{h.DW_FORM[form]}")
        print()

    def get_address_range_table(self, section_headers):
        address_range_table = {}
        name, debug_aranges = self.get_section_from_name('.debug_aranges', section_headers)
        offset = debug_aranges.offset
        limit = debug_aranges.offset + debug_aranges.size

        num = 0
        while offset < limit:
            arh = h.AddressRangeHeader.from_buffer_copy(self.data[offset : offset + sizeof(h.AddressRangeHeader)])
            address_range_table[num] = [arh, []]
            offset += sizeof(h.AddressRangeHeader)
            while True:
                address = int.from_bytes(self.data[offset : offset + 4], 'little')
                length = int.from_bytes(self.data[offset + 4: offset + 8], 'little')
                value = (address, length)
                address_range_table[num][1].append(value)
                offset += 8
                if address == 0 and length == 0:
                    break
            num += 1
        
        return address_range_table
    
    def dump_address_range_table(self, address_range_table):
        print('Contents of the .debug_aranges section:\n')
        for num in address_range_table:
            arh, values = address_range_table[num]
            print(f'  Legnth:                   {arh.length}')
            print(f'  Version:                  {arh.version}')
            print(f'  Offset into .debug_info:  {hex(arh.info_offset)}')
            print(f'  Pointer size:             {arh.ptr_size}')
            print(f'  Segment size:             {arh.seg_size}\n')
            print(f'    Address    Length')
            for address, length in values:
                print(f'    {address:08x} {length:08x}')
        print()

    def get_name_lookup_table(self, section_headers):
        name_lookup_table = {}
        name, debug_pubnames = self.get_section_from_name('.debug_pubnames', section_headers)
        offset = debug_pubnames.offset
        limit = debug_pubnames.offset + debug_pubnames.size

        num = 0
        while offset < limit:
            nlh = h.NameLookupHeader.from_buffer_copy(self.data[offset : offset + sizeof(h.NameLookupHeader)])
            name_lookup_table[num] = [nlh, []]
            offset += sizeof(h.NameLookupHeader)
            while True:
                off = int.from_bytes(self.data[offset : offset + 4], 'little')
                offset += 4
                if off == 0:
                    break
                name = self.get_string(offset, 0)
                value = (off, name)
                name_lookup_table[num][1].append(value)
                offset += len(name) + 1
            num += 1

        return name_lookup_table
    
    def dump_name_lookup_table(self, name_lookup_table):
        print('Contents of the .debug_pubnames section:\n')
        for num in name_lookup_table:
            nlh, values = name_lookup_table[num]
            print(f'  Legnth:                              {nlh.length}')
            print(f'  Version:                             {nlh.version}')
            print(f'  Offset into .debug_info section:     {hex(nlh.info_offset)}')
            print(f'  Size of area in .debug_info section: {nlh.info_size}\n')
            print(f'    Offset   Name')
            for offset, name in values:
                offset_str = f'{offset:x}'
                print(f"    {offset_str.ljust(9, ' ')}{name}")
        print()

    def get_compilation_units(self, section_headers, abbreviation_tables):
        compilation_units = {}
        name, debug_info = self.get_section_from_name('.debug_info', section_headers)
        name, debug_str = self.get_section_from_name('.debug_str', section_headers)
        offset = debug_info.offset
        limit = debug_info.offset + debug_info.size

        prev_size = 0
        while offset < limit:
            cu = h.CompilationUnitHeader.from_buffer_copy(self.data[offset : offset + sizeof(h.CompilationUnitHeader)])
            # print(hex(cu.length), cu.version, hex(cu.abbrev_offset))
            abbrev_table = abbreviation_tables[cu.abbrev_offset]
            offset += sizeof(h.CompilationUnitHeader)
            dies = []
            while True:
                if (offset - debug_info.offset) - prev_size >= (cu.length + 4):
                    # print('quitting dies loop')
                    break
                abbrev_number = self.data[offset]
                offset += 1
                # TODO: abbrev_number is an LEB128 number
                if abbrev_number == 0:
                    # print('found abbrev number 0')
                    dies.append([abbrev_number, None, []])
                    continue
                tag, has_children, attributes = abbrev_table[abbrev_number]
                # print(hex(offset - debug_info.offset - 1), abbrev_number, h.DW_TAG[tag])
                attr_values = []
                for name, form in attributes:
                    relative = hex(offset - debug_info.offset)
                    if form == 0x08: # DW_FORM_string
                        value = self.get_string(offset, 0)
                        offset += len(value) + 1
                    elif form == 0x05: # DW_FORM_data2
                        value = int.from_bytes(self.data[offset : offset + 2], 'little')
                        offset += 2
                    elif form in [0x06, 0x01, 0x13] : # DW_FORM_data4, DW_FORM_addr, DW_FORM_ref4
                        value = int.from_bytes(self.data[offset : offset + 4], 'little')
                        offset += 4
                    elif form in [0x0c, 0x0b]: # DW_FORM_flag, DW_FORM_data1
                        value = self.data[offset]
                        offset += 1
                    elif form == 0x0e: # DW_FORM_strp
                        ptr = int.from_bytes(self.data[offset : offset + 4], 'little')
                        value = self.get_string(debug_str.offset, ptr)
                        offset += 4
                    elif form == 0x0a: # DW_FORM_block1
                        length = self.data[offset]
                        offset += 1
                        value = self.data[offset : offset + length]
                        offset += length
                    elif form == 0x0f: # DW_FORM_udata
                        value = 0
                        shift = 0
                        while True:
                            mbyte = self.data[offset]
                            value |= (mbyte & 0x7f) << shift
                            offset += 1
                            if (mbyte & 0x80) >> 7 == 0:
                                break
                            shift += 7
                    elif name == 0 and form == 0:
                        continue
                    else:
                        print('ERROR: not supported')
                        return
                    # print(relative, h.DW_AT[name], value)
                    attr_value = (name, value)
                    attr_values.append(attr_value)
                dies.append([abbrev_number, tag, attr_values])
            # print(hex(offset - debug_info.offset), hex(prev_size))
            compilation_units[prev_size] = [cu, dies]
            prev_size += cu.length + 4
            # time.sleep(3)

        return compilation_units

    def dump_compilation_units(self, compilation_units):
        print('Contents of the .debug_info section:\n')
        at_pad = len(max(list(h.DW_AT.values()), key=len))

        for num in compilation_units:
            print(f'  Compilation Unit @ offset {hex(num):}')
            cu, dies = compilation_units[num]
            print(f'   Length:        {hex(cu.length)} (32-bit)')
            print(f'   Version:       {cu.version}')
            print(f'   Abbrev Offset: {hex(cu.abbrev_offset)}')
            print(f'   Pointer Size:  {cu.ptr_size}')
            for abbrev_number, tag, attr_values in dies:
                if abbrev_number == 0:
                    print(f'             Abbrev number: {abbrev_number}')
                else:
                    print(f'             Abbrev number: {abbrev_number} ({h.DW_TAG[tag]})')
                for name, value in attr_values:
                    print(f"              {h.DW_AT[name].ljust(at_pad, ' ')} : {value}")

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

    art = my_elf.get_address_range_table(shs)
    my_elf.dump_address_range_table(art)

    nlt = my_elf.get_name_lookup_table(shs)
    my_elf.dump_name_lookup_table(nlt)

    cus = my_elf.get_compilation_units(shs, ats)
    my_elf.dump_compilation_units(cus)

    start = time.time()
    for num in cus:
        cu, dies = cus[num]
        for abbrev_number, tag, attr_values in dies:
            for name, value in attr_values:
                if name == 0x03 and value == args[2]: # DW_AT_name
                    print(f'found: {name} {value} in compialtion unit @ offset {hex(num)}')
                    end = time.time()
                    print(f'time: {end - start}')
                    return 0

if __name__ == "__main__":
    main(sys.argv)