from ctypes import sizeof
import elf_h as eh
import dwarf_h as dh
from tree import Node

class elf:
    def __init__(self, file) -> None:
        self.file = file

    def file_header_decorator(func):
        def wrapper(self):
            if not hasattr(self, 'file_header'):
                self.get_file_header()
            func(self)
        return wrapper
    
    def section_headers_decorator(func):
        def wrapper(self):
            if not hasattr(self, 'section_headers'):
                self.get_section_headers()
            func(self)
        return wrapper

    def read_file(self):
        with open(self.file, 'rb') as file:
            self.data = file.read()

    def get_string(self, base, offset):
        char = 0xff
        address = base + offset
        address_cpy = address
        while char != 0x00:
            char = self.data[address]
            address += 1

        return self.data[address_cpy : address - 1].decode('utf-8')

    def get_file_header(self):
        self.file_header = eh.FileHeader.from_buffer_copy(self.data[0:sizeof(eh.FileHeader)])

    @file_header_decorator
    def get_program_headers(self):
        self.program_headers = []
        for num in range(self.file_header.phnum):
            src_cpy = self.file_header.phoff + self.file_header.phentsize*num
            dst_cpy = self.file_header.phoff + self.file_header.phentsize*(num + 1)
            ph = eh.ProgramHeader.from_buffer_copy(self.data[src_cpy : dst_cpy])
            self.program_headers.append(ph)

    @file_header_decorator
    def get_section_headers(self):
        src_cpy = self.file_header.shoff + self.file_header.shentsize*self.file_header.shstrndx
        dst_cpy = self.file_header.shoff + self.file_header.shentsize*(self.file_header.shstrndx + 1)
        shstrtab = eh.SectionHeader.from_buffer_copy(self.data[src_cpy : dst_cpy])
        base = shstrtab.offset

        self.section_headers = {}
        for num in range(self.file_header.shnum):
            src_cpy = self.file_header.shoff + self.file_header.shentsize*num
            dst_cpy = self.file_header.shoff + self.file_header.shentsize*(num + 1)
            sh = eh.SectionHeader.from_buffer_copy(self.data[src_cpy : dst_cpy])
            name = self.get_string(base, sh.name)
            self.section_headers[num] = (name, sh)

    def get_section_from_name(self, name):
        for section in self.section_headers:
            sh_name, sh = self.section_headers[section]
            if sh_name == name:
                return sh_name, sh

    @section_headers_decorator
    def get_symbols(self):
        self.symbols = {}
        name1, symtab = self.get_section_from_name('.symtab')
        name2, strtab = self.get_section_from_name('.strtab')
        num_symbols = symtab.size // sizeof(eh.SymbolEntry)
        for num in range(num_symbols):
            src_cpy = symtab.offset + sizeof(eh.SymbolEntry) * num
            dst_cpy = symtab.offset + sizeof(eh.SymbolEntry) * (num + 1)
            symbol = eh.SymbolEntry.from_buffer_copy(self.data[src_cpy : dst_cpy])
            st_type = symbol.info & 0x0f
            st_bind = symbol.info >> 4

            name = ''
            if st_type != 3:
                name = self.get_string(strtab.offset, symbol.name)

            self.symbols[num] = (name, symbol)

    @section_headers_decorator
    def get_abbreviation_tables(self):
        self.abbreviation_tables = {}
        name, debug_abbrev = self.get_section_from_name('.debug_abbrev')
        offset = debug_abbrev.offset
        limit = debug_abbrev.offset + debug_abbrev.size

        num = 0
        while offset < limit:
            self.abbreviation_tables[num] = {}
            while True:
                code = self.data[offset]
                tag = self.data[offset + 1]
                has_children = self.data[offset + 2]
                if code == 0:
                    offset += 1
                    break
                self.abbreviation_tables[num][code] = [tag, has_children, []]
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
                    self.abbreviation_tables[num][code][2].append(attr)
                    if name == 0 and form == 0:
                        break
            num = offset - debug_abbrev.offset

    @section_headers_decorator
    def get_address_range_table(self):
        self.address_range_table = {}
        name, debug_aranges = self.get_section_from_name('.debug_aranges')
        offset = debug_aranges.offset
        limit = debug_aranges.offset + debug_aranges.size

        num = 0
        while offset < limit:
            arh = dh.AddressRangeHeader.from_buffer_copy(self.data[offset : offset + sizeof(dh.AddressRangeHeader)])
            self.address_range_table[num] = [arh, []]
            offset += sizeof(dh.AddressRangeHeader)
            while True:
                address = int.from_bytes(self.data[offset : offset + 4], 'little')
                length = int.from_bytes(self.data[offset + 4: offset + 8], 'little')
                value = (address, length)
                self.address_range_table[num][1].append(value)
                offset += 8
                if address == 0 and length == 0:
                    break
            num += 1

    @section_headers_decorator
    def get_name_lookup_table(self):
        self.name_lookup_table = {}
        name, debug_pubnames = self.get_section_from_name('.debug_pubnames')
        offset = debug_pubnames.offset
        limit = debug_pubnames.offset + debug_pubnames.size

        num = 0
        while offset < limit:
            nlh = dh.NameLookupHeader.from_buffer_copy(self.data[offset : offset + sizeof(dh.NameLookupHeader)])
            self.name_lookup_table[num] = [nlh, []]
            offset += sizeof(dh.NameLookupHeader)
            while True:
                off = int.from_bytes(self.data[offset : offset + 4], 'little')
                offset += 4
                if off == 0:
                    break
                name = self.get_string(offset, 0)
                value = (off, name)
                self.name_lookup_table[num][1].append(value)
                offset += len(name) + 1
            num += 1

    def get_die(self, offset, abbrev_table, debug_str_offset):
        abbrev_number = self.data[offset]
        offset += 1
        # TODO: abbrev_number is an LEB128 number
        if abbrev_number == 0:
            return Node(None), offset
        tag, has_children, attributes = abbrev_table[abbrev_number]
        attr_values = []
        for name, form in attributes:
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
                value = self.get_string(debug_str_offset, ptr)
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
            attr_value = (name, value)
            attr_values.append(attr_value)
        die = dh.DebugInformationEntry(offset, abbrev_number, tag, has_children, attr_values)
        return Node(die), offset

    def build_tree(self, offset, root, abbrev_table, debug_str_offset):
        while True:
            die, offset = self.get_die(offset, abbrev_table, debug_str_offset)
            if die.value is None:
                break
            root.add_child(die)
            if die.value.has_children:
                offset = self.build_tree(offset, die, abbrev_table, debug_str_offset)
        return offset

    def get_compilation_units(self, section_headers, abbreviation_tables):
        compilation_units = {}
        name, debug_info = self.get_section_from_name('.debug_info', section_headers)
        name, debug_str = self.get_section_from_name('.debug_str', section_headers)
        offset = debug_info.offset
        limit = debug_info.offset + debug_info.size

        prev_offset = 0
        while offset < limit:
            cu = dh.CompilationUnitHeader.from_buffer_copy(self.data[offset : offset + sizeof(dh.CompilationUnitHeader)])
            abbrev_table = abbreviation_tables[cu.abbrev_offset]
            offset += sizeof(dh.CompilationUnitHeader)
            root, offset = self.get_die(offset, abbrev_table, debug_str.offset)
            offset = self.build_tree(offset, root, abbrev_table, debug_str.offset)
            compilation_units[prev_offset] = [cu, root]
            prev_offset = offset - debug_info.offset

        return compilation_units

    def dump_dies(self, root, level):
        print(f"{level*'|   '}|- {root.value.__str__()}")
        for child in root.children:
            self.dump_dies(child, level+1)

    def dump_compilation_units(self, compilation_units):
        print('Contents of the .debug_info section:\n')
        at_pad = len(max(list(dh.DW_AT.values()), key=len))

        for num in compilation_units:
            print(f'  Compilation Unit @ offset {hex(num):}')
            cu, root = compilation_units[num]
            print(f'   Length:        {hex(cu.length)} (32-bit)')
            print(f'   Version:       {cu.version}')
            print(f'   Abbrev Offset: {hex(cu.abbrev_offset)}')
            print(f'   Pointer Size:  {cu.ptr_size}')
            level = 0
            self.dump_dies(root, level)
