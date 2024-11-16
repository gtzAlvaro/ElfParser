from ctypes import sizeof
import elf_h as eh
import tree as tree
import dwarf_h as dh

class elf:
    def __init__(self, name, file=None) -> None:
        self.name = name
        self.file = file

    def read_file_decorator(func):
        def wrapper(self):
            if not hasattr(self, 'data'):
                self.read_file()
            func(self)
        return wrapper
    
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
    
    def abbreviation_tables_decorator(func):
        def wrapper(self):
            if not hasattr(self, 'abbreviation_tables'):
                self.get_abbreviation_tables()
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

    def unsigned_leb128_decoder(self, offset):
        result = 0
        shift = 0
        while True:
            mbyte = self.data[offset]
            result |= (mbyte & 0x7f) << shift
            offset += 1
            if (mbyte & 0x80) >> 7 == 0:
                break
            shift += 7
        return offset, result

    def signed_leb128_decoder(self, offset):
        result = 0
        shift = 0
        while True:
            mbyte = self.data[offset]
            offset += 1
            result |= (mbyte & 0x7f) << shift
            shift += 7
            if not (mbyte & 0x80):
                break

        if mbyte & 0x40:
            result |= -(1 << shift)

        return offset, result

    @read_file_decorator
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

    def get_symbol(self, name):
        for num in self.symbols:
            symbol_name, symbol = self.symbols[num]
            if symbol_name == name:
                return symbol_name, symbol

        return None, None

    @section_headers_decorator
    def get_symbols(self):
        self.symbols = eh.Symbols()
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

            self.symbols.add_symbol(num, name, symbol)

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

    @section_headers_decorator
    def get_debug_lines(self):
        self.debug_lines = {}
        name, debug_line = self.get_section_from_name('.debug_line')
        offset = debug_line.offset
        limit = debug_line.offset + debug_line.size

        base_offset = 0
        while offset < limit:
            statement = dh.StatementProgram()
            statement.prologue = dh.StatementProgramPrologue.from_buffer_copy(self.data[offset : offset + sizeof(dh.StatementProgramPrologue)])

            base = offset + sizeof(dh.StatementProgramPrologue)
            statement.opcodes = []
            for num in range(statement.prologue.opcode_base - 1):
                opcode = self.data[base]
                statement.opcodes.append(opcode)
                base += 1

            statement.directory_table_offset = base - debug_line.offset
            statement.include_directories = []
            while True:
                dir_name = self.get_string(debug_line.offset, base - debug_line.offset)
                statement.include_directories.append(dir_name)
                base += len(dir_name) + 1
                if self.data[base] == 0:
                    base += 1
                    break

            statement.file_names = []
            statement.file_name_table_offset = base - debug_line.offset
            while True:
                myfile = dh.FileName()
                myfile.name = self.get_string(debug_line.offset, base - debug_line.offset)
                base += len(myfile.name) + 1
                myfile.dir = self.data[base]
                base += 1
                myfile.time = self.data[base]
                base += 1
                myfile.size = self.data[base]
                base += 1

                statement.file_names.append(myfile)
                if self.data[base] == 0:
                    base += 1
                    break

            myregs = dh.StateMachineRegisters()
            statement.matrix = []
            while base < (debug_line.offset + base_offset + statement.prologue.total_length + 4):
                if self.data[base] == 0x01: # DW_LNS_copy
                    base += 1
                    row = [
                        hex(base - debug_line.offset),
                        hex(myregs.address),
                        myregs.file,
                        myregs.line,
                        myregs.column,
                        myregs.is_stmt,
                        myregs.basic_block,
                        myregs.end_sequence
                    ]
                    statement.matrix.append(row)
                elif self.data[base] == 0x02: # DWS_LNS_advance_pc
                    base += 1
                    base, value = self.unsigned_leb128_decoder(base)
                    myregs.address += statement.prologue.minimum_instruction_length * value
                elif self.data[base] == 0x03: # DW_LNS_advance_line
                    base += 1
                    base, value = self.signed_leb128_decoder(base)
                    myregs.line += value
                elif self.data[base] == 0x04: # DW_LNS_set_file
                    base += 1
                    base, value = self.unsigned_leb128_decoder(base)
                    myregs.file = value
                elif self.data[base] == 0x05: # DWS_LNS_set_column
                    base += 1
                    base, value = self.unsigned_leb128_decoder(base)
                    myregs.column = value
                elif self.data[base] == 0x00: # extended opcodes
                    base += 1
                    base, size = self.unsigned_leb128_decoder(base)
                    if self.data[base] == 0x01: # DW_LNE_end_sequence
                        base += 1
                        myregs.end_sequence = True
                        row = [
                            hex(base - debug_line.offset),
                            hex(myregs.address),
                            myregs.file,
                            myregs.line,
                            myregs.column,
                            myregs.is_stmt,
                            myregs.basic_block,
                            myregs.end_sequence
                        ]
                        statement.matrix.append(row)
                        myregs = dh.StateMachineRegisters()
                    elif self.data[base] == 0x02: # DW_LNE_set_address
                        base += 1
                        address = int.from_bytes(self.data[base : base + size - 1], 'little')
                        base += size - 1
                        myregs.address = address
                else: # special opcode
                    adjusted_opcode = self.data[base] - statement.prologue.opcode_base
                    base += 1
                    address_advance = adjusted_opcode // statement.prologue.line_range
                    line_advance = statement.prologue.line_base + (adjusted_opcode % statement.prologue.line_range)
                    myregs.line += line_advance
                    myregs.address += statement.prologue.minimum_instruction_length * address_advance
                    row = [
                        hex(base - debug_line.offset),
                        hex(myregs.address),
                        myregs.file,
                        myregs.line,
                        myregs.column,
                        myregs.is_stmt,
                        myregs.basic_block,
                        myregs.end_sequence
                    ]
                    statement.matrix.append(row)
                    myregs.basic_block = False

            self.debug_lines[base_offset] = statement
            offset += statement.prologue.total_length + 4
            base_offset += statement.prologue.total_length + 4

    def get_die(self, level, offset, abbrev_table, prev_offset, debug_info_offset, debug_str_offset):
        die = dh.DebugInformationEntry(level, offset - debug_info_offset, self.data[offset])
        offset += 1
        # TODO: abbrev_number is an LEB128 number
        if die.abbrev_number == 0:
            return die, offset
        die.tag, die.has_children, attributes = abbrev_table[die.abbrev_number]
        for name, form in attributes:
            if name == 0 and form == 0:
                continue

            attr_name = dh.DW_AT[name]
            attribute = dh.Attribute(offset - debug_info_offset, attr_name, form)
            if form == 0x08: # DW_FORM_string
                value = self.get_string(offset, 0)
                offset += len(value) + 1
            elif form == 0x05: # DW_FORM_data2
                value = int.from_bytes(self.data[offset : offset + 2], 'little')
                offset += 2
            elif form in [0x06, 0x01, 0x13] : # DW_FORM_data4, DW_FORM_addr, DW_FORM_ref4
                value = int.from_bytes(self.data[offset : offset + 4], 'little')
                offset += 4
                if form == 0x13: # DW_FORM_ref4
                    value = prev_offset + value
            elif form in [0x0c, 0x0b]: # DW_FORM_flag, DW_FORM_data1
                value = self.data[offset]
                offset += 1
            elif form == 0x0e: # DW_FORM_strp
                ptr = int.from_bytes(self.data[offset : offset + 4], 'little')
                attribute.offset_str = ptr
                value = self.get_string(debug_str_offset, ptr)
                offset += 4
            elif form == 0x0a: # DW_FORM_block1
                length = self.data[offset]
                offset += 1
                value = self.data[offset : offset + length]
                offset += length
            elif form == 0x0f: # DW_FORM_udata
                offset, value = self.unsigned_leb128_decoder(offset)
            else:
                print('ERROR: not supported')
                return
            attribute.value = value
            die.set_attr(attr_name, attribute)
        return die, offset

    def build_tree(self, level, offset, root, abbrev_table, prev_offset, debug_info_offset, debug_str_offset):
        while True:
            die, offset = self.get_die(level, offset, abbrev_table, prev_offset, debug_info_offset, debug_str_offset)
            node = tree.Node(die)
            root.add_child(node)
            if die.abbrev_number == 0:
                break
            if die.has_children:
                offset = self.build_tree(level + 1, offset, node, abbrev_table, prev_offset, debug_info_offset, debug_str_offset)
        return offset

    @section_headers_decorator
    @abbreviation_tables_decorator
    def get_compilation_units(self):
        self.compilation_units = {}
        name, debug_info = self.get_section_from_name('.debug_info')
        name, debug_str = self.get_section_from_name('.debug_str')
        offset = debug_info.offset
        limit = debug_info.offset + debug_info.size

        prev_offset = 0
        while offset < limit:
            cu = dh.CompilationUnitHeader.from_buffer_copy(self.data[offset : offset + sizeof(dh.CompilationUnitHeader)])
            abbrev_table = self.abbreviation_tables[cu.abbrev_offset]
            offset += sizeof(dh.CompilationUnitHeader)
            die, offset = self.get_die(0, offset, abbrev_table, prev_offset, debug_info.offset, debug_str.offset)
            root = tree.Node(die)
            offset = self.build_tree(1, offset, root, abbrev_table, prev_offset, debug_info.offset, debug_str.offset)
            self.compilation_units[prev_offset] = [cu, root]
            prev_offset = offset - debug_info.offset
