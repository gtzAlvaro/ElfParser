import math
from enum import Enum
from ctypes import Union
from ctypes import sizeof
from ctypes import c_uint
from ctypes import c_ubyte
from ctypes import c_ushort
from tabulate import tabulate
from ctypes import c_ulonglong
from ctypes import LittleEndianStructure
import elf as elf

invalid_types = [
    0x01, # DW_TAG_array_type
    0x0f, # DW_TAG_pointer_type
    0x26, # DW_TAG_const_type
]

def var_repr(name, ref_die, is_const, is_pointer, is_array, array_size):
    var_repr = ''
    if is_const:
        var_repr += 'const '

    if ref_die.tag == 0x13: # DW_TAG_structure_type
        var_repr += 'struct '
    elif ref_die.tag == 0x17: # DW_TAG_union_type
        var_repr += 'union '
    
    if hasattr(ref_die, 'DW_AT_name'):
        var_repr += f'{ref_die.DW_AT_name} '

    if is_pointer:
        var_repr += '*'

    var_repr += name

    if is_array:
        for dimension in array_size:
            var_repr += f'[{dimension}]'

    return var_repr

def __str__(self):
    matrix = []
    for field in self._fields_:
        val = getattr(self, field[0])
        if type(val) is int:
            matrix.append([field[0], hex(val)])
        else:
            try:
                length = len(val)
                if type(val[0]) is int:
                    array = ' '.join(map(lambda x: f'{x:02x}', val))
                    matrix.append([field[0], array])
                else:
                    for element in val:
                        matrix.append([field[0], ''])
                        matrix.append(['', element.__str__()])
            except:
                matrix.append([field[0], ''])
                matrix.append(['', val.__str__()])
    return tabulate(matrix, tablefmt="plain")

def show(self):
    print(self.__str__())

class fw_vars:
    def __init__(self, name) -> None:
        self.name = name
        self.elf = elf.elf(name)
        self._debug_info = {}

    def get_node(self, attribute, value):
        for num in self.elf.compilation_units:
            cu, root = self.elf.compilation_units[num]
            node = root.search(attribute, value)
            if node is None:
                continue
            return node

    def get_by_name(self, name):
        node = self.get_node('DW_AT_name', name)
        return node 

    def get_by_ref(self, offset):
        node = self.get_node('offset', offset)
        return node

    def get_data_type(self, node, level):
        die = node.value
        name = getattr(die, 'DW_AT_name', 'no_name')
        if die.tag == 0x13: # DW_TAG_structure_type
            data_type, byte_size = self.struct(name, node, level)
        elif die.tag == 0x17: # DW_TAG_union_type
            data_type, byte_size = self.union(name, node, level)
        elif die.tag == 0x24: # DW_TAG_base_type
            if name == 'unsigned char' or name == '_Bool':
                data_type, byte_size  = c_ubyte, sizeof(c_ubyte)
            elif name == 'unsigned short':
                data_type, byte_size = c_ushort, sizeof(c_ushort)
            elif name == 'unsigned int':
                data_type, byte_size = c_uint, sizeof(c_uint)
            elif name == 'unsigned long long':
                data_type, byte_size = c_ulonglong, sizeof(c_ulonglong)
        elif die.tag == 0x04: # DW_TAG_enumeration_type
            # FIXME: not all enums are 1 byte
            data_type, byte_size  = c_ubyte, sizeof(c_ubyte)
        elif die.tag == 0x16: # DW_TAG_typedef
            data_type, byte_size = self.typedef(node, level)

        return data_type, byte_size

    def decode(self, name, die, level=0):
        is_const = False
        is_pointer = False
        is_array = False
        array_size = []

        # keep referencing, until node is not const, pointer or array
        ref_node = self.get_by_ref(die.DW_AT_type)
        ref_die = ref_node.value
        while ref_die.tag in invalid_types:
            if ref_die.tag == 0x26: # DW_TAG_const_type
                is_const = True

            if ref_die.tag == 0x0f: # DW_TAG_pointer_type
                is_pointer = True

            if ref_die.tag == 0x01: # DW_TAG_array_type
                is_array = True
                # array node has multiple children
                # each children represent the size of each dimension
                for child in reversed(ref_node.children):
                    child_die = child.value
                    if child_die.abbrev_number == 0:
                        continue
                    # special case for g_trace_buffer_ctx
                    # buffer field has no size
                    if not hasattr(child_die, 'DW_AT_count'):
                        array_size.append(1)
                    else:
                        array_size.append(child_die.DW_AT_count)

            ref_node = self.get_by_ref(ref_die.DW_AT_type)
            ref_die = ref_node.value

        line = var_repr(name, ref_die, is_const, is_pointer, is_array, array_size)
        line = f"{4*level*' '}{line}"
        return ref_node, line, array_size

    def typedef(self, node, level):
        die = node.value
        name = getattr(die, 'DW_AT_name', 'no_name')

        # get node type
        ref_node = self.get_by_ref(die.DW_AT_type)
        data_type, byte_size = self.get_data_type(ref_node, level+1)

        return data_type, byte_size

    def get_members(self, node, level):
        members = []

        for child in node.children:
            child_die = child.value
            if child_die.abbrev_number == 0:
                continue

            if child_die.tag != 0x0d: # DW_TAG_member
                continue

            name = getattr(child_die, 'DW_AT_name', 'no_name')
            ref_node, line, array_size = self.decode(name, child_die, level+1)
            ref_die = ref_node.value
            if hasattr(child_die, 'DW_AT_bit_size') and hasattr(child_die, 'DW_AT_bit_offset'):
                start = child_die.DW_AT_bit_offset
                end = start + child_die.DW_AT_bit_size - 1
            else:
                start = child_die.DW_AT_data_member_location
                end = '?'
                if hasattr(ref_die, 'DW_AT_byte_size'):
                    end = start + ref_die.DW_AT_byte_size
                else:
                    type_node = self.get_by_ref(ref_die.DW_AT_type)
                    if hasattr(type_node.value, 'DW_AT_byte_size'):
                        end = start + type_node.value.DW_AT_byte_size
            print(line, f'({start}:{end})')

            data_byte, byte_size = self.get_data_type(ref_node, level+1)

            if hasattr(child_die, 'DW_AT_bit_size') and hasattr(child_die, 'DW_AT_bit_offset'):
                members.append((name, data_byte, child_die.DW_AT_bit_size))
            else:
                if len(array_size) != 0:
                    if len(array_size) == 1:
                        members.append((name, data_byte*array_size[0]))
                    elif len(array_size) == 2:
                        members.append((name, data_byte*array_size[0]*array_size[1]))
                else:
                    members.append((name, data_byte))
        return members

    def union(self, type_name, node, level):
        members = self.get_members(node, level)
        byte_size = node.value.DW_AT_byte_size
        return type(
            type_name,
            (Union,),
            {
                '_pack_': 4,
                '_fields_': members,
                '__str__': __str__,
                'show': show
            }
        ), byte_size

    def struct(self, type_name, node, level):
        members = self.get_members(node, level)
        byte_size = node.value.DW_AT_byte_size
        return type(
            type_name,
            (LittleEndianStructure,),
            {
                '_pack_': 4,
                '_fields_': members,
                '__str__': __str__,
                'show': show
            }
        ), byte_size

    def whatis(self, name):
        node = self.get_by_name(name)
        die = node.value
        if die.tag != 0x34: # DW_TAG_variable
            self.log.warning('only variable names are acepted')
            return 1, None

        ref_node, line, array_size = self.decode(name, die)
        return ref_node.value.DW_AT_name

    def create(self, name, mybytes=None):
        node = self.get_by_name(name)
        data_type, byte_size = self.get_data_type(node, 0)
        self._debug_info[name] = [
            sizeof(data_type),
            byte_size
        ]

        if mybytes is not None:
            return data_type.from_buffer_copy(mybytes)
        return data_type()

    def get_enum(self, name):
        node = self.get_by_name(name)
        die = node.value

        if die.tag != 0x04: # DW_TAG_enumeration_type
            self.log.warning(f'only enums are allowed: {die.tag}')
            return None

        enumerators = []
        for child in node.children:
            child_die = child.value

            if child_die.abbrev_number == 0:
                continue

            if child_die.tag != 0x28: # DW_TAG_enumerator
                continue

            enumerator = (child_die.DW_AT_name, child_die.DW_AT_const_value)
            enumerators.append(enumerator)
    
        return Enum(name, enumerators)

    def dump_global_vars(self):
        for number in self.elf.symbols:
            name, symbol = self.elf.symbols[number]

            st_type = symbol.info & 0x0f
            st_bind = symbol.info >> 4
            if st_type != 1: # OBJECT
                continue

            if st_bind != 1: # GLOBAL
                continue

            # only global variables that start with g_
            if name[0:2] != 'g_':
                continue

            data_type = self.whatis(name)
            myvar = self.create(data_type)

    def debug(self):
        matrix = []
        for name, data in self._debug_info.items():
            matrix.append([name, data[0], data[1]])

        table = tabulate(matrix, headers=['name', 'size in bytes', 'actual size in bytes'])
        print(table)