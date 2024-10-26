import elf as elf
from ctypes import Union
from ctypes import c_uint
from ctypes import c_ubyte
from ctypes import c_ushort
from ctypes import c_ulonglong
from ctypes import LittleEndianStructure

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

class fw_vars:
    def __init__(self, elf) -> None:
        self.elf = elf
        self.vars = []

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

    def struct(self, typename, node, level, union=False):
        fields = []

        for child in node.children:
            child_die = child.value
            if child_die.abbrev_number == 0:
                continue

            if child_die.tag != 0x0d: # DW_TAG_member
                continue

            name = child_die.attributes.get(0x03)
            name = getattr(child_die, 'DW_AT_name', 'no_name')
            ref_node, line, array_size = self.decode(name, child_die, level)
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

            if ref_die.tag == 0x13: # DW_TAG_structure_type
                datatype = self.struct(name, ref_node, level+1)
            elif ref_die.tag == 0x16: # DW_TAG_typedef
                datatype = self.typedef(ref_node, level+1)
            elif ref_die.tag == 0x17: # DW_TAG_union_type
                datatype = self.struct(name, ref_node, level+1)
            elif ref_die.tag == 0x24: # DW_TAG_base_type
                if ref_die.DW_AT_name == '_Bool':
                    datatype = c_ubyte
            elif ref_die.tag == 0x04: # DW_TAG_enumeration_type
                # TODO: check for DW_AT_byte_size and return according type
                datatype = c_ubyte

            if hasattr(child_die, 'DW_AT_bit_size') and hasattr(child_die, 'DW_AT_bit_offset'):
                fields.append((name, datatype, child_die.DW_AT_bit_size))
            else:
                if len(array_size) != 0:
                    if len(array_size) == 1:
                        fields.append((name, datatype*array_size[0]))
                    elif len(array_size) == 2:
                        fields.append((name, datatype*array_size[0]*array_size[1]))
                else:
                    fields.append((name, datatype))

        ctype = LittleEndianStructure
        if union:
            ctype = Union
        return type(typename, (ctype,), {'_pack_': 4, '_fields_': fields})

    def typedef(self, node, level):
        die = node.value
        name = getattr(die, 'DW_AT_name', 'no_name')

        # get node type
        ref_node = self.get_by_ref(die.DW_AT_type)
        ref_die = ref_node.value
        if ref_die.tag == 0x13: # DW_TAG_structure_type
            datatype = self.struct(name, ref_node, level)
        elif ref_die.tag == 0x17: # DW_TAG_union_type
            datatype = self.struct(name, ref_node, level+1, True)
        elif ref_die.tag == 0x24: # DW_TAG_base_type
            if ref_die.DW_AT_name == 'unsigned int':
                datatype = c_uint
            elif ref_die.DW_AT_name == 'unsigned char':
                datatype = c_ubyte
            elif ref_die.DW_AT_name == 'unsigned short':
                datatype = c_ushort
            elif ref_die.DW_AT_name == 'unsigned long long':
                datatype = c_ulonglong
        elif ref_die.tag == 0x04: # DW_TAG_enumeration_type
            datatype = c_ubyte
        elif ref_die.tag == 0x16: # DW_TAG_typedef
            datatype = self.typedef(ref_node, level+1)

        return datatype

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

    def dump(self):
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

            node = self.get_by_name(name)
            die = node.value
            ref_node, line, array_size = self.decode(name, die)
            ref_die = ref_node.value
            address = int.from_bytes(die.DW_AT_location[1:], 'little')
            if not hasattr(ref_die, 'DW_AT_byte_size'):
                # look into the type from ref_node for a dw_at_byte_size
                type_node = self.get_by_ref(ref_die.DW_AT_type)
                type_die = type_node.value
                if not hasattr(type_die, 'DW_AT_byte_size'):
                    byte_size = None
                else:
                    byte_size = type_die.DW_AT_byte_size
            else:
                byte_size = ref_die.DW_AT_byte_size
            print(hex(address), byte_size, line)

            if ref_die.tag == 0x13: # DW_TAG_structure_type
                mytype = self.struct(ref_die.DW_AT_name, ref_node, 1)
            elif ref_die.tag == 0x16: # DW_TAG_typedef
                mytype = self.typedef(ref_node, 1)
            
            self.vars.append(name)
            setattr(self, name, mytype())
