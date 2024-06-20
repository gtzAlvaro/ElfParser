import argparse
import elf as elf

def show_union(root, node):
    print('union {')
    for child in node.children:
        if child.value.abbrev_number == 0:
            continue

        if child.value.tag != 0x0d: # DW_TAG_member
            continue

        handler = handlers[child.value.tag]
        handler(root, child)
    print('}')

def show_pointer(root, node):
    pass

def show_array(root, node):
    dw_at_type = node.value.attributes[0x49].value # DW_AT_type
    ref_node = root.search('offset', dw_at_type)
    print(ref_node.value.attributes[0x03].value) # DW_AT_name

def show_typedef(root, node):
    dw_at_name = node.value.attributes[0x03].value # DW_AT_name
    dw_at_type = node.value.attributes[0x49].value # DW_AT_type
    ref_node = root.search('offset', dw_at_type)
    handler = handlers[ref_node.value.tag]
    handler(root, ref_node)

def show_enum(root, node):
    pass

def show_member(root, node):
    dw_at_name = ''
    if 0x03 in node.value.attributes:
        dw_at_name = node.value.attributes[0x03].value # DW_AT_name
    dw_at_type = node.value.attributes[0x49].value # DW_AT_type
    ref_node = root.search('offset', dw_at_type)
    if ref_node.value.tag in [0x01, 0x0f]: # DW_TAG_array_type, DW_TAG_pointer_type
        dw_at_type = ref_node.value.attributes[0x49].value # DW_AT_type
        ref2_node = root.search('offset', dw_at_type)
        dw_at_type = ref2_node.value.attributes[0x03].value # DW_AT_name
        if ref_node.value.tag == 0x01: # DW_TAG_array_type
            print(f'    {dw_at_type} {dw_at_name}[];')
        elif ref_node.value.tag == 0x0f: # DW_TAG_pointer_type
            print(f'    {dw_at_type}* {dw_at_name};')
    elif ref_node.value.tag == 0x13: # DW_AT_structure
        show_struct(root, ref_node)
    else:
        dw_at_type = ref_node.value.attributes[0x03].value # DW_AT_name
        print(f'    {dw_at_type} {dw_at_name};')

def show_struct(root, node):
    print('struct {')
    for child in node.children:
        if child.value.abbrev_number == 0:
            continue
        handler = handlers[child.value.tag]
        handler(root, child)
    print('}')

handlers = {
    0x01: show_array,
    0x04: show_enum,
    0x0d: show_member,
    0x0f: show_pointer,
    0x13: show_struct,
    0x16: show_typedef,
    0x17: show_union
}

class gdb:
    def __init__(self, file) -> None:
        self.elf = elf.elf(file)
        self.elf.get_compilation_units()

    def whatis(self, variable):
        for num in self.elf.compilation_units:
            cu, root = self.elf.compilation_units[num]
            node = root.search('attributes', (0x03, variable)) # DW_AT_name
            if node is None:
                continue

            ref4 = node.value.attributes[0x49].value # DW_AT_type
            node = root.search('offset', ref4)
            if 0x03 in node.value.attributes: # DW_AT_name
                print(node.value.attributes[0x03].value)
            else:
                tag = elf.dh.DW_TAG[node.value.tag]
                if 'structure' in tag:
                    print('type = struct {...}')
            break

    def ptype(self, typedef):
        for num in self.elf.compilation_units:
            cu, root = self.elf.compilation_units[num]
            node = root.search('attributes', (0x03, typedef)) # DW_AT_name
            if node is None:
                continue

            handle = handlers[node.value.tag]
            handle(root, node)
            break

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("elf_file", help="path to elf file")
    parser.add_argument("--whatis", help="return type fo variable name")
    parser.add_argument("--ptype", help="show type definition")
    args = parser.parse_args()

    g = gdb(args.elf_file)

    if args.whatis:
        g.whatis(args.whatis)

    if args.ptype:
        g.ptype(args.ptype)

if __name__ == '__main__':
    main()