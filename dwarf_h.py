from ctypes import c_uint
from ctypes import c_byte
from ctypes import c_ubyte
from ctypes import c_ushort
from ctypes import LittleEndianStructure

DW_TAG = {
    0x01: 'DW_TAG_array_type',
    0x02: 'DW_TAG_class_type',
    0x03: 'DW_TAG_entry_point',
    0x04: 'DW_TAG_enumeration_type',
    0x05: 'DW_TAG_formal_parameter',
    0x08: 'DW_TAG_imported_declaration',
    0x0a: 'DW_TAG_label',
    0x0b: 'DW_TAG_lexical_block',
    0x0d: 'DW_TAG_member',
    0x0f: 'DW_TAG_pointer_type',
    0x10: 'DW_TAG_reference_type',
    0x11: 'DW_TAG_compile_unit',
    0x12: 'DW_TAG_string_type',
    0x13: 'DW_TAG_structure_type',
    0x15: 'DW_TAG_subroutine_type',
    0x16: 'DW_TAG_typedef',
    0x17: 'DW_TAG_union_type',
    0x18: 'DW_TAG_unspecified_parameters',
    0x19: 'DW_TAG_variant',
    0x1a: 'DW_TAG_common_block',
    0x1b: 'DW_TAG_common_inclusion',
    0x1c: 'DW_TAG_inheritance',
    0x1d: 'DW_TAG_inlined_subroutine',
    0x1e: 'DW_TAG_module',
    0x1f: 'DW_TAG_ptr_to_member_type',
    0x20: 'DW_TAG_set_type',
    0x21: 'DW_TAG_subrange_type',
    0x22: 'DW_TAG_with_stmt',
    0x23: 'DW_TAG_access_declaration',
    0x24: 'DW_TAG_base_type',
    0x25: 'DW_TAG_catch_block',
    0x26: 'DW_TAG_const_type',
    0x27: 'DW_TAG_constant',
    0x28: 'DW_TAG_enumerator',
    0x29: 'DW_TAG_file_type',
    0x2a: 'DW_TAG_friend',
    0x2b: 'DW_TAG_namelist',
    0x2c: 'DW_TAG_namelist_item',
    0x2d: 'DW_TAG_packed_type',
    0x2e: 'DW_TAG_subprogram',
    0x2f: 'DW_TAG_template_type_param',
    0x30: 'DW_TAG_template_value_param',
    0x31: 'DW_TAG_thrown_type',
    0x32: 'DW_TAG_try_block',
    0x33: 'DW_TAG_variant_part',
    0x34: 'DW_TAG_variable',
    0x35: 'DW_TAG_volatile_type'
}

DW_CHILDREN = {
    0x00: '[no children]',
    0x01: '[has children]'
}

DW_AT = {
    0x00: 'DW_AT value',
    0x01: 'DW_AT_sibling',
    0x02: 'DW_AT_location',
    0x03: 'DW_AT_name',
    0x09: 'DW_AT_ordering',
    0x0b: 'DW_AT_byte_size',
    0x0c: 'DW_AT_bit_offset',
    0x0d: 'DW_AT_bit_size',
    0x10: 'DW_AT_stmt_list',
    0x11: 'DW_AT_low_pc',
    0x12: 'DW_AT_high_pc',
    0x13: 'DW_AT_language',
    0x15: 'DW_AT_discr',
    0x16: 'DW_AT_discr_value',
    0x17: 'DW_AT_visibility',
    0x18: 'DW_AT_import',
    0x19: 'DW_AT_string_length',
    0x1a: 'DW_AT_common_reference',
    0x1b: 'DW_AT_comp_dir',
    0x1c: 'DW_AT_const_value',
    0x1d: 'DW_AT_containing_type',
    0x1e: 'DW_AT_default_value',
    0x20: 'DW_AT_inline',
    0x21: 'DW_AT_is_optional',
    0x22: 'DW_AT_lower_bound',
    0x25: 'DW_AT_producer',
    0x27: 'DW_AT_prototyped',
    0x2a: 'DW_AT_return_addr',
    0x2c: 'DW_AT_start_scope',
    0x2e: 'DW_AT_stride_size',
    0x2f: 'DW_AT_upper_bound',
    0x31: 'DW_AT_abstract_origin',
    0x32: 'DW_AT_accessibility',
    0x33: 'DW_AT_address_class',
    0x34: 'DW_AT_artificial',
    0x35: 'DW_AT_base_types',
    0x36: 'DW_AT_calling_convention',
    0x37: 'DW_AT_count',
    0x38: 'DW_AT_data_member_location',
    0x39: 'DW_AT_decl_column',
    0x3a: 'DW_AT_decl_file',
    0x3b: 'DW_AT_decl_line',
    0x3c: 'DW_AT_declaration',
    0x3d: 'DW_AT_discr_list',
    0x3e: 'DW_AT_encoding',
    0x3f: 'DW_AT_external',
    0x40: 'DW_AT_frame_base',
    0x41: 'DW_AT_friend',
    0x42: 'DW_AT_identifier_case',
    0x43: 'DW_AT_macro_info',
    0x44: 'DW_AT_namelist_item',
    0x45: 'DW_AT_priority',
    0x46: 'DW_AT_segment',
    0x47: 'DW_AT_specification',
    0x48: 'DW_AT_static_link',
    0x49: 'DW_AT_type',
    0x4a: 'DW_AT_use_location',
    0x4b: 'DW_AT_variable_parameter',
    0x4c: 'DW_AT_virtuality',
    0x4d: 'DW_AT_vtable_elem_location',
    0x4e: 'DW_AT_allocated',
    0x4f: 'DW_AT_associated',
    0x50: 'DW_AT_data_location',
    0x51: 'DW_AT_byte_stride',
    0x52: 'DW_AT_entry_pc',
    0x53: 'DW_AT_use_UTF8',
    0x54: 'DW_AT_extension',
    0x55: 'DW_AT_ranges',
    0x56: 'DW_AT_trampoline',
    0x57: 'DW_AT_call_column',
    0x58: 'DW_AT_call_file',
    0x59: 'DW_AT_call_line',
    0x5a: 'DW_AT_description',
    0x5b: 'DW_AT_binary_scale',
    0x5c: 'DW_AT_decimal_scale',
    0x5d: 'DW_AT_small',
    0x5e: 'DW_AT_decimal_sign',
    0x5f: 'DW_AT_digit_count',
    0x60: 'DW_AT_picture_string',
    0x61: 'DW_AT_mutable',
    0x62: 'DW_AT_threads_scaled',
    0x63: 'DW_AT_explicit',
    0x64: 'DW_AT_object_pointer',
    0x65: 'DW_AT_endianity',
    0x66: 'DW_AT_elemental',
    0x67: 'DW_AT_pure',
    0x68: 'DW_AT_recursive',
    0x69: 'DW_AT_signature',
    0x6a: 'DW_AT_main_subprogram',
    0x6b: 'DW_AT_data_bit_offset',
    0x6c: 'DW_AT_const_expr',
    0x6d: 'DW_AT_enum_class',
    0x6e: 'DW_AT_linkage_name',
    0x6f: 'DW_AT_string_length_bit_size',
    0x70: 'DW_AT_string_length_byte_size',
    0x71: 'DW_AT_rank',
    0x72: 'DW_AT_str_offsets_base',
    0x73: 'DW_AT_addr_base',
    0x74: 'DW_AT_rnglists_base',
    0x76: 'DW_AT_dwo_name',
    0x77: 'DW_AT_reference',
    0x78: 'DW_AT_rvalue_reference',
    0x79: 'DW_AT_macros',
    0x7a: 'DW_AT_call_all_calls',
    0x7b: 'DW_AT_call_all_source_calls',
    0x7c: 'DW_AT_call_all_tail_calls',
    0x7d: 'DW_AT_call_return_pc',
    0x7e: 'DW_AT_call_value',
    0x7f: 'DW_AT_call_origin',
    0x80: 'DW_AT_call_parameter',
    0x81: 'DW_AT_call_pc',
    0x82: 'DW_AT_call_tail_call',
    0x83: 'DW_AT_call_target',
    0x84: 'DW_AT_call_target_clobbered',
    0x85: 'DW_AT_call_data_location',
    0x86: 'DW_AT_call_data_value',
    0x87: 'DW_AT_noreturn',
    0x88: 'DW_AT_alignment',
    0x89: 'DW_AT_export_symbols',
    0x8a: 'DW_AT_deleted',
    0x8b: 'DW_AT_defaulted',
    0x8c: 'DW_AT_loclists_base'
}

DW_FORM = {
    0x00: 'DW_FORM value',
    0x01: 'DW_FORM_addr',
    0x03: 'DW_FORM_block2',
    0x04: 'DW_FORM_block4',
    0x05: 'DW_FORM_data2',
    0x06: 'DW_FORM_data4',
    0x07: 'DW_FORM_data8',
    0x08: 'DW_FORM_string',
    0x09: 'DW_FORM_block',
    0x0a: 'DW_FORM_block1',
    0x0b: 'DW_FORM_data1',
    0x0c: 'DW_FORM_flag',
    0x0d: 'DW_FORM_sdata',
    0x0e: 'DW_FORM_strp',
    0x0f: 'DW_FORM_udata',
    0x10: 'DW_FORM_ref_addr',
    0x11: 'DW_FORM_ref1',
    0x12: 'DW_FORM_ref2',
    0x13: 'DW_FORM_ref4',
    0x14: 'DW_FORM_ref8',
    0x15: 'DW_FORM_ref_udata',
    0x16: 'DW_FORM_indirect'
}

class CompilationUnitHeader(LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ('length', c_uint),
        ('version', c_ushort),
        ('abbrev_offset', c_uint),
        ('ptr_size', c_ubyte),
    ]

class AddressRangeHeader(LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ('length', c_uint),
        ('version', c_ushort),
        ('info_offset', c_uint),
        ('ptr_size', c_ubyte),
        ('seg_size', c_ubyte),
        ('pad', c_uint),
    ]

class NameLookupHeader(LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ('length', c_uint),
        ('version', c_ushort),
        ('info_offset', c_uint),
        ('info_size', c_uint),
    ]

class StatementProgramPrologue(LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ('total_length', c_uint),
        ('version', c_ushort),
        ('prologue_length', c_uint),
        ('minimum_instruction_length', c_ubyte),
        ('default_is_stmt', c_ubyte),
        ('line_base', c_byte),
        ('line_range', c_ubyte),
        ('opcode_base', c_ubyte),
    ]

class FileName:
    def __init__(self):
        self.name = None
        self.dir = None
        self.time = None
        self.size = None

class StateMachineRegisters:
    def __init__(self):
        self.address = 0
        self.file = 1
        self.line = 1
        self.column = 0
        self.is_stmt = None
        self.basic_block = False
        self.end_sequence = False

class StatementProgram:
    def __init__(self):
        self.prologue = None
        self.opcodes = None
        self.directory_table_offset = None
        self.include_directories = None
        self.file_name_table_offset = None
        self.file_names = None
        self.matrix = None

class Attribute:
    def __init__(self, offset, name, form, value=None, offset_str=None) -> None:
        self.offset = offset
        self.name = name
        self.form = form
        self.value = value
        self.offset_str = offset_str

    def __str__(self) -> str:
        if self.form == 0x13: # DW_FORM_ref4
            value = f'<{hex(self.value)}>'
        elif self.form == 0x06: # DW_FORM_data4
            value = f'{hex(self.value)}'
        elif self.form == 0x0e: # DW_FORM_strp
            value = f'(indirect string, offset: {hex(self.offset_str)}): {self.value}'
        else:
            value = self.value
        my_string = f"    <{self.offset:x}>   {self.name.ljust(18, ' ')}: {value}\n"

        return my_string

class DebugInformationEntry:
    def __init__(self, level, offset, abbrev_number, tag=None, has_children=None) -> None:
        self.level = level
        self.offset = offset
        self.abbrev_number = abbrev_number
        self.tag = tag
        self.has_children = has_children
        self.attributes = {}

    def set_attr(self, name, value):
        setattr(self, name, value.value)
        self.attributes[name] = value

    def __str__(self) -> str:
        my_string = f' <{self.level}><{self.offset:x}>: Abbrev Number: {self.abbrev_number}'
        if self.abbrev_number != 0:
            my_string += f' ({DW_TAG[self.tag]})'
        my_string += '\n'

        for name, value in self.attributes.items():
            my_string += value.__str__()

        return my_string[:-1]
