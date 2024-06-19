from ctypes import c_uint
from ctypes import c_ubyte
from ctypes import c_ushort
from ctypes import c_ulonglong
from ctypes import LittleEndianStructure

class FileHeader(LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ('magic_number', c_uint),
        ('ei_class', c_ubyte),
        ('data', c_ubyte),
        ('version', c_ubyte),
        ('osabi', c_ubyte),
        ('abiversion', c_ulonglong),
        ('type', c_ushort),
        ('machine', c_ushort),
        ('e_version', c_uint),
        ('entry', c_uint),
        ('phoff', c_uint),
        ('shoff', c_uint),
        ('flags', c_uint),
        ('ehsize', c_ushort),
        ('phentsize', c_ushort),
        ('phnum', c_ushort),
        ('shentsize', c_ushort),
        ('shnum', c_ushort),
        ('shstrndx', c_ushort),
    ]

class ProgramHeader(LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ('type', c_uint),
        ('offset', c_uint),
        ('vaddr', c_uint),
        ('paddr', c_uint),
        ('filesz', c_uint),
        ('memsz', c_uint),
        ('flags', c_uint),
        ('align', c_uint),
    ]

class SectionHeader(LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ('name', c_uint),
        ('type', c_uint),
        ('flags', c_uint),
        ('addr', c_uint),
        ('offset', c_uint),
        ('size', c_uint),
        ('link', c_uint),
        ('info', c_uint),
        ('addralign', c_uint),
        ('entsize', c_uint),
    ]

ST_TYPE = {
    0:  'NOTYPE',
    1:  'OBJECT',
    2:  'FUNC',
    3:  'SECTION',
    4:  'FILE',
    13: 'LOPROC',
    15: 'HIPROC'
}

ST_BIND = {
    0:  'LOCAL',
    1:  'GLOBAL',
    2:  'WEAK',
    13: 'LOPROC',
    15: 'HIPROC'
}

SHN = {
    0:      'UND',
    0xff00: 'LOPROC',
    0xff1f: 'HIPROC',
    0xfff1: 'ABS',
    0xfff2: 'COMMON',
    0xffff: 'HIRESERVE'
}

class SymbolEntry(LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ('name', c_uint),
        ('value', c_uint),
        ('size', c_uint),
        ('info', c_ubyte),
        ('other', c_ubyte),
        ('shndx', c_ushort),
    ]
