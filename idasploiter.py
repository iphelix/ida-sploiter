#!/usr/bin/env python
#
# IDA Sploiter is an exploit development and vulnerability research environment
# implemented as a plugin for Hex-Ray's IDA Pro disassembler.

IDASPLOITER_VERSION = "1.0"

# Copyright (C) 2014 Peter Kacherginsky
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met: 
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer. 
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# 3. Neither the name of the copyright holder nor the names of its contributors
#    may be used to endorse or promote products derived from this software without 
#    specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# Performance profiling
import cProfile
import pstats

# IDA libraries
import idaapi
import idautils
import idc
from idaapi import Form, Choose2, plugin_t

# Python libraries
import os
import binascii
import string
import textwrap
import copy
import csv
import itertools

from struct import pack, unpack
from ctypes import *

###############################################################################
# Data Tables and Structures
###############################################################################

###############################################################################
# 00-FF Single byte to unicode transforms
# NOTE: Some unicode characters can have two bytes
#       http://www.phenoelit.org/stuff/Phenoelit20c3.pdf

# Ascii_to_Unicode_transforms
ASCII_TO_UNICODE_GENERAL = [
    "\x00\x00", "\x00\x01", "\x00\x02", "\x00\x03", "\x00\x04", "\x00\x05",
    "\x00\x06", "\x00\x07", "\x00\x08", "\x00\x09", "\x00\x0a", "\x00\x0b", 
    "\x00\x0c", "\x00\x0d", "\x00\x0e", "\x00\x0f", "\x00\x10", "\x00\x11", 
    "\x00\x12", "\x00\x13", "\x00\x14", "\x00\x15", "\x00\x16", "\x00\x17", 
    "\x00\x18", "\x00\x19", "\x00\x1a", "\x00\x1b", "\x00\x1c", "\x00\x1d", 
    "\x00\x1e", "\x00\x1f", "\x00\x20", "\x00\x21", "\x00\x22", "\x00\x23", 
    "\x00\x24", "\x00\x25", "\x00\x26", "\x00\x27", "\x00\x28", "\x00\x29", 
    "\x00\x2a", "\x00\x2b", "\x00\x2c", "\x00\x2d", "\x00\x2e", "\x00\x2f", 
    "\x00\x30", "\x00\x31", "\x00\x32", "\x00\x33", "\x00\x34", "\x00\x35", 
    "\x00\x36", "\x00\x37", "\x00\x38", "\x00\x39", "\x00\x3a", "\x00\x3b", 
    "\x00\x3c", "\x00\x3d", "\x00\x3e", "\x00\x3f", "\x00\x40", "\x00\x41", 
    "\x00\x42", "\x00\x43", "\x00\x44", "\x00\x45", "\x00\x46", "\x00\x47", 
    "\x00\x48", "\x00\x49", "\x00\x4a", "\x00\x4b", "\x00\x4c", "\x00\x4d", 
    "\x00\x4e", "\x00\x4f", "\x00\x50", "\x00\x51", "\x00\x52", "\x00\x53", 
    "\x00\x54", "\x00\x55", "\x00\x56", "\x00\x57", "\x00\x58", "\x00\x59", 
    "\x00\x5a", "\x00\x5b", "\x00\x5c", "\x00\x5d", "\x00\x5e", "\x00\x5f", 
    "\x00\x60", "\x00\x61", "\x00\x62", "\x00\x63", "\x00\x64", "\x00\x65", 
    "\x00\x66", "\x00\x67", "\x00\x68", "\x00\x69", "\x00\x6a", "\x00\x6b", 
    "\x00\x6c", "\x00\x6d", "\x00\x6e", "\x00\x6f", "\x00\x70", "\x00\x71", 
    "\x00\x72", "\x00\x73", "\x00\x74", "\x00\x75", "\x00\x76", "\x00\x77", 
    "\x00\x78", "\x00\x79", "\x00\x7a", "\x00\x7b", "\x00\x7c", "\x00\x7d", 
    "\x00\x7e", "\x00\x7f"
]

ASCII_TO_UNICODE_ANSI = ASCII_TO_UNICODE_GENERAL + [
    "\x20\xac", "\x00\x81", "\x20\x1a", "\x01\x92", "\x20\x1e", "\x20\x26",
    "\x20\x20", "\x20\x21", "\x02\xc6", "\x20\x30", "\x01\x60", "\x20\x39",
    "\x01\x52", "\x00\x8d", "\x01\x7d", "\x00\x8f", "\x90\x00", "\x20\x18",
    "\x20\x19", "\x20\x1c", "\x20\x1d", "\x20\x22", "\x20\x13", "\x20\x14",
    "\x02\xdc", "\x21\x22", "\x01\x61", "\x3a\x20", "\x01\x53", "\x00\x9d",
    "\x01\x7e", "\x01\x78", "\x00\xa0", "\x00\xa1", "\x00\xa2", "\x00\xa3",
    "\x00\xa4", "\x00\xa5", "\x00\xa6", "\x00\xa7", "\x00\xa8", "\x00\xa9",
    "\x00\xaa", "\x00\xab", "\x00\xac", "\x00\xad", "\x00\xae", "\x00\xaf",
    "\x00\xb0", "\x00\xb1", "\x00\xb2", "\x00\xb3", "\x00\xb4", "\x00\xb5",
    "\x00\xb6", "\x00\xb7", "\x00\xb8", "\x00\xb9", "\x00\xba", "\x00\xbb",
    "\x00\xbc", "\x00\xbd", "\x00\xbe", "\x00\xbf", "\x00\xc0", "\x00\xc1",
    "\x00\xc2", "\x00\xc3", "\x00\xc4", "\x00\xc5", "\x00\xc6", "\x00\xc7",
    "\x00\xc8", "\x00\xc9", "\x00\xca", "\x00\xcb", "\x00\xcc", "\x00\xcd",
    "\x00\xce", "\x00\xcf", "\x00\xd0", "\x00\xd1", "\x00\xd2", "\x00\xd3",
    "\x00\xd4", "\x00\xd5", "\x00\xd6", "\x00\xd7", "\x00\xd8", "\x00\xd9",
    "\x00\xda", "\x00\xdb", "\x00\xdc", "\x00\xdd", "\x00\xde", "\x00\xdf",
    "\x00\xe0", "\x00\xe1", "\x00\xe2", "\x00\xe3", "\x00\xe4", "\x00\xe5",
    "\x00\xe6", "\x00\xe7", "\x00\xe8", "\x00\xe9", "\x00\xea", "\x00\xeb",
    "\x00\xec", "\x00\xed", "\x00\xee", "\x00\xef", "\x00\xf0", "\x00\xf1",
    "\x00\xf2", "\x00\xf3", "\x00\xf4", "\x00\xf5", "\x00\xf6", "\x00\xf7",
    "\x00\xf8", "\x00\xf9", "\x00\xfa", "\x00\xfb", "\x00\xfc", "\x00\xfd",
    "\x00\xfe", "\x00\xff"
]

ASCII_TO_UNICODE_OEM = ASCII_TO_UNICODE_GENERAL + [
    "\x00\xc7", "\x00\xfc", "\x00\xe9", "\x00\xe2", "\x00\xe4", "\x00\xe0",
    "\x00\xe5", "\x00\xe7", "\x00\xea", "\x00\xeb", "\x00\xe8", "\x00\xef",
    "\x00\xee", "\x00\xec", "\x00\xc4", "\x00\xc5", "\x00\xc9", "\x00\xe6",
    "\x00\xc6", "\x00\xf4", "\x00\xf6", "\x00\xf2", "\x00\xfb", "\x00\xf9",
    "\x00\xff", "\x00\xd6", "\x00\xdc", "\x00\xf8", "\x00\xa3", "\x00\xd8",
    "\x00\xd7", "\x01\x92", "\x00\xe1", "\x00\xed", "\x00\xf3", "\x00\xfa",
    "\x00\xf1", "\x00\xd1", "\x00\xaa", "\x00\xba", "\x00\xbf", "\x00\xae",
    "\x00\xac", "\x00\xbd", "\x00\xbc", "\x00\xa1", "\x00\xab", "\x00\xbb",
    "\x25\x91", "\x25\x92", "\x25\x93", "\x25\x02", "\x25\x24", "\x00\xc1",
    "\x00\xc2", "\x00\xc0", "\x00\xa9", "\x25\x63", "\x25\x51", "\x25\x57",
    "\x25\x5d", "\x00\xa2", "\x00\xa5", "\x25\x10", "\x25\x14", "\x25\x34",
    "\x25\x2c", "\x25\x1c", "\x25\x00", "\x25\x3c", "\x00\xe3", "\x00\xc3",
    "\x25\x5a", "\x25\x54", "\x25\x69", "\x25\x66", "\x25\x60", "\x25\x50",
    "\x25\x6c", "\x00\xa4", "\x00\xf0", "\x00\xd0", "\x00\xca", "\x00\xcb",
    "\x00\xc8", "\x01\x31", "\x00\xcd", "\x00\xce", "\x00\xcf", "\x25\x18",
    "\x25\x0c", "\x25\x88", "\x25\x84", "\x00\xa6", "\x00\xcc", "\x25\x80",
    "\x00\xd3", "\x00\xdf", "\x00\xd4", "\x00\xd2", "\x00\xf5", "\x00\xd5",
    "\x00\xb5", "\x00\xfe", "\x00\xde", "\x00\xda", "\x00\xdb", "\x00\xd9",
    "\x00\xfd", "\x00\xdd", "\x00\xaf", "\x00\xb4", "\x00\xad", "\x00\xb1",
    "\x20\x17", "\x00\xbe", "\x00\xb6", "\x00\xa7", "\x00\xf7", "\x00\xb8",
    "\x00\xb0", "\x00\xa8", "\x00\xb7", "\x00\xb9", "\x00\xb3", "\x00\xb2",
    "\x25\xa0", "\x00\xa0"
]

ASCII_TO_UNICODE_UTF7 = ASCII_TO_UNICODE_GENERAL + [
    "\xff\x80", "\xff\x81", "\xff\x82", "\xff\x83", "\xff\x84", "\xff\x85",
    "\xff\x86", "\xff\x87", "\xff\x88", "\xff\x89", "\xff\x8a", "\xff\x8b",
    "\xff\x8c", "\xff\x8d", "\xff\x8e", "\xff\x8f", "\xff\x90", "\xff\x91",
    "\xff\x92", "\xff\x93", "\xff\x94", "\xff\x95", "\xff\x96", "\xff\x97",
    "\xff\x98", "\xff\x99", "\xff\x9a", "\xff\x9b", "\xff\x9c", "\xff\x9d",
    "\xff\x9e", "\xff\x9f", "\xff\xa0", "\xff\xa1", "\xff\xa2", "\xff\xa3",
    "\xff\xa4", "\xff\xa5", "\xff\xa6", "\xff\xa7", "\xff\xa8", "\xff\xa9",
    "\xff\xaa", "\xff\xab", "\xff\xac", "\xff\xad", "\xff\xae", "\xff\xaf",
    "\xff\xb0", "\xff\xb1", "\xff\xb2", "\xff\xb3", "\xff\xb4", "\xff\xb5",
    "\xff\xb6", "\xff\xb7", "\xff\xb8", "\xff\xb9", "\xff\xba", "\xff\xbb",
    "\xff\xbc", "\xff\xbd", "\xff\xbe", "\xff\xbf", "\xff\xc0", "\xff\xc1",
    "\xff\xc2", "\xff\xc3", "\xff\xc4", "\xff\xc5", "\xff\xc6", "\xff\xc7",
    "\xff\xc8", "\xff\xc9", "\xff\xca", "\xff\xcb", "\xff\xcc", "\xff\xcd",
    "\xff\xce", "\xff\xcf", "\xff\xd0", "\xff\xd1", "\xff\xd2", "\xff\xd3",
    "\xff\xd4", "\xff\xd5", "\xff\xd6", "\xff\xd7", "\xff\xd8", "\xff\xd9",
    "\xff\xda", "\xff\xdb", "\xff\xdc", "\xff\xdd", "\xff\xde", "\xff\xdf",
    "\xff\xe0", "\xff\xe1", "\xff\xe2", "\xff\xe3", "\xff\xe4", "\xff\xe5",
    "\xff\xe6", "\xff\xe7", "\xff\xe8", "\xff\xe9", "\xff\xea", "\xff\xeb",
    "\xff\xec", "\xff\xed", "\xff\xee", "\xff\xef", "\xff\xf0", "\xff\xf1",
    "\xff\xf2", "\xff\xf3", "\xff\xf4", "\xff\xf5", "\xff\xf6", "\xff\xf7",
    "\xff\xf8", "\xff\xf9", "\xff\xfa", "\xff\xfb", "\xff\xfc", "\xff\xfd",
    "\xff\xfe", "\xff\xff"
]

ASCII_TO_UNICODE_UTF8 = ASCII_TO_UNICODE_GENERAL + [
    "\x00\x00", "\x00\x00", "\x00\x00", "\x00\x00", "\x00\x00", "\x00\x00",
    "\x00\x00", "\x00\x00", "\x00\x00", "\x00\x00", "\x00\x00", "\x00\x00",
    "\x00\x00", "\x00\x00", "\x00\x00", "\x00\x00", "\x00\x00", "\x00\x00",
    "\x00\x00", "\x00\x00", "\x00\x00", "\x00\x00", "\x00\x00", "\x00\x00",
    "\x00\x00", "\x00\x00", "\x00\x00", "\x00\x00", "\x00\x00", "\x00\x00",
    "\x00\x00", "\x00\x00", "\x00\x00", "\x00\x00", "\x00\x00", "\x00\x00",
    "\x00\x00", "\x00\x00", "\x00\x00", "\x00\x00", "\x00\x00", "\x00\x00",
    "\x00\x00", "\x00\x00", "\x00\x00", "\x00\x00", "\x00\x00", "\x00\x00",
    "\x00\x00", "\x00\x00", "\x00\x00", "\x00\x00", "\x00\x00", "\x00\x00",
    "\x00\x00", "\x00\x00", "\x00\x00", "\x00\x00", "\x00\x00", "\x00\x00",
    "\x00\x00", "\x00\x00", "\x00\x00", "\x00\x00", "\x00\x00", "\x00\x01",
    "\x00\x02", "\x00\x03", "\x00\x04", "\x00\x05", "\x00\x06", "\x00\x07",
    "\x00\x08", "\x00\x09", "\x00\x0a", "\x00\x0b", "\x00\x0c", "\x00\x0d",
    "\x00\x0e", "\x00\x0f", "\x00\x10", "\x00\x11", "\x00\x12", "\x00\x13",
    "\x00\x14", "\x00\x15", "\x00\x16", "\x00\x17", "\x00\x18", "\x00\x19",
    "\x00\x1a", "\x00\x1b", "\x00\x1c", "\x00\x1d", "\x00\x1e", "\x00\x1f",
    "\x00\x00", "\x00\x01", "\x00\x02", "\x00\x03", "\x00\x04", "\x00\x05",
    "\x00\x06", "\x00\x07", "\x00\x08", "\x00\x09", "\x00\x0a", "\x00\x0b",
    "\x00\x0c", "\x00\x0d", "\x00\x0e", "\x00\x0f", "\x00\x00", "\x00\x01",
    "\x00\x02", "\x00\x03", "\x00\x04", "\x00\x05", "\x00\x06", "\x00\x07",
    "\x00\x08", "\x00\x09", "\x00\x0a", "\x00\x0b", "\x00\x0c", "\x00\x0d",
    "\x00\x0e", "\x00\x0f"
]

ASCII_TO_UNICODE = [ASCII_TO_UNICODE_ANSI,
                    ASCII_TO_UNICODE_OEM, 
                    ASCII_TO_UNICODE_UTF7, 
                    ASCII_TO_UNICODE_UTF8]

###############################################################################
# Microsoft Portable Executable and Common Object File Format Specification
# Revision 8.3 - February 6, 2013

class IMAGE_DOS_HEADER(Structure):
    _fields_ = [
                    ("signature" , c_char * 2),
                    ("lastsize"  , c_short),
                    ("nblocks"   , c_short),
                    ("nreloc"    , c_short),
                    ("hdrsize"   , c_short),
                    ("minalloc"  , c_short),
                    ("maxalloc"  , c_short),
                    ("ss"        , c_short),
                    ("sp"        , c_short),
                    ("checksum"  , c_short),
                    ("ip"        , c_short),
                    ("cs"        , c_short),
                    ("relocpos"  , c_short),
                    ("noverlay"  , c_short),
                    ("reserved1" , c_short * 4),
                    ("oem_id"    , c_short),
                    ("reserved2" , c_short * 10),
                    ("e_lfanew"  , c_long)
                ]

class IMAGE_FILE_HEADER(Structure):
    _fields_ = [
                    ("Machine"              , c_short),
                    ("NumberOfSections"     , c_short),
                    ("TimeDateStamp"        , c_long),
                    ("PointerToSymbolTable" , c_long),
                    ("NumberOfSymbols"      , c_long),
                    ("SizeOfOptionalHeader" , c_short),
                    ("Characteristics"      , c_short)
                ]

class IMAGE_DATA_DIRECTORY(Structure):
    _fields_ = [
                    ("VirtualAddress", c_long),
                    ("Size", c_long)
                ]

class IMAGE_OPTIONAL_HEADER(Structure):
    _fields_ = [
                    ("signature"               , c_short),
                    ("MajorLinkerVersion"      , c_byte),
                    ("MinorLinkerVersion"      , c_byte),
                    ("SizeOfCode"              , c_long),
                    ("SizeOfInitializedData"   , c_long),
                    ("SizeOfUninitializedData" , c_long),
                    ("AddressOfEntryPoint"     , c_long),
                    ("BaseOfCode"              , c_long),
                    ("BaseOfData"              , c_long),
                    ("ImageBase"               , c_long),
                    ("SectionAlignment"        , c_long),
                    ("FileAlignment"           , c_long),
                    ("MajorOSVersion"          , c_short),
                    ("MinorOSVersion"          , c_short),
                    ("MajorImageVersion"       , c_short),
                    ("MinorImageVersion"       , c_short),
                    ("MajorSubsystemVersion"   , c_short),
                    ("MinorSubsystemVersion"   , c_short),
                    ("Reserved"                , c_long),
                    ("SizeOfImage"             , c_long),
                    ("SizeOfHeaders"           , c_long),
                    ("Checksum"                , c_long),
                    ("Subsystem"               , c_short),
                    ("DLLCharacteristics"      , c_short),
                    ("SizeOfStackReserve"      , c_long),
                    ("SizeOfStackCommit"       , c_long),
                    ("SizeOfHeapReserve"       , c_long),
                    ("SizeOfHeapCommit"        , c_long),
                    ("LoaderFlags"             , c_long),
                    ("NumberOfRvaAndSizes"     , c_long),
                    ("DataDirectory"           , IMAGE_DATA_DIRECTORY * 16)
                ]

class IMAGE_OPTIONAL_HEADER64(Structure):
    _fields_ = [
                    ("signature"               , c_short),
                    ("MajorLinkerVersion"      , c_byte),
                    ("MinorLinkerVersion"      , c_byte),
                    ("SizeOfCode"              , c_long),
                    ("SizeOfInitializedData"   , c_long),
                    ("SizeOfUninitializedData" , c_long),
                    ("AddressOfEntryPoint"     , c_long),
                    ("BaseOfCode"              , c_long),
                    ("ImageBase"               , c_longlong),
                    ("SectionAlignment"        , c_long),
                    ("FileAlignment"           , c_long),
                    ("MajorOSVersion"          , c_short),
                    ("MinorOSVersion"          , c_short),
                    ("MajorImageVersion"       , c_short),
                    ("MinorImageVersion"       , c_short),
                    ("MajorSubsystemVersion"   , c_short),
                    ("MinorSubsystemVersion"   , c_short),
                    ("Reserved"                , c_long),
                    ("SizeOfImage"             , c_long),
                    ("SizeOfHeaders"           , c_long),
                    ("Checksum"                , c_long),
                    ("Subsystem"               , c_short),
                    ("DLLCharacteristics"      , c_short),
                    ("SizeOfStackReserve"      , c_longlong),
                    ("SizeOfStackCommit"       , c_longlong),
                    ("SizeOfHeapReserve"       , c_longlong),
                    ("SizeOfHeapCommit"        , c_longlong),
                    ("LoaderFlags"             , c_long),
                    ("NumberOfRvaAndSizes"     , c_long),
                    ("DataDirectory"           , IMAGE_DATA_DIRECTORY * 16)
                ]

class IMAGE_LOAD_CONFIG_DIRECTORY(Structure):
    _fields_ = [
                    ("Size"                          , c_long),
                    ("TimeDateStamp"                 , c_long),
                    ("MajorVersion"                  , c_short),
                    ("MinorVersion"                  , c_short),
                    ("GlobalFlagsClear"              , c_long),
                    ("GlobalFlagsSet"                , c_long),
                    ("CriticalSectionDefaultTimeout" , c_long),
                    ("DeCommitFreeBlockThreshold"    , c_long),
                    ("DeCommitTotalFreeThreshold"    , c_long),
                    ("LockPrefixTable"               , c_long),
                    ("MaximumAllocationSize"         , c_long),
                    ("VirtualMemoryThreshold"        , c_long),
                    ("ProcessHeapFlags"              , c_long),
                    ("ProcessAffinityMask"           , c_long),
                    ("CSDVersion"                    , c_short),
                    ("Reserved1"                     , c_short),
                    ("EditList"                      , c_long),
                    ("SecurityCookie"                , c_long),
                    ("SEHandlerTable"                , c_long),
                    ("SEHandlerCount"                , c_long)
                ]

class IMAGE_LOAD_CONFIG_DIRECTORY64(Structure):
    _fields_ = [
                    ("Size"                          , c_long),
                    ("TimeDateStamp"                 , c_long),
                    ("MajorVersion"                  , c_short),
                    ("MinorVersion"                  , c_short),
                    ("GlobalFlagsClear"              , c_long),
                    ("GlobalFlagsSet"                , c_long),
                    ("CriticalSectionDefaultTimeout" , c_long),
                    ("DeCommitFreeBlockThreshold"    , c_longlong),
                    ("DeCommitTotalFreeThreshold"    , c_longlong),
                    ("LockPrefixTable"               , c_longlong),
                    ("MaximumAllocationSize"         , c_longlong),
                    ("VirtualMemoryThreshold"        , c_longlong),
                    ("ProcessHeapFlags"              , c_long),
                    ("ProcessAffinityMask"           , c_long),
                    ("CSDVersion"                    , c_short),
                    ("Reserved1"                     , c_short),
                    ("EditList"                      , c_longlong),
                    ("SecurityCookie"                , c_longlong),
                    ("SEHandlerTable"                , c_longlong),
                    ("SEHandlerCount"                , c_longlong),
                ]

###############################################################################
# Module Class - Manages module characteristics

class Module():

    def __init__(self, name, size, base, rebase_to):

            self.addr = base

            # BUG: IDA's API does not always zero out the SWIG buffer.
            # BUG: ntdll does not have path information.
            if "\x00" in name:
                name,junk = name.split("\x00",1)

            self.file = os.path.basename(name)
            self.path = os.path.dirname(name)

            self.size = size

            # Parse the module as a PE file
            pe = PE(self.addr)

            if pe:
                self.NXCompat = pe.isNXCompat()
                self.ASLR     = pe.isDynamicBase()
                self.SafeSEH  = pe.isSafeSEH()
                self.GS       = pe.isGS()

###############################################################################
# PE Module Parser

class PE():

    # PE flags
    IMAGE_FILE_MACHINE_I386 = 0x14c

    MAGIC_PE32      = 0x10b
    MAGIC_PE32_PLUS = 0x20b

    IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE = 0x0040
    IMAGE_DLL_CHARACTERISTICS_NX_COMPAT    = 0x0100
    IMAGE_DLLCHARACTERISTICS_NO_SEH        = 0x0400

    def __init__(self, base):

        # PE headers
        self.dos_header            = None
        self.file_header           = None
        self.optional_header       = None
        self.load_config_directory = None
        self.arch64                = False

        # Verify DOS header magic
        magic_dos = idaapi.dbg_read_memory( base, 0x2)
        if magic_dos != "MZ":
            print "[idasploiter] Invalid DOS header magic."
            return None

        # Parse the DOS header
        self.dos_header = IMAGE_DOS_HEADER.from_buffer_copy(
            idaapi.dbg_read_memory(base, 0x40) )

        # Get offset to PE header
        base_pe = base + self.dos_header.e_lfanew

        # Verify PE header magic
        magic_pe = idaapi.dbg_read_memory( base_pe, 0x4 )
        if magic_pe != "PE\x00\x00":
            print "[idasploiter] Invalid PE header magic: %x" % unpack("I",magic_pe)[0]
            return None

        # Parse the FILE header
        # NOTE: IMAGE_FILE_HEADER size is 0x14
        self.file_header = IMAGE_FILE_HEADER.from_buffer_copy( 
            idaapi.dbg_read_memory( base_pe + 0x4, sizeof(IMAGE_FILE_HEADER) ) )

        # Parse the OPTIONAL header
        base_pe_optional =  base_pe + 0x4 + 0x14
        magic_pe_opt = idaapi.dbg_read_memory ( base_pe_optional, 0x2)
        magic_pe_opt = unpack("H", magic_pe_opt)[0]

        # PE32 Optional Header
        if magic_pe_opt == self.MAGIC_PE32:
            self.arch64 = False
            self.optional_header = IMAGE_OPTIONAL_HEADER.from_buffer_copy(
                idaapi.dbg_read_memory( base_pe_optional, self.file_header.SizeOfOptionalHeader ))

        # PE32+ Optional Header
        elif magic_pe_opt == self.MAGIC_PE32_PLUS:
            self.arch64 = True
            self.optional_header = IMAGE_OPTIONAL_HEADER64.from_buffer_copy(
                idaapi.dbg_read_memory( base_pe_optional, self.file_header.SizeOfOptionalHeader ))

        # Invalid PE Header
        else:
            print "[idasploiter] Invalid IMAGE_OPTIONAL_HEADER magic: %x" % unpack("H",magic_pe_opt)[0]
            return None

        # Load Configuration Table
        load_config_directory_rva = self.optional_header.DataDirectory[10].VirtualAddress

        # Parse Load Configuration Table if present
        if load_config_directory_rva:

            # Read LOAD CONFIG DIRECTORY size before parsing it
            load_config_directory_size = idaapi.dbg_read_memory( base + load_config_directory_rva, 0x4)
            load_config_directory_size = unpack("I",load_config_directory_size)[0]

            # Parse LOAD CONFIG DIRECTORY based on PE32 format
            if self.optional_header.signature == self.MAGIC_PE32:
                self.load_config_directory = IMAGE_LOAD_CONFIG_DIRECTORY.from_buffer_copy( idaapi.dbg_read_memory( base + load_config_directory_rva, load_config_directory_size ))

            # Parse LOAD CONFIG DIRECTORY based on PE32+ format
            elif self.optional_header.signature == self.MAGIC_PE32_PLUS:
                self.load_config_directory = IMAGE_LOAD_CONFIG_DIRECTORY64.from_buffer_copy( idaapi.dbg_read_memory( base + load_config_directory_rva, load_config_directory_size ))

            # Invalid PE header
            else:
                print "[idasploiter] Invalid IMAGE_OPTIONAL_HEADER magic: %x" % unpack("H",magic)[0]
                return None

    def isDynamicBase(self):
        if self.optional_header:
            if self.optional_header.DLLCharacteristics & self.IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE:
                return "Yes"
            else:
                return "No"
        else:
            return "Unk"

    def isNXCompat(self):
        if self.optional_header:
            if self.optional_header.DLLCharacteristics & self.IMAGE_DLL_CHARACTERISTICS_NX_COMPAT:
                return "Yes"
            else:
                return "No"
        else:
            return "Unk"

    def isSafeSEH(self):

        if self.file_header and self.optional_header:

            # SafeSEH is only applicable to 32-bit Windows.
            if self.file_header.Machine != self.IMAGE_FILE_MACHINE_I386:
                return "N/A"

            # NO_SEH flag indicates that the module does not use SEH and no handlers can be called in this image.
            elif self.optional_header.DLLCharacteristics & self.IMAGE_DLLCHARACTERISTICS_NO_SEH:
                return "No SEH"

            # SafeSEH is enabled when there is SEHandlerTable entry in the LOAD_CONFIG_DIRECTORY
            elif self.load_config_directory and self.load_config_directory.SEHandlerTable != 0:
                return "Yes"

            # Otherwise SafeSEH is not used
            else:
                return "No"

        else:
            return "Unk"

    def isGS(self):

        if self.file_header and self.optional_header:

            # NOTE: PE32+ does not necessarily provide a pointer to the Security Cookie in the
            #       LoadConfigDirectory. The address appears to be still present in the binary.

            # TODO: Need to do additional research into reliably detecting /GS in PE32+ files.

            # PE32+ binaries with missing LoadConfigDirectory may still used security cookies.
            if self.arch64 and not self.load_config_directory:
                return "Unk"

            if self.load_config_directory and self.load_config_directory.SecurityCookie != 0:

                # Attempt to read the security cookie
                # NOTE: The extra exception handler was added to account for cookie being stored in memory locations
                #       that are not accessible by the debugger (e.g. manually loading win32k.sys, security cookie
                #       address will point to kernel space which we can't read)
                try:
                    # Confirm the Security Cookie is not zero
                    if self.arch64:
                        cookie = idaapi.dbg_read_memory(self.load_config_directory.SecurityCookie, 8)
                        cookie = struct.unpack("<Q", cookie)[0]
                    else:
                        cookie = idaapi.dbg_read_memory(self.load_config_directory.SecurityCookie, 4)
                        cookie = struct.unpack("<I", cookie)[0]

                    if cookie != 0:
                        return "Yes"
                    else:
                        return "Null"

                except Exception, e:
                    return "Inv"

            else:
                return "No"

        else:
            return "Unk"

###############################################################################
# Pointer Class - Manager writable pointer characteristics

class Ptr():

    def __init__(self, module, ptr_ea, ptr_offset, ptr_charset, call_ea, insn_disas):
        self.module = module

        self.ptr_ea = ptr_ea
        self.ptr_offset = ptr_offset
        self.ptr_charset = ptr_charset

        self.call_ea = call_ea
        self.insn_disas = insn_disas

        self.name = idaapi.get_name(self.call_ea + self.ptr_offset, self.ptr_ea) or ""
        self.call_name = idaapi.get_func_name(self.call_ea) or ""

        self.p2p_ea = None
        self.p2p_offset = None
        self.p2p_charset = None

###############################################################################
# Function Pointer Search Engine

class FuncPtr():

    def __init__(self,sploiter):

        self.sploiter   = sploiter
        self.ptr_calls  = list()
        self.ptrs       = list()

    # NOTE: Pointer Offsets are interpreted as follows:
    # Example 1: Consider we have loaded fptr with a user controlled value
    #
    #              mov [fptr + offset], value
    #
    #            The fptr value we need is (fptr - offset) to overwrite
    #            the actual fptr location. Do this early so that applied address
    #            filters consider fptr bytes before offset adjustment.
    #
    #            Specify this positive offset in the Function Pointer form
    #            so that it would be applied to all discovered function pointers.
    #
    # Example 2: Consider we have a pointer to a pointer write condition:
    #
    #              mov fptr, [p2p + offset2]
    #              mov [fptr + offset1], value
    #
    #            The value (p2p - offset2) must point to the fptr location,
    #            but since we have another offset the target of (p2p - offset2)
    #            must be actually (fptr - offset1). Also do this early so that
    #            applied address filters consider p2p before offset adjustment.
    #
    #            Specify this positive p2p offset2 so it gets applied to the listing
    #            of pointers-to-pointers. All pointer-to-pointer(s) will also
    #            be calculated relative to the ptr - offset1
    #
    # NOTE: Only search for pointers to pointers within the same module. This
    #       was done purely for performance considerations since any readable
    #       pointer to pointer may be used.


    def search_pointers(self):
        
        # HACK: A separate flag is used to track user canceling the search,
        #       because multiple calls to idaapi.wasBreak() do not properly
        #       detect cancellations.
        breakFlag = False

        # Show wait dialog
        idaapi.show_wait_box("Searching writable function pointers...")

        for m in self.modules:
 
            ###################################################################
            # Locate all of the CALL and JMP instructions in the current module
            # which use an immediate operand.

            # List of call/jmp pointer calls in a given module
            ptr_calls = list()

            # Iterate over segments in the module
            # BUG: Iterating over all loaded segments is more stable than looking up by address
            for n in xrange(idaapi.get_segm_qty()):
                seg = idaapi.getnseg(n)

                # Segment in a selected modules
                if seg and seg.startEA >= m.addr and seg.endEA <= (m.addr + m.size):

                    # Locate executable segments
                    # NOTE: Each module may have multiple executable segments
                    # TODO: Search for "MOV REG, PTR # CALL REG"
                    if seg.perm & idaapi.SEGPERM_EXEC:

                        # Search all instances of CALL /2 imm32/64 - FF 15
                        # TODO: Alternative pointer calls using SIB: FF 14 E5 11 22 33 44 - call dword/qword ptr [0x44332211]
                        #                                            FF 14 65 11 22 33 44
                        #                                            FF 14 25 11 22 33 44
                        call_ea = seg.startEA
                        while True:
                            call_ea = idaapi.find_binary(call_ea + 1, seg.endEA, "FF 15", 16, idaapi.SEARCH_DOWN)
                            if call_ea == idaapi.BADADDR: break
                            ptr_calls.append( call_ea )

                        # Search all instances of JMP /2 imm32/64 - FF 25
                        # TODO: Alternative pointer calls using SIB: FF 24 E5 11 22 33 44 - jmp dword/qword ptr [0x44332211]
                        #                                            FF 24 65 11 22 33 44
                        #                                            FF 24 25 11 22 33 44
                        call_ea = seg.startEA
                        while True:
                            call_ea = idaapi.find_binary(call_ea + 1, seg.endEA, "FF 25", 16, idaapi.SEARCH_DOWN)
                            if call_ea == idaapi.BADADDR: break
                            ptr_calls.append( call_ea )

            ###################################################################
            # Extract all of the function pointers and make sure they are
            # are writable.

            # List of writable function pointer objects in a given module
            ptrs = list()

            for call_ea in ptr_calls:

                # Decode CALL/JMP instruction
                # NOTE: May result in invalid disassembly of split instructions
                insn_size = idaapi.decode_insn(call_ea)

                if insn_size:

                    insn = idaapi.cmd
                    insn_op1 = insn.Operands[0].type

                    # Verify first operand is a direct memory reference
                    if insn.Operands[0].type == idaapi.o_mem:

                        # Get operand address
                        ptr_ea = insn.Operands[0].addr

                        # Apply pointer offset
                        ptr_ea -= self.ptrOffset

                        # Locate segment where the pointer is located
                        ptr_seg = idaapi.getseg(ptr_ea)

                        # Make sure a valid segment writeable segment was found
                        if ptr_seg and ptr_seg.perm & idaapi.SEGPERM_WRITE:

                            # Get pointer charset
                            ptr_charset = self.sploiter.get_ptr_charset(ptr_ea)

                            # Filter the pointer
                            if not self.filterP2P:
                                if ptr_charset == None:                                    continue
                                if self.ptrNonull     and not "nonull"     in ptr_charset: continue
                                if self.ptrUnicode    and not "unicode"    in ptr_charset: continue
                                if self.ptrAscii      and not "ascii"      in ptr_charset: continue
                                if self.ptrAsciiPrint and not "asciiprint" in ptr_charset: continue
                                if self.ptrAlphaNum   and not "alphanum"   in ptr_charset: continue
                                if self.ptrNum        and not "numeric"    in ptr_charset: continue
                                if self.ptrAlpha      and not "alpha"      in ptr_charset: continue

                            # Increment the fptr counter

                            # Get pointer disassembly
                            insn_disas = idc.GetDisasmEx(call_ea, idaapi.GENDSM_FORCE_CODE)

                            # Add pointer to the list
                            ptr = Ptr(m.file, ptr_ea, self.ptrOffset, ptr_charset, call_ea, insn_disas)
                            ptrs.append(ptr)

            ###################################################################
            # Cache Pointers to Pointers

            ptr_ea_prefix_cache = dict()

            if self.searchP2P:

                # CACHE: Running repeated searches over the entire memory space is 
                #        very expensive. Let's cache all of the addresses containing
                #        bytes corresponding to discovered function pointers in a
                #        single search and simply reference this cache for each
                #        function pointer. Specifically running idaapi.find_binary()
                #        is much more expensive than idaapi.dbg_read_memory().
                #
                # NOTE:  For performance considerations, the cache works on a per 
                #        module basis, but could be expanded for the entire memory
                #        space.
                #
                # prefix_offset - how many bytes of discovered function
                #        pointers to cache.
                #                 
                #        Example: For function pointers 0x00401234, 0x00404321, 0x000405678
                #        we are going to use prefix_offset 2, so we will cache all of the
                #        values located at addresses 0x0040XXXX

                if self.sploiter.addr64:
                    pack_format   = "<Q"
                    addr_bytes    = 8
                    prefix_offset = 6
                else:
                    pack_format   = "<I"
                    addr_bytes    = 4
                    prefix_offset = 2

                # Set of unique N-byte address prefixes to search in memory
                ea_prefix_set = set()

                for ptr in ptrs:
                    ptr_ea = ptr.ptr_ea

                    ptr_bytes = struct.pack( pack_format, ptr_ea )
                    ptr_bytes = ptr_bytes[-prefix_offset:]

                    ea_prefix_set.add( ptr_bytes)

                # Search the module for all bytes corresponding to the prefix
                # and use them as candidates for pointers-to-pointers

                for ea_prefix in ea_prefix_set:

                    # NOTE: Make sure you search using 44 33 22 11 format and not 11223344
                    ea_prefix_str = " ".join(  ["%02x" % ord(b) for b in ea_prefix]  )

                    # Initialize search parameters for a given module
                    ea = m.addr
                    maxea = m.addr + m.size

                    while True:
                        ea = idaapi.find_binary(ea + 1, maxea, ea_prefix_str, 16, idaapi.SEARCH_DOWN)
                        if ea == idaapi.BADADDR: break

                        p2p_ea = ea - (addr_bytes - prefix_offset)

                        dbg_mem = idaapi.dbg_read_memory(p2p_ea, addr_bytes)
                        ptr_ea_prefix = unpack(pack_format, dbg_mem)[0]

                        if ptr_ea_prefix in ptr_ea_prefix_cache:
                            ptr_ea_prefix_cache[ptr_ea_prefix].add(p2p_ea)
                        else:
                            ptr_ea_prefix_cache[ptr_ea_prefix] = set([p2p_ea,])

                        # Detect search cancellation, but allow the loop below
                        # to run to create already cached/found function pointers

                        # Canceled
                        if breakFlag or idaapi.wasBreak():
                            breakFlag = True
                            break

                    # Canceled
                    if breakFlag or idaapi.wasBreak():
                        breakFlag = True
                        break


            ###################################################################
            # Locate Pointer to Pointers

            for ptr in ptrs:

                ptr_ea = ptr.ptr_ea

                # Locate pointers-to-pointers for a given function pointer in the cache
                if self.searchP2P and ptr_ea in ptr_ea_prefix_cache:

                    for p2p_ea in ptr_ea_prefix_cache[ptr_ea]:

                        # Apply pointer-to-pointer offset
                        p2p_ea -= self.p2pOffset

                        p2p_charset = self.sploiter.get_ptr_charset(p2p_ea)

                        # Filter the pointer
                        if self.filterP2P:
                            if p2p_charset == None:                                    continue
                            if self.ptrNonull     and not "nonull"     in p2p_charset: continue
                            if self.ptrUnicode    and not "unicode"    in p2p_charset: continue
                            if self.ptrAscii      and not "ascii"      in p2p_charset: continue
                            if self.ptrAsciiPrint and not "asciiprint" in p2p_charset: continue
                            if self.ptrAlphaNum   and not "alphanum"   in p2p_charset: continue
                            if self.ptrNum        and not "numeric"    in p2p_charset: continue
                            if self.ptrAlpha      and not "alpha"      in p2p_charset: continue

                        # Copy existing pointer object to modify it for the particular p
                        p2p = copy.copy(ptr)
                        p2p.p2p_ea = p2p_ea
                        p2p.p2p_offset = self.p2pOffset
                        p2p.p2p_charset = p2p_charset

                        # Apppend p2p specific pointer object to the global list
                        self.ptrs.append(p2p)

                        # Exceeded maximum number of pointers
                        if self.maxPtrs and len(self.ptrs) >= self.maxPtrs:
                            breakFlag = True
                            print "[idasploiter] Maximum number of pointers exceeded."
                            break

                # Simply append pointer object to the global list
                else:
                    self.ptrs.append(ptr)

                    # Exceeded maximum number of pointers
                    if self.maxPtrs and len(self.ptrs) >= self.maxPtrs:
                        breakFlag = True
                        print "[idasploiter] Maximum number of pointers exceeded."
                        break

                if breakFlag or idaapi.wasBreak():
                    breakFlag = True
                    break

            # Canceled
            # NOTE: Only works when started from GUI not script.
            if breakFlag or idaapi.wasBreak():
                breakFlag = True
                print "[idasploiter] Canceled."
                break

        print "[idasploiter] Found %d total pointers." % len(self.ptrs)
        idaapi.hide_wait_box()

###############################################################################
# Gadget Class - manages ROP gadget characteristics

class Gadget():

    def __init__(self, instructions, pivot, operations, chg_registers, use_registers):

        self.address = 0x0

        self.module = ""

        self.instructions = instructions
        self.size = len(instructions)

        self.pivot = pivot
        self.operations = operations

        self.chg_registers = chg_registers
        self.use_registers = use_registers

        self.ptr_charset = []

###############################################################################
# ROP Search Engine

class Rop():

    def __init__(self, sploiter):
        
        self.maxRopOffset = 40 # Maximum offset from the return instruction to look for gadgets. default: 40
        self.maxRopSize   = 6  # Maximum number of instructions to look for gadgets. default: 6
        self.maxRetnImm   = 64 # Maximum imm16 value in retn. default: 64
        self.maxJopImm    = 255 # Maximum jop [reg + IMM] value. default: 64
        self.maxRops      = 0  # Maximum number of ROP chains to find. default: 0 (unlimited)

        self.debug        = False

        self.regnames     = idaapi.ph_get_regnames()

        self.sploiter     = sploiter
        self.retns        = list()
        self.gadgets      = list()

        # Decoded instruction cache
        self.insn_cache = dict()

        # Extra bytes to read to ensure correct decoding of
        # RETN, RETN imm16, CALL /2, and JMP /4 instructions.
        self.dbg_read_extra = 6 # FF + ModR/M + SIB + disp32 

        self.insn_arithmetic_ops = ["inc","dec","neg", "add","sub","mul","imul","div","idiv","adc","sbb","lea"]
        self.insn_bit_ops = ["not","and","or","xor","shr","shl","sar","sal","shld","shrd","ror","rcr","rcl"]

    def get_o_reg_name(self, insn, n):

        reg_num = insn.Operands[n].reg
        reg_name = self.regnames[reg_num]

        # NOTE: IDA's x86/x86-64 regname array contains only register root names
        #       (e.g ax,cx,dx,etc.). However we can still figure out exact register
        #       size by looking at the operand 'dtyp' property.
        if reg_num < 8:

            # 32-bit register
            if insn.Operands[n].dtyp == idaapi.dt_dword:
                reg_name = 'e'+reg_name

            # 64-bit register
            elif insn.Operands[n].dtyp == idaapi.dt_qword:
                reg_name = 'r'+reg_name

            # 16-bit register otherwise

        return reg_name

    def search_retns(self):

        for m in self.modules:

            # Iterate over segments in the module
            # BUG: Iterating over all loaded segments is more stable than looking up by address
            for n in xrange(idaapi.get_segm_qty()):
                seg = idaapi.getnseg(n)

                # Locate executable segments in a selected modules
                # NOTE: Each module may have multiple executable segments
                if seg and \
                   seg.startEA >= m.addr and seg.endEA <= (m.addr + m.size) and \
                   seg.perm & idaapi.SEGPERM_EXEC:

                    #######################################################
                    # Search for ROP gadgets
                    if self.searchRop:

                        #Search all instances of RETN 
                        ea = seg.startEA
                        while True:
                            ea = idaapi.find_binary(ea + 1, seg.endEA, "C3", 16, idaapi.SEARCH_DOWN)
                            if ea == idaapi.BADADDR: break
                            self.retns.append( (ea, m.file))

                        # Search all instances of RETN imm16
                        ea = seg.startEA
                        while True:
                            ea = idaapi.find_binary(ea + 1, seg.endEA, "C2", 16, idaapi.SEARCH_DOWN)
                            if ea == idaapi.BADADDR: break

                            # Read imm16 value and filter large values
                            retn_imm16 = idaapi.dbg_read_memory ( ea + 1, 0x2)
                            retn_imm16 = unpack("<H", retn_imm16)[0]

                            if retn_imm16 <= self.maxRetnImm:

                                self.retns.append( (ea, m.file))

                    #######################################################
                    # Search for JOP gadgets
                    if self.searchJop:

                        # Search all instances of JMP reg (FF /4) and CALL reg (FF /2)
                        ea = seg.startEA
                        while True:
                            ea = idaapi.find_binary(ea + 1, seg.endEA, "FF", 16, idaapi.SEARCH_DOWN)
                            if ea == idaapi.BADADDR: break

                            # Read possible ModR/M, SIB, and IMM8/IMM32 bytes
                            jop = idaapi.dbg_read_memory ( ea + 1, 0x6)

                            ###################################################
                            # JMP/CALL reg
                            if jop[0] in ["\xe0","\xe1","\xe2","\xe3","\xe4","\xe5","\xe6","\xe7",
                                          "\xd0","\xd1","\xd2","\xd3","\xd4","\xd5","\xd6","\xd7"]:
                                self.retns.append( (ea, m.file))

                            ###################################################
                            # JMP/CALL [reg] no SIB
                            # NOTE: Do not include pure [disp] instruction.

                            # JMP/CALL [reg] no *SP,*BP
                            elif jop[0] in ["\x20","\x21","\x22","\x23","\x26","\x27", 
                                            "\x10","\x11","\x12","\x13","\x16","\x17"]:
                                self.retns.append( (ea, m.file))

                            # JMP/CALL [reg + imm8] no *SP
                            elif jop[0] in ["\x60","\x61","\x62","\x63","\x65","\x66","\x67",
                                            "\x50","\x51","\x52","\x53","\x55","\x56","\x57"]:
                                jop_imm8 = jop[1]
                                jop_imm8 = unpack("b", jop_imm8)[0] # signed

                                if jop_imm8 <= self.maxJopImm:
                                    self.retns.append( (ea, m.file))


                            # JMP/CALL [reg + imm32] no *SP
                            elif jop[0] in ["\xa0","\xa1","\xa2","\xa3","\xa5","\xa6","\xa7",
                                            "\x90","\x91","\x92","\x93","\x95","\x96","\x97"]:
                                jop_imm32 = jop[1:5]
                                jop_imm32 = unpack("<i", jop_imm32)[0] # signed

                                if jop_imm32 <= self.maxJopImm:
                                    self.retns.append( (ea, m.file))

                            ###################################################
                            # JMP/CALL [reg] with SIB
                            # NOTE: Do no include pure [disp] instructions in SIB ([*] - none)
                            elif (jop[0] in ["\x24","\x64","\xa4"] and not jop[1] in ["\x25","\x65","\xad","\xe5"]) or \
                                 (jop[0] in ["\x14","\x54","\x94"] and not jop[1] in ["\x25","\x65","\xad","\xe5"]):

                                 # Check for displacement
                                if jop[0] in ["\x64","\x54"]:
                                    jop_imm8 = jop[2]
                                    jop_imm8 = unpack("b", jop_imm8)[0] # signed

                                    if jop_imm8 <= self.maxJopImm:
                                        self.retns.append( (ea, m.file))

                                elif jop[0] in ["\xa4","\x94"]:
                                    jop_imm32 = jop[2:6]
                                    jop_imm32 = unpack("<i", jop_imm32)[0] # signed

                                    if jop_imm32 <= self.maxJopImm:
                                        self.retns.append( (ea, m.file))

                                else:
                                    self.retns.append( (ea, m.file))

        print "[idasploiter] Found %d returns" % len(self.retns)

    def search_gadgets(self):

        count_total = len(self.retns)
        count_notify = 0
        count_curr  = 0

        # BUG: A separate flag is used to track user canceling the search,
        #      because multiple calls to idaapi.wasBreak() do not properly
        #      detect cancellations.
        breakFlag = False

        # Show wait dialog
        if not self.debug: idaapi.show_wait_box("Searching gadgets: 00%%%%")

        for (ea_end, module) in self.retns:

            # Flush the gadgets cache for each new retn pointer
            self.gadgets_cache = dict()

            # Flush memory cache for each new retn pointer
            self.dbg_mem_cache = None

            # CACHE: It is faster to read as much memory in one blob than to make incremental reads backwards.
            #        Try to read and cache self.maxRopOffset bytes back. In cases where it is not possible,
            #        then simply try to read the largest chunk.
            
            # NOTE: Read a bit extra to cover correct decoding of RETN, RETN imm16, CALL /2, and JMP /4 instructions.

            for i in range(self.maxRopOffset):
                self.dbg_mem_cache = idaapi.dbg_read_memory(ea_end - self.maxRopOffset + i, self.maxRopOffset - i + self.dbg_read_extra)
                if self.dbg_mem_cache != None:
                    break

            # Search all possible gadgets up to maxoffset bytes back
            # NOTE: Try all byte combinations to capture longer/more instructions
            #       even with bad bytes in the middle.
            for i in range(1, len(self.dbg_mem_cache) - self.dbg_read_extra):

                ea = ea_end - i

                # Get pointer charset
                ptr_charset = self.sploiter.get_ptr_charset(ea)

                # Filter the pointer
                if ptr_charset == None:                                    continue
                if self.ptrNonull     and not "nonull"     in ptr_charset: continue
                if self.ptrUnicode    and not "unicode"    in ptr_charset: continue
                if self.ptrAscii      and not "ascii"      in ptr_charset: continue
                if self.ptrAsciiPrint and not "asciiprint" in ptr_charset: continue
                if self.ptrAlphaNum   and not "alphanum"   in ptr_charset: continue
                if self.ptrNum        and not "numeric"    in ptr_charset: continue
                if self.ptrAlpha      and not "alpha"      in ptr_charset: continue

                # Try to build a gadget at the pointer
                gadget = self.build_gadget(ea, ea_end)

                # Successfully built the gadget
                if gadget:

                    # Populate gadget object with more data
                    gadget.address = ea
                    gadget.module = module
                    gadget.ptr_charset = ptr_charset

                    # Filter gadgets with too many instruction
                    if gadget.size > self.maxRopSize: 
                        break

                    # Append newly built gadget
                    self.gadgets.append(gadget)
                    self.gadgets_cache[ea] = gadget

                    # Exceeded maximum number of gadgets
                    if self.maxRops and len(self.gadgets) >= self.maxRops:
                        breakFlag = True
                        print "[idasploiter] Maximum number of gadgets exceeded."
                        break
                else:
                    self.gadgets_cache[ea] = None

                if breakFlag or idaapi.wasBreak():
                    breakFlag = True
                    break

            # Canceled
            # NOTE: Only works when started from GUI not script.
            if breakFlag or idaapi.wasBreak():
                breakFlag = True
                print "[idasploiter] Canceled."
                break

            # Progress report
            if not self.debug and count_curr >= count_notify:

                # NOTE: Need to use %%%% to escape both Python and IDA's format strings
                idaapi.replace_wait_box("Searching gadgets: %02d%%%%" % (count_curr*100/count_total) ) 

                count_notify += 0.10 * count_total

            count_curr += 1            

        print "[idasploiter] Found %d gadgets." % len(self.gadgets)
        if not self.debug: idaapi.hide_wait_box()


    # Attempt to build a gadget at the provided start address
    # by verifying it properly terminates at the expected RETN.
    def build_gadget(self, ea, ea_end):

        instructions  = list()
        chg_registers = set()
        use_registers = set()
        operations    = set()
        pivot         = 0

        # Process each instruction in the gadget
        while ea <= ea_end:

            ###################################################################
            # Gadget Level Cache:
            #
            # Locate a gadget (failed or built) starting at this address.
            # If one is located, then we don't need to process any further
            # instructions and just get necessary data from the cached
            # gadget to never have to process the same address twice.
            if ea in self.gadgets_cache:

                # Check if the gadget was build successfully
                gadget_cache = self.gadgets_cache[ea]
                
                # Build the reset of the gadget from cache
                if gadget_cache:    

                    for insn in gadget_cache.instructions:
                        instructions.append(insn)

                    for reg in gadget_cache.chg_registers:
                        chg_registers.add(reg)

                    for reg in gadget_cache.use_registers:
                        use_registers.add(reg)

                    for op in gadget_cache.operations:
                        operations.add(op)

                    pivot += gadget_cache.pivot

                    gadget = Gadget(instructions, pivot, operations, chg_registers, use_registers)
                    return gadget

                # Previous attempt to build gadget at this address failed
                else:
                    return None

            # Process new instruction
            else:

                # Instruction length
                # NOTE: decode_insn also sets global idaapi.cmd
                #       which contains insn_t structure
                insn_size = idaapi.decode_insn(ea)

                # Check successful decoding of the instruction
                if insn_size:

                    # Decoded instruction is too big to be a RETN or RETN imm16
                    if ea + insn_size > ea_end + self.dbg_read_extra:
                        return None

                    ###############################################################
                    # Instruction Level Cache
                    #
                    # Most instructions are repetitive so we can just cache
                    # unique byte combinations to avoid costly decoding more
                    # than once
                    
                    # Read instruction from memory cache
                    dbg_mem_offset = ea - (ea_end - (len(self.dbg_mem_cache) - self.dbg_read_extra) )
                    dbg_mem = self.dbg_mem_cache[dbg_mem_offset:dbg_mem_offset + insn_size]

                    # Create instruction cache if it doesn't already exist
                    if not dbg_mem in self.insn_cache:

                        ###########################################################
                        # Decode instruction
                        ###########################################################

                        # Get global insn_t structure describing the instruction
                        # NOTE: copy() is expensive, so we keep this single-threaded
                        insn = idaapi.cmd                  

                        #######################################################
                        # Decode and Cache instruction characteristics
                        self.insn_cache[dbg_mem] = self.decode_instruction(insn, ea, ea_end)

                    ##################################################################
                    # Retrieve cached instruction and apply it to the gadget    

                    # Check that cached instruction contains valid data
                    if self.insn_cache[dbg_mem]:

                        # Retrieve basic instruction characteristics
                        insn_mnem = self.insn_cache[dbg_mem]["insn_mnem"]
                        insn_disas = self.insn_cache[dbg_mem]["insn_disas"]
                        instructions.append(insn_disas)

                        #######################################################
                        # Expected ending instruction of the gadget
                        if ea == ea_end:
                            gadget = Gadget(instructions, pivot, operations, chg_registers, use_registers)
                            return gadget

                        #######################################################
                        # Filter out of place ROP/JOP/COP terminators
                        # NOTE: retn/jmp/call are allowed, but only in the last position

                        # Unexpected return instruction
                        elif insn_mnem == "retn":
                            return None

                        # Unexpected call/jmp instruction
                        elif insn_mnem in ["jmp","call"]:
                            return None

                        #######################################################
                        # Add instruction instruction characteristics to the gadget
                        else:

                            for reg in self.insn_cache[dbg_mem]["insn_chg_registers"]:
                                chg_registers.add(reg)

                            for reg in self.insn_cache[dbg_mem]["insn_use_registers"]:
                                use_registers.add(reg)

                            for op in self.insn_cache[dbg_mem]["insn_operations"]:
                                operations.add(op)

                            pivot += self.insn_cache[dbg_mem]["insn_pivot"]

                    # Previous attempt to decode the instruction invalidated the gadget
                    else:                        
                        return None
                        
                    ###############################################################
                    # Next instruction
                    # NOTE: This is outside cache
                    ea += insn_size

                ###################################################################
                # Failed decoding of the instruction
                # NOTE: Gadgets may have bad instructions in the middle which
                #       can be tolerated as long as we can find a useful instruction
                #       further out.
                else:

                    # HACK: IDA does not disassemble "\x00\x00" unless you enable
                    #       "Disassemble zero opcode instructions" in Processor Options.
                    #       Since this option is normally disabled, I will attempt
                    #       to get this instruction manually.

                    # Read two bytes from memory cache at current instruction candidate
                    dbg_mem_offset = ea - (ea_end - self.maxRopOffset)
                    dbg_mem = self.dbg_mem_cache[dbg_mem_offset:dbg_mem_offset + 2]

                    # Compare to two zero bytes
                    if dbg_mem[:2] == "\x00\x00":

                        if self.sploiter.addr64:
                            instructions.append("add [rax],al")
                        else:
                            instructions.append("add [eax],al")

                        use_registers.add("al")
                        operations.add("reg-to-mem")

                        ea += 2

                    # "MOV Sreg, r/m16" instructions will result in illegal instruction exception: c000001d
                    # or the memory couldn't be read exception: c0000005 which we don't want in our gadgets.
                    elif dbg_mem[0] == "\x8E":
                        return None

                    # Record a "bad byte" if allowed
                    elif dbg_mem and not self.ropNoBadBytes:
                        byte = dbg_mem[0]

                        instructions.append("db %sh" % binascii.hexlify(byte))

                        ea += 1

                    # Invalidate the gadget
                    else:
                        return None

        # Failed to build a gadget, because RETN instruction was not found
        else:    
            return None

    ###############################################################
    # Decode instruction

    def decode_instruction(self, insn, ea, ea_end):

        # Instruction specific characteristics
        insn_chg_registers = set()
        insn_use_registers = set()
        insn_operations = set()
        insn_pivot = 0

        # Instruction feature
        #
        # instruc_t.feature
        #
        # CF_STOP = 0x00001 #  Instruction doesn't pass execution to the next instruction
        # CF_CALL = 0x00002 #  CALL instruction (should make a procedure here)
        # CF_CHG1 = 0x00004 #  The instruction modifies the first operand
        # CF_CHG2 = 0x00008 #  The instruction modifies the second operand
        # CF_CHG3 = 0x00010 #  The instruction modifies the third operand
        # CF_CHG4 = 0x00020 #  The instruction modifies 4 operand
        # CF_CHG5 = 0x00040 #  The instruction modifies 5 operand
        # CF_CHG6 = 0x00080 #  The instruction modifies 6 operand
        # CF_USE1 = 0x00100 #  The instruction uses value of the first operand
        # CF_USE2 = 0x00200 #  The instruction uses value of the second operand
        # CF_USE3 = 0x00400 #  The instruction uses value of the third operand
        # CF_USE4 = 0x00800 #  The instruction uses value of the 4 operand
        # CF_USE5 = 0x01000 #  The instruction uses value of the 5 operand
        # CF_USE6 = 0x02000 #  The instruction uses value of the 6 operand
        # CF_JUMP = 0x04000 #  The instruction passes execution using indirect jump or call (thus needs additional analysis)
        # CF_SHFT = 0x08000 #  Bit-shift instruction (shl,shr...)
        # CF_HLL  = 0x10000 #  Instruction may be present in a high level language function.
        insn_feature = insn.get_canon_feature()

        # Instruction mnemonic name
        insn_mnem = insn.get_canon_mnem()

        #if insn_mnem in self.mnems: self.mnems[insn_mnem] += 1
        #else:                       self.mnems[insn_mnem]  = 1

        # Get instruction operand types
        #
        # op_t.type
        #                    Description                          Data field
        # o_void     =  0 #  No Operand                           ----------
        # o_reg      =  1 #  General Register (al,ax,es,ds...)    reg
        # o_mem      =  2 #  Direct Memory Reference  (DATA)      addr
        # o_phrase   =  3 #  Memory Ref [Base Reg + Index Reg]    phrase
        # o_displ    =  4 #  Memory Reg [Base Reg + Index Reg + Displacement] phrase+addr
        # o_imm      =  5 #  Immediate Value                      value
        # o_far      =  6 #  Immediate Far Address  (CODE)        addr
        # o_near     =  7 #  Immediate Near Address (CODE)        addr
        insn_op1 = insn.Operands[0].type
        insn_op2 = insn.Operands[1].type

        ###############################################################
        # Filter gadget
        ###############################################################

        # Do not filter ROP, JOP, COP, always decode them
        # NOTE: A separate check must be done to check if they are out of place.
        if not insn_mnem in ["retn","jmp","call"]:

            # Filter gadgets with instructions that don't forward execution to the next address
            if insn_feature & idaapi.CF_STOP:
                return None

            # Filter gadgets with instructions in a bad list
            elif insn_mnem in self.ropBadMnems:
                return None

            # Filter gadgets with jump instructions
            # Note: conditional jumps may still be useful if we can
            #       set flags prior to calling them.
            elif not self.ropAllowJcc and insn_mnem[0] == "j":
                return None

        ###############################################################
        # Get disassembly
        ###############################################################
        # NOTE: GENDSM_FORCE_CODE ensures correct decoding
        #       of split instructions.
        insn_disas = idc.GetDisasmEx(ea, idaapi.GENDSM_FORCE_CODE)                
        insn_disas = insn_disas.partition(';')[0]       # Remove comments from disassembly                       
        insn_disas = ' '.join(insn_disas.split())       # Remove extraneous space from disassembly

        ###############################################################
        # Analyze instruction
        ###############################################################

        # Standalone instruction
        if insn_op1 == idaapi.o_void:

            # TODO: Determine and test how these instructions affect the stack
            #       in 32-bit and 64-bit modes.
            if insn_mnem in ["pusha","pushad","popa","popad","pushf","pushfd","pushfq","popf","popfd","popfq"]:
                insn_operations.add("stack")

                if insn_mnem in ["popa","popad"]:
                    insn_pivot += 7*4
                elif insn_mnem in ["pusha","pushad"]:
                    insn_pivot -= 8*4
                elif insn_mnem in ["popf","popfd"]:
                    insn_pivot += 4
                elif insn_mnem in ["pushf","pushfd"]:
                    insn_pivot -= 4
                elif insn_mnem == "popfq":  # TODO: Needs testing
                    insn_pivot += 8
                elif insn_mnem == "pushfq": # TODO: Needs testing
                    insn_pivot -= 8

        # Single operand instruction
        elif insn_op2 == idaapi.o_void:

            # Single operand register
            if insn_op1 == idaapi.o_reg:
                insn_operations.add("one-reg")

                if insn_feature & idaapi.CF_CHG1:
                    reg_name = self.get_o_reg_name(insn, 0)
                    insn_chg_registers.add(reg_name)

                    # Check for stack operation
                    if reg_name[1:] == "sp":
                        insn_operations.add("stack")

                        if insn_mnem == "inc":
                            insn_pivot += 1

                        elif insn_mnem == "dec":
                            insn_pivot -= 1

                elif insn_feature & idaapi.CF_USE1:
                    reg_name = self.get_o_reg_name(insn, 0)
                    insn_use_registers.add(reg_name)

            # Single operand immediate
            elif insn_op1 == idaapi.o_imm:
                insn_operations.add("one-imm")

            # Single operand reference
            # TODO: determine the [reg + ...] value if present
            elif insn_op1 == idaapi.o_phrase or insn_op1 == idaapi.o_displ:
                insn_operations.add("one-mem")

            # PUSH/POP mnemonic with a any operand type
            if insn_mnem in ["push","pop"]:
                insn_operations.add("stack")

                # Adjust pivot based on operand size (32bit vs 64bit)
                if insn_mnem == "pop":
                    if   insn.Operands[0].dtyp == idaapi.dt_dword: insn_pivot += 4
                    elif insn.Operands[0].dtyp == idaapi.dt_qword: insn_pivot += 8
                elif insn_mnem == "push":                   
                    if   insn.Operands[0].dtyp == idaapi.dt_dword: insn_pivot -= 4
                    elif insn.Operands[0].dtyp == idaapi.dt_qword: insn_pivot -= 8

            # Check for arithmetic operation:
            if insn_mnem in self.insn_arithmetic_ops:
                insn_operations.add("math")

            # Check for bit-wise operations:
            if insn_mnem in self.insn_bit_ops:
                insn_operations.add("bit")

        # Two operand instruction
        else:

            # Check for arithmetic operations
            if insn_mnem in self.insn_arithmetic_ops:
                insn_operations.add("math")

            # Check for bit-wise operations
            if insn_mnem in self.insn_bit_ops:
                insn_operations.add("bit")

            # Two operand instruction with the first operand a register
            if insn_op1 == idaapi.o_reg:

                reg_name = self.get_o_reg_name(insn, 0)

                if insn_feature & idaapi.CF_CHG1:
                    insn_chg_registers.add(reg_name)

                    # Check for stack operation
                    if reg_name[1:] == "sp":
                        insn_operations.add("stack")

                        # Determine stack pivot distance
                        if insn_op2 == idaapi.o_imm:

                            # NOTE: adb and sbb may also be useful, but let the user
                            #       determine their use by locating the operations "stack"
                            if insn_mnem == "add":
                                insn_pivot += insn.Operands[1].value

                            elif insn_mnem == "sub":
                                insn_pivot -= insn.Operands[1].value

                    # Check for operations
                    if insn_op2 == idaapi.o_reg:
                        insn_operations.add("reg-to-reg")
                    elif insn_op2 == idaapi.o_imm:
                        insn_operations.add("imm-to-reg")

                    # TODO: determine the [reg + ...] value if present
                    elif insn_op2 == idaapi.o_phrase or insn_op2 == idaapi.o_displ:
                        insn_operations.add("mem-to-reg")

                if insn_feature & idaapi.CF_USE1:
                    insn_use_registers.add(reg_name)


            # Two operand instruction with the second operand a register
            if insn_op2 == idaapi.o_reg:

                reg_name = self.get_o_reg_name(insn, 1)

                if insn_feature & idaapi.CF_CHG2:
                    insn_chg_registers.add(reg_name)

                    # Check for stack operation
                    if reg_name[1:] == "sp":
                        insn_operations.add("stack")

                if insn_feature & idaapi.CF_USE2:
                    insn_use_registers.add(reg_name)

                # Check for operations
                # TODO: determine the [reg + ...] value if present
                if insn_op1 == idaapi.o_phrase or insn_op1 == idaapi.o_displ:
                    insn_operations.add("reg-to-mem")

        # Build instruction dictionary
        insn = dict()
        insn["insn_mnem"] = insn_mnem
        insn["insn_disas"] = insn_disas
        insn["insn_operations"] = insn_operations
        insn["insn_chg_registers"] = insn_chg_registers
        insn["insn_use_registers"] = insn_use_registers
        insn["insn_pivot"] = insn_pivot

        return insn

###############################################################################
# Sploiter Engine

class Sploiter():

    def __init__(self):
        


        # Process modules list
        self.modules = list()
        self.rop     = None
        self.funcptr = None

        # Default patterns
        self.c4_list = string.punctuation
        self.c3_list = string.uppercase
        self.c2_list = string.lowercase
        self.c1_list = string.digits

        if not idaapi.ph.id == idaapi.PLFM_386:
            print "[idasploiter] Only Intel 80x86 processors are supported."
            sys.exit(1)

        # Check if processor supports 64-bit addressing
        if idaapi.ph.flag & idaapi.PR_USE64:
            self.addr64 = True
            self.addr_format = "%016X"
            self.pack_format_be = ">Q"
            self.pack_format_le = "<Q"
        else:
            self.addr64 = False
            self.addr_format = "%08X"
            self.pack_format_be = ">I"
            self.pack_format_le = "<I"

    def get_ptr_charset(self, ea):

        ptr_charset = []

        # Flags. True until proven otherwise.
        nonull     = True
        unicode    = True
        ascii      = True
        asciiprint = True        
        alphanum   = True
        alpha      = True
        numeric    = True
        
        ptr_bytes = pack(self.pack_format_be, ea)
        for i,b in enumerate( ptr_bytes ):

            b_int = ord(b)

            if b in self.ptrBadChars:
                return None

            # Locate any null bytes
            if nonull and b == "\x00":
                nonull = False

            # Unicode compatible address must have
            # null bytes at even points in the address
            if unicode and not i % 2:

                if not ptr_bytes[i:i+2] in ASCII_TO_UNICODE[ self.unicodeTable ]:
                    unicode = False

            # Find any non-ascii characters
            if ascii and not b_int > 127:

                # Find any non-ascii printable characters
                if asciiprint and not (b_int < 32 or b_int > 126):

                    # Find any non-alphanumeric characters
                    if alphanum and (b in string.ascii_letters or b in string.digits):

                        # Find any non-numeric characters
                        if numeric and not b in string.digits:
                            numeric = False

                        # Find any non-letter characters
                        if alpha and not b in string.ascii_letters:
                            alpha = False
                    else:                        
                        alphanum = False
                        numeric  = False
                        alpha     = False
                else:                    
                    asciiprint = False
                    alphanum   = False
                    numeric    = False
                    alpha      = False
            else:                
                ascii      = False
                asciiprint = False
                alphanum   = False
                numeric    = False
                alpha      = False

                # NOTE: You can continue to filter for upper/lower here if necessary
        
        if nonull:     ptr_charset.append("nonull")

        if unicode:    ptr_charset.append("unicode")

        if ascii:      
            ptr_charset.append("ascii")

            if asciiprint: 
                ptr_charset.append("asciiprint")

                if alphanum:   
                    ptr_charset.append("alphanum")

                    if numeric:    ptr_charset.append("numeric")
                    if alpha:      ptr_charset.append("alpha")
        

        return ptr_charset  

    def process_modules(self):

        # Reset modules list
        self.modules = list()

        for m in idautils.Modules():

            module = Module(m.name, m.size, m.base, m.rebase_to)
            self.modules.append(module)

    def show_modules_view(self):
        mod = ModuleView(self)
        mod.show()

    def process_rop(self, select_list = None):

        # Initialize ROP gadget search engine
        self.rop = Rop(self)

        # Prompt user for ROP search settings
        f = RopForm(self, select_list)
        ok = f.Execute()
        if ok == 1:

            # Configure ROP gadget search engine

            # Get selected modules
            self.rop.modules = [self.modules[i] for i in f.mod.GetEmbSelection()]

            if len(self.rop.modules) > 0:

                # Pointer filters
                self.rop.ptrNonull     = f.cPtrNonull.checked
                self.rop.ptrUnicode    = f.cPtrUnicode.checked
                self.rop.ptrAscii      = f.cPtrAscii.checked
                self.rop.ptrAsciiPrint = f.cPtrAsciiPrint.checked
                self.rop.ptrAlphaNum   = f.cPtrAlphaNum.checked
                self.rop.ptrAlpha      = f.cPtrAlpha.checked
                self.rop.ptrNum        = f.cPtrNum.checked

                # Filter bad characters
                buf                    = f.strBadChars.value
                buf = buf.replace(' ','')         # remove spaces
                buf = buf.replace('\\x','')       # remove '\x' prefixes
                buf = buf.replace('0x','')        # remove '0x' prefixes
                try:
                    buf = binascii.unhexlify(buf) # convert to bytes
                    self.ptrBadChars   = buf
                except Exception, e:
                    idaapi.warning("Invalid input: %s" % e)
                    self.ptrBadChars   = ""

                # Ascii_to_Unicode_transformation table
                # BUG: DropdownControl does not work on IDA 6.5
                self.unicodeTable      = f.radUnicode.value

                # ROP instruction filters
                self.rop.ropBadMnems   = [mnem.strip().lower() for mnem in f.strBadMnems.value.split(',')]
                self.rop.ropAllowJcc   = f.cRopAllowJcc.checked
                self.rop.ropNoBadBytes = f.cRopNoBadBytes.checked

                # Get ROP engine settings
                self.rop.maxRopSize    = f.intMaxRopSize.value
                self.rop.maxRopOffset  = f.intMaxRopOffset.value
                self.rop.maxRops       = f.intMaxRops.value
                self.rop.maxRetnImm    = f.intMaxRetnImm.value

                # Gadget search values
                self.rop.searchRop     = f.cRopSearch.checked
                self.rop.searchJop     = f.cJopSearch.checked

                # Search for returns and ROP gadgets
                self.rop.search_retns()
                self.rop.search_gadgets()

                # Show the ROP gadgets view
                ropView = RopView(self)
                ropView.show()

            else:
                idaapi.warning("No modules selected.")

        f.Free()

    def process_funcptr(self, select_list = None):

        # Prompt user for function pointer search settings
        f = PtrForm(self, select_list)
        ok = f.Execute()
        if ok == 1:

            # Initialize Function Pointer search engine
            self.funcptr = FuncPtr(self)

            # Configure Function Pointer search engine

            # Get selected modules
            self.funcptr.modules = [self.modules[i] for i in f.mod.GetEmbSelection()]

            if len(self.funcptr.modules) > 0:

                # Pointer filters
                self.funcptr.ptrNonull     = f.cPtrNonull.checked
                self.funcptr.ptrUnicode    = f.cPtrUnicode.checked
                self.funcptr.ptrAscii      = f.cPtrAscii.checked
                self.funcptr.ptrAsciiPrint = f.cPtrAsciiPrint.checked
                self.funcptr.ptrAlphaNum   = f.cPtrAlphaNum.checked
                self.funcptr.ptrAlpha      = f.cPtrAlpha.checked
                self.funcptr.ptrNum        = f.cPtrNum.checked

                # Apply pointer filters to the funcptr or ptr-to-ptr
                if f.rFilterP2P.selected:
                    self.funcptr.filterP2P = True
                else:
                    self.funcptr.filterP2P = False

                # Ascii_to_Unicode_transformation table
                # BUG: DropdownControl does not work on IDA 6.5
                self.unicodeTable      = f.radUnicode.value

                # Filter bad characters
                buf                    = f.strBadChars.value
                buf = buf.replace(' ','')         # remove spaces
                buf = buf.replace('\\x','')       # remove '\x' prefixes
                buf = buf.replace('0x','')        # remove '0x' prefixes
                try:
                    buf = binascii.unhexlify(buf) # convert to bytes
                    self.ptrBadChars = buf
                except Exception, e:
                    idaapi.warning("Invalid input: %s" % e)
                    self.ptrBadChars = ""

                # Offsets
                self.funcptr.ptrOffset = int(f.intPtrOffset.value, 16)
                self.funcptr.p2pOffset = int(f.intP2POffset.value, 16)

                # Pointer search engine settings
                self.funcptr.searchP2P = not f.rSearchPtrOnly.checked
                self.funcptr.maxPtrs   = f.intMaxPtrs.value

                # Search for writable pointers
                self.funcptr.search_pointers()

                # Show the writable pointers view
                ptrView = PtrView(self)
                ptrView.show()

            else:
                idaapi.warning("No modules selected.")

        f.Free()

    def pattern_create(self):

        f = PatternCreateForm(self)
        ok = f.Execute()
        if ok == 1:  
            pass

        f.Free()

    def pattern_detect(self, debugger=True):

        f = PatternDetectForm(self, debugger)
        ok = f.Execute()
        if ok == 1:  
            pass

        f.Free()

    def process_compare(self, debugger=True):

        f = CompareForm(self, debugger)
        ok = f.Execute()
        if ok == 1:
            pass

        f.Free()


###############################################################################
# Sploiter UI
###############################################################################

###############################################################################
# Module UI
###############################################################################

class ModuleView(Choose2):
    """
    Chooser class to display security characteristics of loaded modules.
    """
    def __init__(self, sploiter, embedded = False):

        self.sploiter = sploiter

        Choose2.__init__(self,
                         "Modules",
                         [ ["Address",  13 | Choose2.CHCOL_HEX], 
                           ["Name",     10 | Choose2.CHCOL_PLAIN], 
                           ["Size",     10 | Choose2.CHCOL_HEX],
                           ["SafeSEH",   6 | Choose2.CHCOL_PLAIN],
                           ["ASLR",      6 | Choose2.CHCOL_PLAIN], 
                           ["DEP",       6 | Choose2.CHCOL_PLAIN],
                           ["Canary",    6 | Choose2.CHCOL_PLAIN],
                           ["Path",     40 | Choose2.CHCOL_PLAIN], 
                         ],
                         flags = Choose2.CH_MULTI,  # Select multiple modules
                         embedded=embedded)

        self.icon = 150

        # Items for display
        self.items = list()

        # Initialize/Refresh the view
        self.refreshitems()

        # Selected items
        self.select_list = list()

        # Command callbacks
        self.cmd_load_module     = None
        self.cmd_search_gadgets  = None
        self.cmd_search_pointers = None

    def show(self):
        # Attempt to open the view
        if self.Show() < 0: return False

        # Add extra context menu commands
        # NOTE: Make sure you check for duplicates
        if self.cmd_load_module == None:
            self.cmd_load_module = self.AddCommand("Load module...", flags = idaapi.CHOOSER_POPUP_MENU, icon=135)
        if self.cmd_search_gadgets == None:
            self.cmd_search_gadgets = self.AddCommand("Search gadgets...", flags = idaapi.CHOOSER_POPUP_MENU | idaapi.CHOOSER_MULTI_SELECTION, icon=182 )
        if self.cmd_search_pointers == None:
            self.cmd_search_pointers = self.AddCommand("Search function pointers...", flags = idaapi.CHOOSER_POPUP_MENU | idaapi.CHOOSER_MULTI_SELECTION, icon=143 )


        return True

    def refreshitems(self):
        self.items = list()

        for m in self.sploiter.modules:
            self.items.append([ self.sploiter.addr_format % m.addr, 
                                m.file, 
                                "%08X" % m.size,
                                m.SafeSEH, m.ASLR,
                                m.NXCompat,
                                m.GS,
                                m.path])

    def OnCommand(self, n, cmd_id):

        # Search ROP gadgets
        if cmd_id == self.cmd_search_gadgets:

            # Empty selection
            if n == -1:

                # Initialize ROP gadget form with empty selection
                self.sploiter.process_rop(select_list = self.select_list)

            # Selection start
            elif n == -2:
                self.select_list = list()

            # Selection end
            elif n == -3:

                # Initialize ROP gadget form with user selection
                self.sploiter.process_rop(select_list = self.select_list)
                self.select_list = list()

            # Selection number
            else:
                self.select_list.append(n)

        # Search function pointers
        elif cmd_id == self.cmd_search_pointers:

            # Empty selection
            if n == -1:

                # Initialize function pointers form with empty selection
                self.sploiter.process_funcptr(select_list = self.select_list)

            # Selection start
            elif n == -2:
                self.select_list = list()

            # Selection end
            elif n == -3:

                # Initialize function pointers form with user selection
                self.sploiter.process_funcptr(select_list = self.select_list)
                self.select_list = list()

            # Selection number
            else:
                self.select_list.append(n)

        elif cmd_id == self.cmd_load_module:

            module_name = idaapi.askfile_c(0, "*.*", "Please select module to load")
            if module_name:
                print "[idasploiter] Loading module: %s" % module_name     
                loadlib = idaapi.Appcall.proto("kernel32_LoadLibraryA", "int __stdcall loadlib(const char *fn);")
                hmod = loadlib(module_name)
                if hmod:
                    print "[idasploiter] Finished loading module: %s" % module_name
                else:
                    print "[idasploiter] Could not load: %s" % module_name

                self.refreshitems()

        return 1

    def OnSelectLine(self, n):
        pass

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetIcon(self, n):

        if not len(self.items) > 0:
            return -1

        m = self.sploiter.modules[n]
        if m.SafeSEH != "No" and m.ASLR == "Yes" and m.NXCompat == "Yes" and m.GS != "No":
            return 61
        elif m.ASLR == "Yes":
            return 60
        else:
            return 59

    def OnClose(self):
        self.cmd_search_gadgets = None
        self.cmd_search_pointers    = None

    def OnGetSize(self):
        return len(self.items)

    def OnRefresh(self, n):
        self.refreshitems()
        return n

    def OnActivate(self):
        self.refreshitems()

###############################################################################
# ROP UI
###############################################################################

###############################################################################
# ROP/JOP/COP Form

class RopForm(Form):

    def __init__(self, sploiter, select_list = None):

        self.sploiter = sploiter
        self.select_list = select_list

        self.mod = ModuleView(self.sploiter, embedded=True)

        Form.__init__(self, 
r"""BUTTON YES* Search
Search ROP gadgets

{FormChangeCb}<Modules:{cEChooser}>

Pointer Charset:                  Search Settings:
<nonull:{cPtrNonull}>        <Bad Chars        :{strBadChars}>     
<unicode:{cPtrUnicode}>       Unicode Table    <ANSI:{rUnicodeANSI}><OEM:{rUnicodeOEM}><UTF7:{rUnicodeUTF7}><UTF8:{rUnicodeUTF8}>{radUnicode}>
<ascii:{cPtrAscii}>         <Bad Instructions :{strBadMnems}>
<asciiprint:{cPtrAsciiPrint}>    <Max gadget size  :{intMaxRopSize}>
<alphanum:{cPtrAlphaNum}>      <Max gadget offset:{intMaxRopOffset}>
<alpha:{cPtrAlpha}>         <Max RETN imm16   :{intMaxRetnImm}>
<numeric:{cPtrNum}>{ptrGroup}>       <Max JOP imm8/32  :{intMaxJopImm}>
                <Max gadgets      :{intMaxRops}>
                Other settings   <Allow conditional jumps:{cRopAllowJcc}>
                <Do not allow bad bytes:{cRopNoBadBytes}>
                <Search for ROP gadgets:{cRopSearch}>
                <Search for JOP gadgets:{cJopSearch}>{ropGroup}>


""", {
                'cEChooser'       : Form.EmbeddedChooserControl(self.mod, swidth=131),
                'ptrGroup'        : Form.ChkGroupControl(("cPtrNonull", "cPtrAscii", "cPtrAsciiPrint", "cPtrUnicode",'cPtrAlphaNum','cPtrAlpha','cPtrNum')),
                'ropGroup'        : Form.ChkGroupControl(('cRopAllowJcc','cRopNoBadBytes','cRopSearch','cJopSearch')),
                'intMaxRopSize'   : Form.NumericInput(swidth=4,tp=Form.FT_DEC,value=self.sploiter.rop.maxRopSize),
                'intMaxRopOffset' : Form.NumericInput(swidth=4,tp=Form.FT_DEC,value=self.sploiter.rop.maxRopOffset),
                'intMaxRops'      : Form.NumericInput(swidth=4,tp=Form.FT_DEC,value=self.sploiter.rop.maxRops),
                'intMaxRetnImm'   : Form.NumericInput(swidth=4,tp=Form.FT_HEX,value=self.sploiter.rop.maxRetnImm),
                'intMaxJopImm'    : Form.NumericInput(swidth=4,tp=Form.FT_HEX,value=self.sploiter.rop.maxJopImm),
                'strBadChars'     : Form.StringInput(swidth=70,tp=Form.FT_ASCII),
                'radUnicode'      : Form.RadGroupControl(("rUnicodeANSI","rUnicodeOEM","rUnicodeUTF7","rUnicodeUTF8")),
                'strBadMnems'     : Form.StringInput(swidth=80,tp=Form.FT_ASCII,value="leave, int, into, enter, syscall, sysenter, sysexit, sysret, in, out, loop, loope, loopne, lock, rep, repe, repz, repne, repnz"),
                'FormChangeCb'    : Form.FormChangeCb(self.OnFormChange),
            })

        self.Compile()

    def OnFormChange(self, fid):

        # Form initialization
        if fid == -1:
            self.SetFocusedField(self.cEChooser)

            # Preselect non-ASLR modules on startup if none were already specified
            if self.select_list == None:

                self.select_list = list()
                for i, m in enumerate(self.sploiter.modules):
                    if m.ASLR == "No":
                        self.select_list.append(i)

            self.SetControlValue(self.cEChooser, self.select_list)

            # Enable both ROP and JOP search by default
            self.SetControlValue(self.cRopSearch, True)
            self.SetControlValue(self.cJopSearch, True)

            # Skip bad instructions by default
            self.SetControlValue(self.cRopNoBadBytes, True)

        # Form OK pressed
        elif fid == -2:
            pass

        return 1

###############################################################################
# ROP Viewer

class RopView(Choose2):
    """
    Chooser class to display security characteristics of loaded modules.
    """
    def __init__(self, sploiter):

        self.sploiter = sploiter

        Choose2.__init__(self,
                         "ROP gadgets",
                         [ ["Address",           13 | Choose2.CHCOL_HEX], 
                           ["Gadget",            30 | Choose2.CHCOL_PLAIN], 
                           ["Module",            10 | Choose2.CHCOL_PLAIN],
                           ["Size",               3 | Choose2.CHCOL_DEC],
                           ["Pivot",              4 | Choose2.CHCOL_DEC],
                           ["Operations",         12 | Choose2.CHCOL_PLAIN],
                           ["Changed Registers", 12 | Choose2.CHCOL_PLAIN],
                           ["Used Registers",    12 | Choose2.CHCOL_PLAIN],
                           ["Charset",           12 | Choose2.CHCOL_PLAIN],
                         ],
                         flags = Choose2.CH_MULTI)

        self.icon = 182

        # Items for display
        self.items = []

        # Initialize/Refresh the view
        self.refreshitems()

        # Selected items
        self.gadget_chain = list()

        # Command callbacks
        self.cmd_chain_add   = None
        self.cmd_chain_build = None
        self.cmd_chain_clear = None
        self.cmd_export_csv  = None


    def show(self):
        # Attempt to open the view
        if self.Show() < 0: return False

        if self.cmd_chain_add == None:
            self.cmd_chain_add   = self.AddCommand("Add to chain",     flags = idaapi.CHOOSER_POPUP_MENU | idaapi.CHOOSER_MULTI_SELECTION, icon=50)
        if self.cmd_chain_build == None:
            self.cmd_chain_build = self.AddCommand("Build chain",      flags = idaapi.CHOOSER_POPUP_MENU, icon=156)
        if self.cmd_chain_clear == None:
            self.cmd_chain_clear = self.AddCommand("Clear chain",      flags = idaapi.CHOOSER_POPUP_MENU, icon=32)
        if self.cmd_export_csv == None:
            self.cmd_export_csv  = self.AddCommand("Export as csv...", flags = idaapi.CHOOSER_POPUP_MENU, icon=40)

        return True

    def refreshitems(self):
        self.items = []

        for g in self.sploiter.rop.gadgets:

            self.items.append([ self.sploiter.addr_format % g.address, 
                                " # ".join(g.instructions), 
                                g.module, 
                                "%d" % g.size, 
                                "%d" % g.pivot, 
                                ", ".join(g.operations), 
                                ", ".join(g.chg_registers), 
                                ", ".join(g.use_registers), 
                                ", ".join(g.ptr_charset)
                                ])

    def OnCommand(self, n, cmd_id):

        # Build ROP chain
        if cmd_id == self.cmd_chain_build:

            # Display ROP chain builder form
            f = RopChainForm(self)
            ok = f.Execute()
            if ok == 1:
                pass
            f.Free()

        # Clear ROP chain
        elif cmd_id == self.cmd_chain_clear:
            self.gadget_chain = list()

        # Add gadget to ROP chain
        elif cmd_id == self.cmd_chain_add:
            if n >= 0:
                self.gadget_chain.append( self.sploiter.rop.gadgets[n] )

        # Export CSV
        elif cmd_id == self.cmd_export_csv:

            file_name = idaapi.askfile_c(1, "*.csv", "Please enter CSV file name")
            if file_name:
                print "[idasploiter] Exporting gadgets to %s" % file_name
                with open(file_name, 'wb') as csvfile:
                    csvwriter = csv.writer(csvfile, delimiter=',',
                                            quotechar='"', quoting=csv.QUOTE_MINIMAL)
                    csvwriter.writerow(["Address","Gadget","Module","Size","Pivot","Operations","Changed Registers","Used Registers","Charset"])
                    for item in self.items:
                        csvwriter.writerow(item)

        return 1

    def OnSelectLine(self, n):
        idaapi.jumpto( self.sploiter.rop.gadgets[n].address )

    def OnGetLine(self, n):
        return self.items[n]

    def OnClose(self):
        self.cmd_chain_add   = None
        self.cmd_chain_build = None
        self.cmd_chain_clear = None
        self.cmd_export_csv  = None

    def OnGetSize(self):
        return len(self.items)

    def OnRefresh(self, n):
        self.refreshitems()
        return n

    def OnActivate(self):
        self.refreshitems()

###############################################################################
# ROP Chain Builder UI
###############################################################################

###############################################################################
# ROP Chain Viewer

class RopChainView(Choose2):
    """
    Chooser class to display security characteristics of loaded modules.
    """
    def __init__(self, ropview):

        self.ropview = ropview

        Choose2.__init__(self,
                         "ROP gadgets",
                         [ ["Address",           13 | Choose2.CHCOL_HEX], 
                           ["Gadget",            30 | Choose2.CHCOL_PLAIN], 
                           ["Module",            10 | Choose2.CHCOL_PLAIN],
                           ["Size",               3 | Choose2.CHCOL_DEC],
                           ["Pivot",              4 | Choose2.CHCOL_DEC],
                           ["Operations",        12 | Choose2.CHCOL_PLAIN],
                           ["Changed Registers", 12 | Choose2.CHCOL_PLAIN],
                           ["Used Registers",    12 | Choose2.CHCOL_PLAIN],
                           ["Charset",           12 | Choose2.CHCOL_PLAIN],
                         ],
                         flags = Choose2.CH_MULTI,
                         embedded = True)

        self.icon = 182

        # Items for display and corresponding data
        self.items = []

        # Selected items
        self.select_list = list()

        # Initialize/Refresh the view
        self.refreshitems()

    def refreshitems(self):
        self.items = []

        for g in self.ropview.gadget_chain:

            self.items.append([ self.ropview.sploiter.addr_format % g.address, 
                                " # ".join(g.instructions), 
                                g.module, 
                                "%d" % g.size if g.size else "", 
                                "%d" % g.pivot if g.pivot else "", 
                                ", ".join(g.operations), 
                                ", ".join(g.chg_registers), 
                                ", ".join(g.use_registers), 
                                ", ".join(g.ptr_charset)
                                ])

        return

    def OnCommand(self, n, cmd_id):

        if cmd_id == self.cmd_move_up:
            if n > 0:
                self.ropview.gadget_chain.insert(n-1, self.ropview.gadget_chain.pop(n))

        # NOTE: Moving items down should be done in one go in reverse
        #       to avoid self.items from desyncing from gadget_chain list.
        elif cmd_id == self.cmd_move_down:

            # Empty selection
            if n == -1:
                pass

            # Selection start
            elif n == -2:
                self.select_list = list()

            # Selection end
            elif n == -3:
                for i in sorted(self.select_list, reverse=True):
                    self.ropview.gadget_chain.insert(i+1, self.ropview.gadget_chain.pop(i))
                self.select_list = list()

            else:
                self.select_list.append(n)

        # NOTE: Duplicating items should be done in one go in reverse
        #       to avoid self.items desyncing from gadget_chain list.
        elif cmd_id == self.cmd_duplicate:
            
            # Empty selection
            if n == -1:
                pass

            # Selection start
            elif n == -2:
                self.select_list = list()

            # Selection end
            elif n == -3:

                # Duplicate selection after the last index
                last_i = self.select_list[-1]

                # Duplicate selected items in reverse
                for i in sorted(self.select_list, reverse=True):

                    if last_i == len(self.ropview.gadget_chain) - 1:
                        self.ropview.gadget_chain.append(self.ropview.gadget_chain[i])
                    else:
                        self.ropview.gadget_chain.insert(last_i + 1, self.ropview.gadget_chain[i])

                self.select_list = list()

            else:
                self.select_list.append(n)

        # NOTE: Deleting items should be done in one go in reverse
        #       to avoid self.items desyncing from gadget_chain list.
        elif cmd_id == self.cmd_delete:
            
            # Empty selection
            if n == -1:
                pass

            # Selection start
            elif n == -2:
                self.select_list = list()

            # Selection end
            elif n == -3:
                for i in sorted(self.select_list, reverse=True):
                    del self.ropview.gadget_chain[i]
                self.select_list = list()

            else:
                self.select_list.append(n)



        return 1

    def OnSelectLine(self, n):
        pass

    def OnGetLine(self, n):
        return self.items[n]

    def OnClose(self):
        pass

    def OnGetSize(self):
        return len(self.items)

    def OnRefresh(self, n):
        self.refreshitems()
        return n

    def OnRefreshed(self):
        self.refreshitems()
        return len(self.items)

    def OnActivate(self):
        self.refreshitems()


###############################################################################
# ROPChain Form

class RopChainForm(Form):

    def __init__(self, ropview):

        self.ropview = ropview

        self.ropchainview = RopChainView(self.ropview)

        Form.__init__(self, 
r"""BUTTON YES* NONE
BUTTON CANCEL NONE
ROP Chain Builder

{FormChangeCb}<ROP gadgets:{cEChooser}>
<:{strAddr}><:{strComment}><Insert:{iButtonInsert}>
<:{strRopChain}>
Formats<Plain:{rFmtPlain}><Python:{rFmtPython}><Ruby:{rFmtRuby}><Perl:{rFmtPerl}><JavaScript:{rFmtJS}>{rGroup}> 
{spacer}<Generate:{iButtonGenerate}>
""", {
                'spacer'          : Form.StringLabel("                                "),
                'cEChooser'       : Form.EmbeddedChooserControl(self.ropchainview, swidth=125),
                'strAddr'         : Form.StringInput(value="0x4141414141414141" if self.ropview.sploiter.addr64 else "0x41414141", swidth=10),
                'strComment'      : Form.StringInput(value="padding", swidth=20),
                'iButtonInsert'   : Form.ButtonInput(self.OnButtonInsert, swidth=5),
                'strRopChain'     : Form.MultiLineTextControl(text="", swidth=125, flags = Form.MultiLineTextControl.TXTF_FIXEDFONT),
                'rGroup'          : Form.RadGroupControl(("rFmtPlain","rFmtPython", "rFmtRuby", "rFmtPerl", "rFmtJS") ),
                'iButtonGenerate' : Form.ButtonInput(self.OnButtonGenerate, swidth=5),
                'FormChangeCb'    : Form.FormChangeCb(self.OnFormChange),
            })

        self.Compile()

    def OnFormChange(self, fid):

        # Form initialization
        if fid == -1:
            self.SetFocusedField(self.cEChooser)

            # Add commands to embedded view
            self.ropchainview.cmd_move_up   = self.cEChooser.AddCommand("Move Up", flags = idaapi.CHOOSER_POPUP_MENU | idaapi.CHOOSER_MULTI_SELECTION | idaapi.CHOOSER_HOTKEY, icon=86)
            self.ropchainview.cmd_move_down = self.cEChooser.AddCommand("Move Down", flags = idaapi.CHOOSER_POPUP_MENU | idaapi.CHOOSER_MULTI_SELECTION, icon=85)
            self.ropchainview.cmd_duplicate = self.cEChooser.AddCommand("Duplicate", flags = idaapi.CHOOSER_POPUP_MENU | idaapi.CHOOSER_MULTI_SELECTION, icon=111)
            self.ropchainview.cmd_delete    = self.cEChooser.AddCommand("Delete", flags = idaapi.CHOOSER_POPUP_MENU | idaapi.CHOOSER_MULTI_SELECTION, icon=112)

        # Form OK pressed
        elif fid == -2:
            pass

        return 1

    def OnButtonInsert(self, code=0):
        # Get user input
        address = self.GetControlValue(self.strAddr)
        address = int(address,16)

        comment = self.GetControlValue(self.strComment)

        # Create a dummy gadget
        gadget = Gadget(instructions = [comment,], pivot = 0, operations = [], chg_registers = [], use_registers = [])
        gadget.address = address
        gadget.size = None
        gadget.pivot = None

        # Insert dummy gadget at selected positions
        select_list = self.GetControlValue(self.cEChooser)
        if select_list:
            for i in sorted(select_list,reverse=True):
                self.ropview.gadget_chain.insert(i + 1, gadget)
        else:
            self.ropview.gadget_chain.append(gadget)

        # Update the view
        self.RefreshField(self.cEChooser)

    # TODO: Generate relative addresses to a dynamically determined module base
    #       (e.g. ROP chain built based on a leaked or calculated base address)
    def OnButtonGenerate(self, code=0):

        ropchain = ""

        if self.ropview.sploiter.addr64:
            addr_format = "%016X"
            pack_format_python = "<Q"
            pack_format_ruby = "Q<"
            pack_format_perl = "Q<"
            pack_words_js = 4
            pack_bytes_c = 8

        else:
            addr_format = "%08X"
            pack_format_python = "<I"
            pack_format_ruby = "V"
            pack_format_perl = "V"
            pack_words_js = 2
            pack_bytes_c = 4

        # Plain output
        if self.GetControlValue(self.rGroup) == 0:

            ropchain += "// Generated by IDA Sploiter\n"

            for g in self.ropview.gadget_chain:

                bytes =  ["\\x%02x" % b for b in struct.unpack("B"*pack_bytes_c, struct.pack(pack_format_python, g.address))]

                ropchain += "\"%s\" // %s # %s\n" % (
                                ''.join(bytes),
                                addr_format % g.address,
                                " # ".join(g.instructions))

        # Python
        elif self.GetControlValue(self.rGroup) == 1:

            ropchain += "# Generated by IDA Sploiter\n"

            for i, g in enumerate(self.ropview.gadget_chain):

                ropchain += "rop_chain %s= struct.pack('%s', 0x%s) # %s\n" % (
                                '+' if i > 0 else ' ',
                                pack_format_python,
                                addr_format % g.address,
                                " # ".join(g.instructions) )

        # Ruby
        elif self.GetControlValue(self.rGroup) == 2:

            ropchain += "# Generated by IDA Sploiter\n"

            for i, g in enumerate(self.ropview.gadget_chain):

                ropchain += "rop_chain %s [0x%s].pack('%s') # %s\n" % (
                                '<<' if i > 0 else ' =',
                                addr_format % g.address,
                                pack_format_ruby,
                                " # ".join(g.instructions) )

        # Perl
        elif self.GetControlValue(self.rGroup) == 3:

            ropchain += "# Generated by IDA Sploiter\n"

            for i, g in enumerate(self.ropview.gadget_chain):

                ropchain += "%s$rop_chain %s= pack('%s', 0x%s); # %s\n" % (
                                'my ' if i == 0 else '',
                                '.' if i > 0 else ' ',
                                pack_format_perl,
                                addr_format % g.address,
                                " # ".join(g.instructions) )

        # JavaScript
        elif self.GetControlValue(self.rGroup) == 4:

            ropchain += "// Generated by IDA Sploiter\n"

            for i, g in enumerate(self.ropview.gadget_chain):

                words_js = ["%%u%04x" % w for w in struct.unpack("H"*pack_words_js, struct.pack(pack_format_python, g.address))]

                ropchain += "rop_chain %s= unescape(\"%s\"); // %s # %s\n" % (
                                '+' if i > 0 else ' ',
                                ''.join(words_js),
                                addr_format % g.address,
                                " # ".join(g.instructions) )

        strRopChain = idaapi.textctrl_info_t(text=ropchain, flags = Form.MultiLineTextControl.TXTF_FIXEDFONT)
        self.SetControlValue(self.strRopChain, strRopChain)

###############################################################################
# Function Pointer UI
###############################################################################

###############################################################################
# Function Pointer Form

class PtrForm(Form):

    def __init__(self, sploiter, select_list = None):

        self.sploiter = sploiter
        self.select_list = select_list
        self.mod = ModuleView(self.sploiter, embedded=True)

        Form.__init__(self, 
r"""BUTTON YES* Search
Search writable function pointers

{FormChangeCb}<Modules:{cEChooser}>

Pointer Charset:                  Search Settings:
<nonull:{cPtrNonull}>        <Bad chars     :{strBadChars}>
<unicode:{cPtrUnicode}>       Unicode Table <ANSI:{rUnicodeANSI}><OEM:{rUnicodeOEM}><UTF7:{rUnicodeUTF7}><UTF8:{rUnicodeUTF8}>{radUnicode}>
<ascii:{cPtrAscii}>         <PTR Offset    :{intPtrOffset}> 
<asciiprint:{cPtrAsciiPrint}>    <P2P Offset    :{intP2POffset}>
<alphanum:{cPtrAlphaNum}>      <Max Pointers  :{intMaxPtrs}>
<alpha:{cPtrAlpha}>         Filter        <Function Pointers:{rFilterPtr}><Pointers-to-Pointers:{rFilterP2P}>{rGroup}>
<numeric:{cPtrNum}>{ptrGroup}>       Other settings<Do not search for pointers-to-pointers:{rSearchPtrOnly}>{rSearchGroup}>


""", {
                'cEChooser'       : Form.EmbeddedChooserControl(self.mod, swidth=131),
                'ptrGroup'        : Form.ChkGroupControl(("cPtrNonull", "cPtrAscii", "cPtrAsciiPrint", "cPtrUnicode",'cPtrAlphaNum','cPtrAlpha','cPtrNum')),
                'rGroup'          : Form.RadGroupControl(("rFilterPtr","rFilterP2P") ),
                'rSearchGroup'    : Form.ChkGroupControl(("rSearchPtrOnly",) ),
                'strBadChars'     : Form.StringInput(swidth=70,tp=Form.FT_ASCII),
                'radUnicode'      : Form.RadGroupControl(("rUnicodeANSI","rUnicodeOEM","rUnicodeUTF7","rUnicodeUTF8")),
                'intPtrOffset'    : Form.StringInput(tp=Form.FT_ASCII,value="0x0", swidth=10),
                'intP2POffset'    : Form.StringInput(tp=Form.FT_ASCII,value="0x0", swidth=10),
                'intMaxPtrs'      : Form.NumericInput(swidth=4,tp=Form.FT_DEC,value=0),
                'FormChangeCb'    : Form.FormChangeCb(self.OnFormChange),
            })

        self.Compile()

    def OnFormChange(self, fid):

        # Form initialization
        if fid == -1:
            self.SetFocusedField(self.cEChooser)

            # Preselect non-ASLR modules on startup if none were already specified
            if self.select_list == None:
                
                self.select_list = list()
                for i, m in enumerate(self.sploiter.modules):
                    if m.ASLR == "No":
                        self.select_list.append(i)

            self.SetControlValue(self.cEChooser, self.select_list)

        # Form OK pressed
        elif fid == -2:
            pass

        return 1

###############################################################################
# Function Pointer Viewer

class PtrView(Choose2):
    """
    Chooser class to display writable function pointers.
    """
    def __init__(self, sploiter):

        self.sploiter = sploiter

        Choose2.__init__(self,
                         "Writeable function pointers",
                         [ ["Pointer",            13 | Choose2.CHCOL_HEX], 
                           ["Offset",              4 | Choose2.CHCOL_HEX], 
                           ["Name",               10 | Choose2.CHCOL_PLAIN],
                           ["Module",             10 | Choose2.CHCOL_PLAIN],
                           ["Charset",            12 | Choose2.CHCOL_PLAIN],
                           ["Caller Address",     13 | Choose2.CHCOL_HEX], 
                           ["Caller Name",        10 | Choose2.CHCOL_PLAIN],
                           ["Instruction",        15 | Choose2.CHCOL_PLAIN],
                           ["Ptr-to-Ptr",         13 | Choose2.CHCOL_PLAIN],
                           ["Ptr-to-Ptr Offset",   4 | Choose2.CHCOL_HEX], 
                           ["Ptr-to-Ptr Charset", 12 | Choose2.CHCOL_PLAIN],
                         ],
                         flags = Choose2.CH_MULTI_EDIT)

        self.icon = 143

        # Items for display and corresponding data
        # NOTE: Could become desynchronized, so to avoid this
        #       refresh the view after each change.
        self.items = []

        # Initialize/Refresh the view
        self.refreshitems()

        # Selected items
        self.select_caller_breakpoint_list = list()

        # Command callbacks
        self.cmd_select_caller_breakpoint = None
        self.cmd_jump_ptr = None
        self.cmd_jump_p2p = None
        self.cmd_jump_caller = None
        self.cmd_export_csv  = None

    def show(self):
        # Attempt to open the view
        if self.Show() < 0: return False

        # Add extra context menu commands
        # NOTE: Make sure you check for duplicates
        if self.cmd_select_caller_breakpoint == None:
            self.cmd_select_caller_breakpoint = self.AddCommand("Add breakpoint", flags = idaapi.CHOOSER_POPUP_MENU | idaapi.CHOOSER_MULTI_SELECTION, icon=120)

        if self.cmd_jump_ptr == None:
            self.cmd_jump_ptr = self.AddCommand("Jump to pointer", flags = idaapi.CHOOSER_POPUP_MENU | idaapi.CHOOSER_MULTI_SELECTION, icon=141)

        if self.cmd_jump_p2p == None:
            self.cmd_jump_p2p = self.AddCommand("Jump to pointer-to-pointer", flags = idaapi.CHOOSER_POPUP_MENU | idaapi.CHOOSER_MULTI_SELECTION, icon=142)

        if self.cmd_jump_caller == None:
            self.cmd_jump_caller = self.AddCommand("Jump to caller", flags = idaapi.CHOOSER_POPUP_MENU | idaapi.CHOOSER_MULTI_SELECTION, icon=143)

        if self.cmd_export_csv == None:
            self.cmd_export_csv = self.AddCommand("Export as csv...", flags = idaapi.CHOOSER_POPUP_MENU, icon=40)

        return True

    def refreshitems(self):
        self.items = []

        for ptr in self.sploiter.funcptr.ptrs:

            self.items.append([ self.sploiter.addr_format % ptr.ptr_ea, 
                                hex(ptr.ptr_offset),
                                ptr.name, 
                                ptr.module, 
                                ", ".join(ptr.ptr_charset),
                                self.sploiter.addr_format % ptr.call_ea,
                                ptr.call_name,
                                ptr.insn_disas,      
                                self.sploiter.addr_format % ptr.p2p_ea if ptr.p2p_ea else "",
                                hex(ptr.p2p_offset) if ptr.p2p_ea else "",
                                ", ".join(ptr.p2p_charset) if ptr.p2p_ea else "",                          
                                ])

    def OnCommand(self, n, cmd_id):

        if cmd_id == self.cmd_select_caller_breakpoint:

            # Empty selection
            if n == -1:
                pass                

            # Selection start
            elif n == -2:
                self.select_caller_breakpoint_list = list()

            # Selection end
            elif n == -3:               

                # Unique set of caller addresses
                eas = set()

                for i in self.select_caller_breakpoint_list:
                    eas.add( self.sploiter.funcptr.ptrs[i].call_ea )

                print "[idasploiter] Settings %d breakpoints on selected caller addresses." % len(eas)

                for ea in eas:
                    # Set default software breakpoint
                    idaapi.add_bpt(ea, 0, idaapi.BPT_DEFAULT)

                self.select_caller_breakpoint_list = list()

            # Selection number
            else:
                self.select_caller_breakpoint_list.append(n)

        # Jump to Pointer address
        elif cmd_id == self.cmd_jump_ptr:
            if n >= 0 and self.sploiter.funcptr.ptrs[n].ptr_ea:
                idaapi.jumpto( self.sploiter.funcptr.ptrs[n].ptr_ea )

        # Jump to Pointer-to-Pointer address
        elif cmd_id == self.cmd_jump_p2p:
            if n >= 0 and self.sploiter.funcptr.ptrs[n].p2p_ea:
                idaapi.jumpto( self.sploiter.funcptr.ptrs[n].p2p_ea )

        # Jump to Caller address
        elif cmd_id == self.cmd_jump_caller:
            if n >= 0 and self.sploiter.funcptr.ptrs[n].call_ea:
                idaapi.jumpto( self.sploiter.funcptr.ptrs[n].call_ea )

        # Export CSV
        elif cmd_id == self.cmd_export_csv:

            file_name = idaapi.askfile_c(1, "*.csv", "Please enter CSV file name")
            if file_name:
                print "[idasploiter] Exporting function pointers to %s" % file_name
                with open(file_name, 'wb') as csvfile:
                    csvwriter = csv.writer(csvfile, delimiter=',',
                                            quotechar='"', quoting=csv.QUOTE_MINIMAL)
                    csvwriter.writerow(["Pointer","Offset","Name","Module","Charset","Caller Address","Caller Name","Instruction","Ptr-to-Ptr","Ptr-to-Ptr Offset","Ptr-to-Ptr Charset"])
                    for item in self.items:
                        csvwriter.writerow(item)
        return 1

 
    def OnSelectLine(self, n):
        idaapi.jumpto( int(self.items[n][0],16) )

    def OnGetLine(self, n):
        return self.items[n]

    def OnClose(self):
        self.cmd_select_caller_breakpoint = None
        self.cmd_jump_ptr = None
        self.cmd_jump_p2p = None
        self.cmd_jump_caller = None
        self.cmd_export_csv  = None

    def OnGetSize(self):
        return len(self.items)

    def OnRefresh(self, n):
        self.refreshitems()
        return n

    def OnActivate(self):
        self.refreshitems()

###############################################################################
# Pattern UI
###############################################################################

###############################################################################
# Pattern Create Form

class PatternCreateForm(Form):

    def __init__(self, sploiter):

        self.sploiter = sploiter
        self.pattern_complete = ""

        Form.__init__(self, 
r"""BUTTON YES NONE
BUTTON CANCEL NONE
Create pattern
{FormChangeCb}<:{strPattern}>
<Size   :{intSize}>
Formats<Regular:{rFmtReg}><Hex:{rFmtHex}><JavaScript:{rFmtJS}>{rGroup}>
Charset<C4:{cC4}><##:{strC4}>
       <C3:{cC3}><##:{strC3}>
       <C2:{cC2}><##:{strC2}>
       <C1:{cC1}>{cGroup}><##:{strC1}>

{spacer}<Generate:{iButtonGenerate}>
""", {
            'spacer'          : Form.StringLabel("            "),
            'intSize'         : Form.NumericInput(swidth=30,tp=Form.FT_DEC,value=1000),
            'iButtonGenerate' : Form.ButtonInput(self.OnButtonGenerate,swidth=5),
            'rGroup'          : Form.RadGroupControl(("rFmtReg","rFmtHex", "rFmtJS") ),
            'cGroup'          : Form.ChkGroupControl(("cC4","cC3","cC2","cC1")),
            'strC4'           : Form.StringInput(swidth=38,tp=Form.FT_ASCII),
            'strC3'           : Form.StringInput(swidth=38,tp=Form.FT_ASCII),
            'strC2'           : Form.StringInput(swidth=38,tp=Form.FT_ASCII),
            'strC1'           : Form.StringInput(swidth=38,tp=Form.FT_ASCII),
            'strPattern'      : Form.MultiLineTextControl(text="", width=400, flags = Form.MultiLineTextControl.TXTF_FIXEDFONT | Form.MultiLineTextControl.TXTF_SELECTED | Form.MultiLineTextControl.TXTF_READONLY),
            'FormChangeCb'    : Form.FormChangeCb(self.OnFormChange),
            })

        self.Compile()

    def OnFormChange(self, fid):

        # Form initialization
        if fid == -1:

            # Set initial checkboxes for the classic metasploit 3-byte pattern
            self.SetControlValue(self.cC4, False)
            self.SetControlValue(self.cC3, True)
            self.SetControlValue(self.cC2, True)
            self.SetControlValue(self.cC1, True)

            # Set initial charsets values
            self.SetControlValue(self.strC4, self.sploiter.c4_list)
            self.SetControlValue(self.strC3, self.sploiter.c3_list)
            self.SetControlValue(self.strC2, self.sploiter.c2_list)
            self.SetControlValue(self.strC1, self.sploiter.c1_list)

        # Form OK pressed
        elif fid == -2:
            pass

        return 1

    def OnButtonGenerate(self, code=0):

        size = self.GetControlValue(self.intSize) 
        print "[idasploiter] Creating a pattern of size %d." % size

        # Update global charset lists
        self.sploiter.c4_list = self.GetControlValue(self.strC4)
        self.sploiter.c3_list = self.GetControlValue(self.strC3)
        self.sploiter.c2_list = self.GetControlValue(self.strC2)
        self.sploiter.c1_list = self.GetControlValue(self.strC1)

        # Generate pattern only using selected lists
        self.update_complete_pattern(self.GetControlValue(self.cC4), self.GetControlValue(self.cC3), self.GetControlValue(self.cC2), self.GetControlValue(self.cC1))

        pattern = self.pattern_create(size) 

        if pattern:

            # Hex output
            if self.GetControlValue(self.rGroup) == 1:
                pattern = binascii.hexlify(pattern)

            # JavaScript Unicode output
            elif self.GetControlValue(self.rGroup) == 2:
                
                pattern_js = ""

                # Number of WORDs in the pattern
                num_words = len(pattern) / 2

                # Chop off extra characters
                num_extra = len(pattern) % 2
                if num_extra:
                    pattern = pattern[:-num_extra]

                # Unpack individual WORDs from the pattern
                words = struct.unpack("H"*num_words, pattern)
                for word in words:
                    pattern_js += "%%u%s" % hex(word)

                pattern = pattern_js

            strPattern = idaapi.textctrl_info_t(text=pattern, flags = Form.MultiLineTextControl.TXTF_FIXEDFONT | Form.MultiLineTextControl.TXTF_SELECTED | Form.MultiLineTextControl.TXTF_READONLY)
            self.SetControlValue(self.strPattern, strPattern )


    def pattern_create(self, size):

        # Make sure at least one custom charset was specified
        if not len(self.pattern_complete):
            idaapi.warning("Cannot generate an empty pattern.")
            return False

        # Requested pattern size exceeds maximum allowed pattern size for the selected characterset
        elif size > len(self.pattern_complete):
            idaapi.warning("Requested size %d exceeds maximum unique pattern size %d." % (size, len(self.pattern_complete)))
            return False

        # Get a size substring from the complete pattern
        else:
            return self.pattern_complete[:size]

    def update_complete_pattern(self, c4, c3, c2, c1):

        c4_list = self.sploiter.c4_list if c4 else ["",]
        c3_list = self.sploiter.c3_list if c3 else ["",]
        c2_list = self.sploiter.c2_list if c2 else ["",]
        c1_list = self.sploiter.c1_list if c1 else ["",]

        # Generate complete pattern
        # NOTE: Not as pretty as calculating offset based on positions, but
        #       allows custom charactersets with varying positions
        self.pattern_complete = ""

        # Produce a cartesian product of all character lists and make a single string by flattening the list of lists
        self.pattern_complete = ''.join([i for j in itertools.product(c4_list, c3_list, c2_list, c1_list) for i in j])


###############################################################################
# Pattern Offset Form

class PatternDetectForm(Form):

    def __init__(self, sploiter, debugger = True):

        self.sploiter = sploiter
        self.debugger = debugger

        self.pattern_complete = ""

        form_dict = {
            'spacer'         : Form.StringLabel("           "),
            'strPattern'      : Form.StringInput(tp=Form.FT_ASCII, swidth=17),
            'strOffset'       : Form.StringInput(tp=Form.FT_ASCII, swidth=13),
            'iButtonDetect'   : Form.ButtonInput(self.OnButtonDetect, swidth=5),
            'rGroup'          : Form.RadGroupControl(('rFmtAuto', 'rFmtStr', 'rFmtAddr')),
            'cGroup'          : Form.ChkGroupControl(("cC4","cC3","cC2","cC1")),
            'strC4'           : Form.StringInput(swidth=38,tp=Form.FT_ASCII),
            'strC3'           : Form.StringInput(swidth=38,tp=Form.FT_ASCII),
            'strC2'           : Form.StringInput(swidth=38,tp=Form.FT_ASCII),
            'strC1'           : Form.StringInput(swidth=38,tp=Form.FT_ASCII),
            'FormChangeCb'    : Form.FormChangeCb(self.OnFormChange),
            }

        reg_form = ""
        self.reg_ctrls = list()

        # Display register values when executed with a debugger running
        if debugger:

            # Select general purpose registers for a given architecture
            if self.sploiter.addr64:
                self.reg_list = ["RAX", "RBX", "RCX", "RDX", "RSP", "RBP", "RSI", "RDI", "RIP", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"]
            else:
                self.reg_list = ["EAX", "EBX", "ECX", "EDX", "ESP", "EBP", "ESI", "EDI", "EIP"]

            # Populate register values and store form controls in a list
            for reg_name in self.reg_list:
                reg_value = idc.GetRegValue(reg_name)
                reg_value = self.sploiter.addr_format % reg_value

                ctrlRegValue = Form.StringInput(tp=Form.FT_ASCII, value=reg_value,swidth=17)
                form_dict["str%s" % reg_name] = ctrlRegValue

                ctrlRegOffset = Form.StringInput(tp=Form.FT_ASCII, swidth=13)
                form_dict["str%sOffset" % reg_name] = ctrlRegOffset

                reg_form += "  <%(reg)03s  :{str%(reg)s}><Offset:{str%(reg)sOffset}>\n" % {'reg': reg_name}

                self.reg_ctrls.append( (ctrlRegValue,  ctrlRegOffset) )

        Form.__init__(self, 
r"""BUTTON YES NONE
BUTTON CANCEL NONE
Detect pattern
{FormChangeCb}%s<Pattern:{strPattern}><Offset:{strOffset}>

Formats<Auto:{rFmtAuto}><Address:{rFmtAddr}><String:{rFmtStr}>{rGroup}>
Charset<C4:{cC4}><:{strC4}>
       <C3:{cC3}><:{strC3}>
       <C2:{cC2}><:{strC2}>
       <C1:{cC1}>{cGroup}><:{strC1}>

{spacer}<Detect:{iButtonDetect}>
""" % reg_form, form_dict)

        self.Compile()

    def OnFormChange(self, fid):

        # Form initialization
        if fid == -1:

            # Set initial checkboxes for the classic metasploit 3-byte pattern
            self.SetControlValue(self.cC4, False)
            self.SetControlValue(self.cC3, True)
            self.SetControlValue(self.cC2, True)
            self.SetControlValue(self.cC1, True)

            # Set initial charsets values
            self.SetControlValue(self.strC4, self.sploiter.c4_list)
            self.SetControlValue(self.strC3, self.sploiter.c3_list)
            self.SetControlValue(self.strC2, self.sploiter.c2_list)
            self.SetControlValue(self.strC1, self.sploiter.c1_list)

            # NOTE: Trying to detect offset for registry values during
            #       form initialization appears to be very slow and does
            #       not provide an option for a user to specify a custom 
            #       characterset.

        # Form OK pressed
        elif fid == -2:
            pass

        return 1

    def OnButtonDetect(self, code=0):

        # Update global charset lists
        self.sploiter.c4_list = self.GetControlValue(self.strC4)
        self.sploiter.c3_list = self.GetControlValue(self.strC3)
        self.sploiter.c2_list = self.GetControlValue(self.strC2)
        self.sploiter.c1_list = self.GetControlValue(self.strC1)

        # Generate pattern only using selected lists
        self.update_complete_pattern(self.GetControlValue(self.cC4), self.GetControlValue(self.cC3), self.GetControlValue(self.cC2), self.GetControlValue(self.cC1))

        for ctrlRegValue, ctrlRegOffset in self.reg_ctrls:
            reg_value = self.GetControlValue(ctrlRegValue)
            self.SetControlValue(ctrlRegOffset, self.verbalize_pattern(reg_value, address=True) )

        pattern = self.GetControlValue(self.strPattern)

        # Force address format
        if self.GetControlValue(self.rFmtAddr):
            self.SetControlValue(self.strOffset, self.verbalize_pattern(pattern, address=True) )

        # Force string format
        elif self.GetControlValue(self.rFmtStr):
            self.SetControlValue(self.strOffset, self.verbalize_pattern(pattern, string=True) )

        # Auto format
        else:
            self.SetControlValue(self.strOffset, self.verbalize_pattern(pattern) )

    def verbalize_pattern(self, pattern, address=False, string=False):

        # Forced address format
        if address:

            # Cleanup the pattern
            pattern = pattern.replace(' ','')       # remove spaces
            pattern = pattern.replace('\\x','')     # remove '\x' prefixes
            pattern = pattern.replace('0x','')      # remove '0x' prefixes

            if self.sploiter.addr64 and len(pattern) == 8*2:
                try:
                    pattern = struct.pack("Q", int(pattern, 16))
                except Exception, e:
                    return "Invalid address"

            elif not self.sploiter.addr64 and len(pattern) == 4*2:
                try:
                    pattern = struct.pack("I", int(pattern, 16))
                except Exception, e:
                    return "Invalid address"

            else:
                return "Invalid address"

        # Forced string format
        elif string:
            pass

        # Autodetect format
        else:

            # Cleanup the pattern
            pattern = pattern.replace(' ','')       # remove spaces
            pattern = pattern.replace('\\x','')     # remove '\x' prefixes
            pattern = pattern.replace('0x','')      # remove '0x' prefixes

            # Attempt to detect and unpack pattern
            if self.sploiter.addr64 and len(pattern) == 8*2:
                try:
                    pattern = struct.pack("Q", int(pattern, 16))
                except Exception, e:
                    pass

            elif not self.sploiter.addr64 and len(pattern) == 4*2:
                try:
                    pattern = struct.pack("I", int(pattern, 16))
                except Exception, e:
                    pass

        if len(pattern) > 0:
            offset         = self.pattern_offset(pattern)
            offset_reverse = self.pattern_offset(pattern[::-1])
        else:
            return "Blank pattern"

        if offset >= 0:
            return "%d" % offset
        elif offset_reverse >= 0:
            return "%d (reverse)" % offset_reverse
        else:
            return "Not detected"

    def pattern_offset(self, pattern):

        offset = -1

        # Make sure at least one custom charset was specified
        if not len(self.pattern_complete):
            idaapi.warning("Cannot detect an empty pattern.")
            return offset

        # Locate the pattern
        if pattern in self.pattern_complete:
            offset = self.pattern_complete.index(pattern)

        return offset

    def update_complete_pattern(self, c4, c3, c2, c1):

        c4_list = self.sploiter.c4_list if c4 else ["",]
        c3_list = self.sploiter.c3_list if c3 else ["",]
        c2_list = self.sploiter.c2_list if c2 else ["",]
        c1_list = self.sploiter.c1_list if c1 else ["",]

        # Generate complete pattern
        # NOTE: Not as pretty as calculating offset based on positions, but
        #       allows custom character sets with varying positions
        self.pattern_complete = ""

        # Produce a cartesian product of all character lists and make a single string by flattening the list of lists
        self.pattern_complete = ''.join([i for j in itertools.product(c4_list, c3_list, c2_list, c1_list) for i in j])

###############################################################################
# Compare UI
###############################################################################

###############################################################################
# Compare Form

class CompareForm(Form):

    def __init__(self, sploiter, debugger = True):

        self.sploiter = sploiter
        self.debugger = debugger

        Form.__init__(self, 
r"""BUTTON YES NONE
BUTTON CANCEL NONE
Compare file to memory
{FormChangeCb}<File     :{impFile}>
<Memory   :{intAddr}>

<:{strCompare}>

<Bad Chars:{strBadChars}>
<Mem Holes:{strMemHoles}>

{spacer}<Compare:{iButtonCompare}>
""", {
            'spacer'        : Form.StringLabel("                                "),
            'impFile'        : Form.FileInput(swidth=62, open=True),
            'intAddr'        : Form.NumericInput(swidth=62, tp=Form.FT_ADDR, value=idaapi.get_screen_ea()),
            'strCompare'     : Form.MultiLineTextControl(text="", swidth=72, flags = Form.MultiLineTextControl.TXTF_FIXEDFONT | Form.MultiLineTextControl.TXTF_READONLY),
            'strBadChars'    : Form.StringInput(swidth=62,tp=Form.FT_ASCII),
            'strMemHoles'    : Form.StringInput(swidth=62,tp=Form.FT_ASCII),
            'iButtonCompare' : Form.ButtonInput(self.OnButtonCompare,),
            'FormChangeCb'   : Form.FormChangeCb(self.OnFormChange),
            })

        self.Compile()

    def OnFormChange(self, fid):

        # Form initialization
        if fid == -1:
            pass

        # Form OK pressed
        elif fid == -2:
            pass

        return 1

    def OnButtonCompare(self, code=0):
        
        #######################################################################
        # Read file into buffer
        file_name = self.GetControlValue(self.impFile)

        # Verify file name was provided
        if not len(file_name):
            idaapi.warning("Please provide file name.")
            return

        # Attempt to read the file
        print "[idasploiter] Reading file %s" % file_name
        
        try:
            f = open(file_name,'rb')
        except Exception, e:
            idaapi.warning("File I/O error({0}): {1}.".format(e.errno, e.strerror) )
            return
        else:
            file_buf = f.read()
            f.close()

        # Check file content
        if not len(file_buf) > 0:
            idaapi.warning("Provided file was blank.")
            return

        # 64k ought to be enough for anybody =)
        elif len(file_buf) > 0xffff:
            idaapi.warning("File is too big.")
            return

        # Covert file bytes into printable hex view
        file_buf_str = " ".join(["%02x" % ord(b) for b in file_buf])
        file_buf_list = textwrap.wrap(file_buf_str, 48)

        #######################################################################
        # Read memory into buffer and mark non-matching bytes
        address = self.GetControlValue(self.intAddr)

        print "[idasploiter] Reading %d bytes from %s." % ( len(file_buf), self.sploiter.addr_format % address)

        if self.debugger:
            mem_buf = idaapi.dbg_read_memory(address, len(file_buf))
        else:
            mem_buf = idaapi.get_many_bytes(address, len(file_buf))

        if not mem_buf:
            idaapi.warning("Could not read memory.")
            return

        # Convert memory bytes into printable hex view
        mem_buf_str = ""

        # Badchars tracking
        badchars = list()
        badchars_nonseq = set()
        badchars_hole = list()

        # Locate all of the non-sequential badchars. The assumption is that
        # after the first badchar (e.g. 0x0A) the rest may be corrupted.
        for i, b in enumerate(file_buf):
            if file_buf[i] == mem_buf[i]:
                mem_buf_str+= ".. "

            else:
                mem_buf_str+= "%02x " % ord( mem_buf[i])

            # Do differential processing if the two bytes are not the same or
            # if the matching byte is in the bad characters list

            if file_buf[i] != mem_buf[i] or "%02x" % ord(file_buf[i]) in badchars_nonseq:

                ###############################################################
                # Memory holes

                # Check if the badchar appears anywhere else in memory to
                # detect positional holes. If this is the first discrepancy
                # then it is likely it is a badchar (e.g. 0x00, 0x0a, 0x0d)

                if len(badchars_hole):
                    hole_i, hole_size = badchars_hole[-1]

                    # Continuation of a previously discovered hole
                    if i == hole_i + hole_size:
                        badchars_hole[-1] = (hole_i, hole_size + 1)

                    # New hole discovered
                    else:
                        badchars_hole.append( (i,1) )

                # New hole discovered
                else:
                    badchars_hole.append( (i,1) )

                ###############################################################
                # Bad characters

                # Check if previous byte in the file is already a badchar, so
                # this new discrepancy doesn't matter:

                if not "%02x" % ord(file_buf[i-1]) in  badchars_nonseq:

                    # Skip sequential corruption
                    if len(badchars_nonseq):
                        bad_i, bad_b = badchars[-1]

                        # Check if the previous byte was also corrupted
                        # indicating a sequential corruption
                        if i - 1 != bad_i:
                            badchars_nonseq.add( "%02x" % ord(b) )

                    else:                      
                        badchars_nonseq.add( "%02x" % ord(b) )

                # Store badchars in a list
                badchars.append( (i,b) )


        mem_buf_list = textwrap.wrap(mem_buf_str, 48)

        if len(badchars) == 0:
            self.SetControlValue(self.strBadChars, "Identical.")  
        elif len(badchars) == len(file_buf):
            self.SetControlValue(self.strBadChars, "Completely different.")          
        else:
            self.SetControlValue(self.strBadChars, " ".join( sorted(badchars_nonseq) ) )
            self.SetControlValue(self.strMemHoles, ", ".join( [ "0x%02X: %d byte(s)" % h for h in badchars_hole ]  ) )

        #######################################################################
        # Populate the text box

        buf_formatted = "      00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F\n\n"
        for i in range( len(file_buf_list) ):

            file_line = file_buf_list[i].ljust(48)
            file_line = file_line[:23]+" "+file_line[23:]

            mem_line = mem_buf_list[i].ljust(48)
            mem_line = mem_line[:23]+" "+mem_line[23:]

            buf_formatted += "%04X  %s  F\n      %s  M\n\n" % (i*0x10, file_line, mem_line)

        strCompare = idaapi.textctrl_info_t(text=buf_formatted, flags = Form.MultiLineTextControl.TXTF_FIXEDFONT | Form.MultiLineTextControl.TXTF_READONLY)
        self.SetControlValue(self.strCompare, strCompare)

###############################################################################
# Plugin Manager
###############################################################################

class SploitManager():
    """ Class that manages GUI forms and exploitation methods of the plugin. """
    
    def __init__(self): 
        self.addmenu_item_ctxs = list()
        self.sploiter = Sploiter()

    ###########################################################################
    # Menu Items
    def add_menu_item_helper(self, menupath, name, hotkey, flags, pyfunc, args):

        # add menu item and report on errors
        addmenu_item_ctx = idaapi.add_menu_item(menupath, name, hotkey, flags, pyfunc, args)
        if addmenu_item_ctx is None:
            return 1
        else:
            self.addmenu_item_ctxs.append(addmenu_item_ctx)
            return 0

    def add_menu_items(self):
        if self.add_menu_item_helper("View/Open subviews/Segments", "Modules", "Shift+F6", 0, self.show_modules_view, None): return 1

        if self.add_menu_item_helper("Search/all error operands", "function pointers...", "Alt+f", 1, self.show_funcptr_view, None): return 1
        if self.add_menu_item_helper("Search/all error operands", "gadgets...", "Alt+r", 1, self.show_rop_view, None): return 1

        if self.add_menu_item_helper("Edit/Begin selection", "Create pattern...", "Shift+c", 0, self.show_pattern_create, None): return 1
        if self.add_menu_item_helper("Edit/Begin selection", "Detect pattern...", "Shift+d", 0, self.show_pattern_detect, None): return 1
        if self.add_menu_item_helper("Edit/Begin selection", "Compare file to memory...", "Shift+f", 0, self.show_compare, None): return 1
        
        return 0

    def del_menu_items(self):
        for addmenu_item_ctx in self.addmenu_item_ctxs:
            idaapi.del_menu_item(addmenu_item_ctx)

    ###########################################################################
    # Utility Functions

    # Check debugger is ready for querying
    def check_debugger(self):
        if idaapi.dbg_can_query() and idaapi.get_process_state() < 0:
            return True
        else:
            return False

    ###########################################################################
    # View Callbacks
    
    # Modules View
    def show_modules_view(self):
        if self.check_debugger():
            self.sploiter.process_modules()
            self.sploiter.show_modules_view()
        else:            
            idaapi.warning("Please run and suspend the debugger.")
            

    # ROP View
    def show_rop_view(self):
        if self.check_debugger():
            self.sploiter.process_modules()
            self.sploiter.process_rop()
        else:            
            idaapi.warning("Please run and suspend the debugger.")
            

    # Function Pointer View
    def show_funcptr_view(self):     
        if self.check_debugger():   
            self.sploiter.process_modules()
            self.sploiter.process_funcptr()
        else:            
            idaapi.warning("Please run and suspend the debugger.")

    # Create Pattern Form
    def show_pattern_create(self):
        self.sploiter.pattern_create()

    # Detect Pattern Form
    def show_pattern_detect(self):

        # Debugger Version
        if self.check_debugger():
            self.sploiter.pattern_detect()

        # Static Version
        else:
            self.sploiter.pattern_detect(debugger=False)

    # Compare File to Memory Form
    def show_compare(self):

        # Debugger Version
        if self.check_debugger():
            self.sploiter.process_compare()

        # Static Version
        else:
            self.sploiter.process_compare(debugger=False)


###############################################################################

class idasploiter_t(plugin_t):

    flags = idaapi.PLUGIN_UNL
    comment = "Exploit development and vulnerability research toolkit."
    help = "Exploit development and vulnerability research toolkit."
    wanted_name = "IDA Sploiter"
    wanted_hotkey = ""

    def init(self):  

        # Only Intel x86/x86-64 are supported
        if idaapi.ph_get_id() == idaapi.PLFM_386:

            global idasploiter_manager

            # Check if already initialized
            if not 'idasploiter_manager' in globals():

                idasploiter_manager = SploitManager()
                if idasploiter_manager.add_menu_items():
                    print "Failed to initialize IDA Sploiter."
                    idasploiter_manager.del_menu_items()
                    del idasploiter_manager
                    return idaapi.PLUGIN_SKIP
                else:
                    print("Initialized IDA Sploiter v%s (c) Peter Kacherginsky <iphelix@thesprawl.org>" % IDASPLOITER_VERSION)

            return idaapi.PLUGIN_KEEP
        else:
            return idaapi.PLUGIN_SKIP

    def run(self, arg):
        pass

    def term(self):
        pass        

def PLUGIN_ENTRY():
    return idasploiter_t()

###############################################################################
# Script / Testing
###############################################################################

def idasploiter_main():
    global idasploiter_manager

    if 'idasploiter_manager' in globals():
        idasploiter_manager.del_menu_items()
        del idasploiter_manager

    idasploiter_manager = SploitManager()
    idasploiter_manager.add_menu_items()

    sploiter = idasploiter_manager.sploiter

if __name__ == '__main__':
    #idasploiter_main()
    pass