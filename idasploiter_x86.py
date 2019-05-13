#!/usr/bin/env python
#
# IDA Sploiter is an exploit development and vulnerability research environment
# implemented as a plugin for Hex-Ray's IDA Pro disassembler.

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

# IDA Sploiter
from idasploiter import FuncPtr, Gadget, Ptr, Rop, read_module_memory, Sploiter

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
import struct

from struct import pack, unpack
from ctypes import *


###############################################################################
# Function Pointer Search Engine

class x86_FuncPtr(FuncPtr):
    def __init__(self, sploiter):

        FuncPtr.__init__(self, sploiter)

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
                            ptr_calls.append(call_ea)

                        # Search all instances of JMP /2 imm32/64 - FF 25
                        # TODO: Alternative pointer calls using SIB: FF 24 E5 11 22 33 44 - jmp dword/qword ptr [0x44332211]
                        #                                            FF 24 65 11 22 33 44
                        #                                            FF 24 25 11 22 33 44
                        call_ea = seg.startEA
                        while True:
                            call_ea = idaapi.find_binary(call_ea + 1, seg.endEA, "FF 25", 16, idaapi.SEARCH_DOWN)
                            if call_ea == idaapi.BADADDR: break
                            ptr_calls.append(call_ea)

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
                                if self.ptrNonull and not "nonull" in ptr_charset: continue
                                if self.ptrUnicode and not "unicode" in ptr_charset: continue
                                if self.ptrAscii and not "ascii" in ptr_charset: continue
                                if self.ptrAsciiPrint and not "asciiprint" in ptr_charset: continue
                                if self.ptrAlphaNum and not "alphanum" in ptr_charset: continue
                                if self.ptrNum and not "numeric" in ptr_charset: continue
                                if self.ptrAlpha and not "alpha" in ptr_charset: continue

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
                    pack_format = "<Q"
                    addr_bytes = 8
                    prefix_offset = 6
                else:
                    pack_format = "<I"
                    addr_bytes = 4
                    prefix_offset = 2

                # Set of unique N-byte address prefixes to search in memory
                ea_prefix_set = set()

                for ptr in ptrs:
                    ptr_ea = ptr.ptr_ea

                    ptr_bytes = struct.pack(pack_format, ptr_ea)
                    ptr_bytes = ptr_bytes[-prefix_offset:]

                    ea_prefix_set.add(ptr_bytes)

                # Search the module for all bytes corresponding to the prefix
                # and use them as candidates for pointers-to-pointers

                for ea_prefix in ea_prefix_set:

                    # NOTE: Make sure you search using 44 33 22 11 format and not 11223344
                    ea_prefix_str = " ".join(["%02x" % ord(b) for b in ea_prefix])

                    # Initialize search parameters for a given module
                    ea = m.addr
                    maxea = m.addr + m.size

                    while True:
                        ea = idaapi.find_binary(ea + 1, maxea, ea_prefix_str, 16, idaapi.SEARCH_DOWN)
                        if ea == idaapi.BADADDR: break

                        p2p_ea = ea - (addr_bytes - prefix_offset)

                        dbg_mem = read_module_memory(p2p_ea, addr_bytes)
                        ptr_ea_prefix = unpack(pack_format, dbg_mem)[0]

                        if ptr_ea_prefix in ptr_ea_prefix_cache:
                            ptr_ea_prefix_cache[ptr_ea_prefix].add(p2p_ea)
                        else:
                            ptr_ea_prefix_cache[ptr_ea_prefix] = set([p2p_ea, ])

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
                            if self.ptrNonull and not "nonull" in p2p_charset: continue
                            if self.ptrUnicode and not "unicode" in p2p_charset: continue
                            if self.ptrAscii and not "ascii" in p2p_charset: continue
                            if self.ptrAsciiPrint and not "asciiprint" in p2p_charset: continue
                            if self.ptrAlphaNum and not "alphanum" in p2p_charset: continue
                            if self.ptrNum and not "numeric" in p2p_charset: continue
                            if self.ptrAlpha and not "alpha" in p2p_charset: continue

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
# ROP Search Engine

class x86_Rop(Rop):
    def __init__(self, sploiter):

        Rop.__init__(self, sploiter)

        # Extra bytes to read to ensure correct decoding of
        # RETN, RETN imm16, CALL /2, and JMP /4 instructions.
        self.dbg_read_extra = 6  # FF + ModR/M + SIB + disp32

        self.insn_arithmetic_ops = ["inc", "dec", "neg", "add", "sub", "mul", "imul", "div", "idiv", "adc", "sbb",
                                    "lea"]
        self.insn_bit_ops = ["not", "and", "or", "xor", "shr", "shl", "sar", "sal", "shld", "shrd", "ror", "rcr", "rcl"]

    def get_o_reg_name(self, insn, n):

        reg_num = insn.Operands[n].reg
        reg_name = self.regnames[reg_num]

        # NOTE: IDA's x86/x86-64 regname array contains only register root names
        #       (e.g ax,cx,dx,etc.). However we can still figure out exact register
        #       size by looking at the operand 'dtyp' property.
        if reg_num < 8:

            # 32-bit register
            if insn.Operands[n].dtyp == idaapi.dt_dword:
                reg_name = 'e' + reg_name

            # 64-bit register
            elif insn.Operands[n].dtyp == idaapi.dt_qword:
                reg_name = 'r' + reg_name

                # 16-bit register otherwise

        return reg_name

    def search_retns(self):

        if not self.debug: print("found %d modules" % len(self.modules))
        for m in self.modules:

            # Iterate over segments in the module
            # BUG: Iterating over all loaded segments is more stable than looking up by address
            if not self.debug: print("found %d segments" % idaapi.get_segm_qty())
            for n in xrange(idaapi.get_segm_qty()):
                seg = idaapi.getnseg(n)

                # Locate executable segments in a selected modules
                # NOTE: Each module may have multiple executable segments
                if seg and seg.startEA >= m.addr and seg.endEA <= (m.addr + m.size):
                    # If the debugger is attached then we can check if the segment is executable, else
                    # just check if it is code or not.
                    if idaapi.dbg_can_query() and idaapi.get_process_state() < 0:
                        if seg.perm & idaapi.SEGPERM_EXEC == 0:
                            continue
                    elif seg.type & idaapi.SEG_CODE == 0:
                        continue

                    #######################################################
                    # Search for ROP gadgets
                    if self.searchRop:

                        # Search all instances of RETN
                        ea = seg.startEA
                        while True:
                            ea = idaapi.find_binary(ea + 1, seg.endEA, "C3", 16, idaapi.SEARCH_DOWN)
                            if ea == idaapi.BADADDR: break
                            self.retns.append((ea, m.file))

                        # Search all instances of RETN imm16
                        ea = seg.startEA
                        while True:
                            ea = idaapi.find_binary(ea + 1, seg.endEA, "C2", 16, idaapi.SEARCH_DOWN)
                            if ea == idaapi.BADADDR: break

                            # Read imm16 value and filter large values
                            retn_imm16 = read_module_memory(ea + 1, 0x2)
                            retn_imm16 = unpack("<H", retn_imm16)[0]

                            if retn_imm16 <= self.maxRetnImm:
                                self.retns.append((ea, m.file))

                    #######################################################
                    # Search for JOP gadgets
                    if self.searchJop:

                        # Search all instances of JMP reg (FF /4) and CALL reg (FF /2)
                        ea = seg.startEA
                        while True:
                            ea = idaapi.find_binary(ea + 1, seg.endEA, "FF", 16, idaapi.SEARCH_DOWN)
                            if ea == idaapi.BADADDR: break

                            # Read possible ModR/M, SIB, and IMM8/IMM32 bytes
                            jop = read_module_memory(ea + 1, 0x6)
                            if jop == None or len(jop) == 0:
                                continue

                            ###################################################
                            # JMP/CALL reg
                            if jop[0] in ["\xe0", "\xe1", "\xe2", "\xe3", "\xe4", "\xe5", "\xe6", "\xe7",
                                          "\xd0", "\xd1", "\xd2", "\xd3", "\xd4", "\xd5", "\xd6", "\xd7"]:
                                self.retns.append((ea, m.file))

                            ###################################################
                            # JMP/CALL [reg] no SIB
                            # NOTE: Do not include pure [disp] instruction.

                            # JMP/CALL [reg] no *SP,*BP
                            elif jop[0] in ["\x20", "\x21", "\x22", "\x23", "\x26", "\x27",
                                            "\x10", "\x11", "\x12", "\x13", "\x16", "\x17"]:
                                self.retns.append((ea, m.file))

                            # JMP/CALL [reg + imm8] no *SP
                            elif jop[0] in ["\x60", "\x61", "\x62", "\x63", "\x65", "\x66", "\x67",
                                            "\x50", "\x51", "\x52", "\x53", "\x55", "\x56", "\x57"]:
                                jop_imm8 = jop[1]
                                jop_imm8 = unpack("b", jop_imm8)[0]  # signed

                                if jop_imm8 <= self.maxJopImm:
                                    self.retns.append((ea, m.file))


                            # JMP/CALL [reg + imm32] no *SP
                            elif jop[0] in ["\xa0", "\xa1", "\xa2", "\xa3", "\xa5", "\xa6", "\xa7",
                                            "\x90", "\x91", "\x92", "\x93", "\x95", "\x96", "\x97"]:
                                jop_imm32 = jop[1:5]
                                jop_imm32 = unpack("<i", jop_imm32)[0]  # signed

                                if jop_imm32 <= self.maxJopImm:
                                    self.retns.append((ea, m.file))

                            ###################################################
                            # JMP/CALL [reg] with SIB
                            # NOTE: Do no include pure [disp] instructions in SIB ([*] - none)
                            elif (jop[0] in ["\x24", "\x64", "\xa4"] and not jop[1] in ["\x25", "\x65", "\xad",
                                                                                        "\xe5"]) or \
                                    (jop[0] in ["\x14", "\x54", "\x94"] and not jop[1] in ["\x25", "\x65", "\xad",
                                                                                           "\xe5"]):

                                # Check for displacement
                                if jop[0] in ["\x64", "\x54"]:
                                    jop_imm8 = jop[2]
                                    jop_imm8 = unpack("b", jop_imm8)[0]  # signed

                                    if jop_imm8 <= self.maxJopImm:
                                        self.retns.append((ea, m.file))

                                elif jop[0] in ["\xa4", "\x94"]:
                                    jop_imm32 = jop[2:6]
                                    jop_imm32 = unpack("<i", jop_imm32)[0]  # signed

                                    if jop_imm32 <= self.maxJopImm:
                                        self.retns.append((ea, m.file))

                                else:
                                    self.retns.append((ea, m.file))

        print "[idasploiter] Found %d returns" % len(self.retns)

    def search_gadgets(self):

        count_total = len(self.retns)
        count_notify = 0
        count_curr = 0

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
                self.dbg_mem_cache = read_module_memory(ea_end - self.maxRopOffset + i,
                                                        self.maxRopOffset - i + self.dbg_read_extra)
                if self.dbg_mem_cache != None:
                    break

            # Check to make sure we have actual data to work with.
            if self.dbg_mem_cache == None:
                continue

            # Search all possible gadgets up to maxoffset bytes back
            # NOTE: Try all byte combinations to capture longer/more instructions
            #       even with bad bytes in the middle.
            for i in range(1, len(self.dbg_mem_cache) - self.dbg_read_extra):

                ea = ea_end - i

                # Get pointer charset
                ptr_charset = self.sploiter.get_ptr_charset(ea)

                # Filter the pointer
                if ptr_charset == None:                                    continue
                if self.ptrNonull and not "nonull" in ptr_charset: continue
                if self.ptrUnicode and not "unicode" in ptr_charset: continue
                if self.ptrAscii and not "ascii" in ptr_charset: continue
                if self.ptrAsciiPrint and not "asciiprint" in ptr_charset: continue
                if self.ptrAlphaNum and not "alphanum" in ptr_charset: continue
                if self.ptrNum and not "numeric" in ptr_charset: continue
                if self.ptrAlpha and not "alpha" in ptr_charset: continue

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
                idaapi.replace_wait_box("Searching gadgets: %02d%%%%" % (count_curr * 100 / count_total))

                count_notify += 0.10 * count_total

            count_curr += 1

        print "[idasploiter] Found %d gadgets." % len(self.gadgets)
        if not self.debug: idaapi.hide_wait_box()

    # Attempt to build a gadget at the provided start address
    # by verifying it properly terminates at the expected RETN.
    def build_gadget(self, ea, ea_end):

        instructions = list()
        chg_registers = set()
        use_registers = set()
        operations = set()
        pivot = 0

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
                    dbg_mem_offset = ea - (ea_end - (len(self.dbg_mem_cache) - self.dbg_read_extra))
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
                        elif insn_mnem in ["jmp", "call"]:
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

                    # BUGFIX: For some reason the length of dbg_mem may be 0 (perhaps we ran out of cache?), so
                    # verify the size is valid before using the buffer.
                    if len(dbg_mem) != 2:
                        return None

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

        # if insn_mnem in self.mnems: self.mnems[insn_mnem] += 1
        # else:                       self.mnems[insn_mnem]  = 1

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
        if not insn_mnem in ["retn", "jmp", "call"]:

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
        insn_disas = insn_disas.partition(';')[0]  # Remove comments from disassembly
        insn_disas = ' '.join(insn_disas.split())  # Remove extraneous space from disassembly

        ###############################################################
        # Analyze instruction
        ###############################################################

        # Standalone instruction
        if insn_op1 == idaapi.o_void:

            # TODO: Determine and test how these instructions affect the stack
            #       in 32-bit and 64-bit modes.
            if insn_mnem in ["pusha", "pushad", "popa", "popad", "pushf", "pushfd", "pushfq", "popf", "popfd", "popfq"]:
                insn_operations.add("stack")

                if insn_mnem in ["popa", "popad"]:
                    insn_pivot += 7 * 4
                elif insn_mnem in ["pusha", "pushad"]:
                    insn_pivot -= 8 * 4
                elif insn_mnem in ["popf", "popfd"]:
                    insn_pivot += 4
                elif insn_mnem in ["pushf", "pushfd"]:
                    insn_pivot -= 4
                elif insn_mnem == "popfq":  # TODO: Needs testing
                    insn_pivot += 8
                elif insn_mnem == "pushfq":  # TODO: Needs testing
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
            if insn_mnem in ["push", "pop"]:
                insn_operations.add("stack")

                # Adjust pivot based on operand size (32bit vs 64bit)
                if insn_mnem == "pop":
                    if insn.Operands[0].dtyp == idaapi.dt_dword:
                        insn_pivot += 4
                    elif insn.Operands[0].dtyp == idaapi.dt_qword:
                        insn_pivot += 8
                elif insn_mnem == "push":
                    if insn.Operands[0].dtyp == idaapi.dt_dword:
                        insn_pivot -= 4
                    elif insn.Operands[0].dtyp == idaapi.dt_qword:
                        insn_pivot -= 8

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

class x86_Sploiter(Sploiter):
    def __init__(self):

        Sploiter.__init__(self)

        # Initialize fields specific to this architecture.
        self.bad_instructions = "leave, int, into, enter, syscall, sysenter, sysexit, sysret, in, out, loop, loope, loopne, lock, rep, repe, repz, repne, repnz"

        # Select general purpose registers for a given architecture
        if self.addr64:
            self.reg_list = ["RAX", "RBX", "RCX", "RDX", "RSP", "RBP", "RSI", "RDI", "RIP", "R8", "R9", "R10", "R11",
                             "R12", "R13", "R14", "R15"]
        else:
            self.reg_list = ["EAX", "EBX", "ECX", "EDX", "ESP", "EBP", "ESI", "EDI", "EIP"]

    def is_func_ptr_supported(self):
        return True

    def get_func_ptr_instance(self):

        # Check processor type and create the function pointer class.
        if idaapi.ph.id == idaapi.PLFM_386:
            return x86_FuncPtr(self)
        else:
            return None

    def get_rop_instance(self):

        # Check the processor type and create the rop class.
        if idaapi.ph.id == idaapi.PLFM_386:
            return x86_Rop(self)
        else:
            return None


class idasploiter_x86_t(plugin_t):

    flags = idaapi.PLUGIN_UNL
    comment = ""
    help = ""
    wanted_name = ""
    wanted_hotkey = ""

    def init(self):
        return idaapi.PLUGIN_SKIP

    def run(self, arg):
        pass

    def term(self):
        pass

def PLUGIN_ENTRY():
    return idasploiter_x86_t()