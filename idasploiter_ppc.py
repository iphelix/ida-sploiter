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
# ROP Search Engine

class ppc_Rop(Rop):

    def __init__(self, sploiter):
        
        Rop.__init__(self, sploiter)

        # Extra bytes to read to ensure correct decoding of
        # BLR instructions.
        self.dbg_read_extra = 4

        self.insn_arithmetic_ops = ["neg", "add","addc","adde","addi","addic","addic.","addis","addme","addze","divw","divw.","divwo","divwo.","divwu","divwu.","divwuo","divwuo.","mulhw","mulhw.","mulhwu","mulhwu.","mulli","mullw","mullw.","mullwo","mullwo.",
									"subf","subf.","subfo","subfo.","sub","subfc","subfc.","subfco","subfco.","subc","subfe","subfe.","subfeo","subfeo.","subfic","subfme","subfme.","subfmeo","subfmeo.","subfzo","subfze.","subfzeo","subfzeo."]
        self.insn_bit_ops = ["neg","and","andc","andi","andis","or","orc","ori","oris","nand","nor","xor","xori","xoris","slw","srw","sraw","srawi","rlwimi","rlwinm","rlwnm","rldicr"]

    def get_o_reg_name(self, insn, n):

        reg_num = insn.Operands[n].reg
        reg_name = self.regnames[reg_num]

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

                        #Search all instances of BLR
                        ea = seg.startEA
                        while True:
                            ea = idaapi.find_binary(ea + 1, seg.endEA, "4E 80 00 20", 16, idaapi.SEARCH_DOWN)
                            if ea == idaapi.BADADDR: break

                            self.retns.append((ea, m.file))

                        # Search all instances of BTCTR
                        ea = seg.startEA
                        while True:
                            ea = idaapi.find_binary(ea + 1, seg.endEA, "4E 80 04 20", 16, idaapi.SEARCH_DOWN)
                            if ea == idaapi.BADADDR: break

                            self.retns.append((ea, m.file))

                        # Search all instances of BTCTRL
                        ea = seg.startEA
                        while True:
                            ea = idaapi.find_binary(ea + 1, seg.endEA, "4E 80 04 21", 16, idaapi.SEARCH_DOWN)
                            if ea == idaapi.BADADDR: break

                            self.retns.append((ea, m.file))

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

        print("found %s retns" % len(self.retns))
        for (ea_end, module) in self.retns:

            # Flush the gadgets cache for each new retn pointer
            self.gadgets_cache = dict()

            # Flush memory cache for each new retn pointer
            self.dbg_mem_cache = None

            # CACHE: It is faster to read as much memory in one blob than to make incremental reads backwards.
            #        Try to read and cache self.maxRopSize instructions back. In cases where it is not possible,
            #        then simply try to read the largest chunk.
            
            # NOTE: Read a bit extra to cover correct decoding of RETN and RETN imm16 instructions.
			
            self.dbg_mem_cache = read_module_memory(ea_end - (self.maxRopSize * 4), (self.maxRopSize * 4) + self.dbg_read_extra)

            # Check to make sure we have actual data to work with.
            if self.dbg_mem_cache == None:
                continue

            # Search all possible gadgets up to maxoffset bytes back
            # NOTE: try all byte combinations to capture longer/more instructions
            #       even with bad bytes in the middle.
            for i in range(1, self.maxRopSize + 1):

                ea = ea_end - (i * 4)

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
                idaapi.replace_wait_box("Searching gadgets: %02d%%%%" % (count_curr * 100/count_total))

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

                        # Check if we found an instruction that would change the instruction pointer
                        if insn_mnem == "blr" or insn_mnem == "bctr" or insn_mnem == "bctrl":

                            # RETN at the expected address
                            if ea == ea_end:
                                gadget = Gadget(instructions, pivot, operations, chg_registers, use_registers)
                                return gadget

                            # RETN at an unexpected address
                            else:
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
                    # Invalidate the gadget
                    return None

        # Failed to build a gadget, because RETN instruction was not found
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
        if insn_feature == 0:
            return None

        # Instruction mnemonic name
        insn_mnem = insn.get_canon_mnem()

        # BUGBUG: The IDA PowerPC processor module has a bug that causes 'b', 'blr', 'bctr', and 'bctrl' instructions to decode
        # identically. Manually check the opcode bytes to determine for real what instruction this is.
        insn_opcode = idc.Dword(ea)
        if insn_opcode == 0x4E800020:
            insn_mnem = "blr"
        elif insn_opcode == 0x4E800420:
            insn_mnem = "bctr"
        elif insn_opcode == 0x4E800421:
            insn_mnem = "bctrl"

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
        insn_op3 = insn.Operands[2].type

        ###############################################################
        # Filter gadget
        ###############################################################

        # Filter gadgets with instructions that don't forward execution to the next address
        if insn_feature & idaapi.CF_STOP:
            if insn_mnem != "blr" and insn_mnem != "bctrl":
                return None

        # Filter gadgets with instructions in a bad list
        elif insn_mnem in self.ropBadMnems:
            return None

        # Filter gadgets with branch instructions
        # Note: conditional branches may still be useful if we can
        #       set flags prior to calling them.
        elif not self.ropAllowJcc and insn_mnem == "b":
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

        # Check for arithmetic operations
        if insn_mnem in self.insn_arithmetic_ops:
            insn_operations.add("math")

        # Check for bit-wise operations
        if insn_mnem in self.insn_bit_ops:
            insn_operations.add("bit")

        # Check if the operands are registers and record how it is used.
        if insn_op1 == idaapi.o_reg:

            reg1_name = self.get_o_reg_name(insn, 0)

            # Check if the register is used or modified or both.
            if insn_feature & idaapi.CF_USE1:
                insn_use_registers.add(reg1_name)

            if insn_feature & idaapi.CF_CHG1:
                insn_chg_registers.add(reg1_name)

            # Check for stack operation
            if reg1_name == "r1":
                insn_operations.add("stack")

                # Determine stack pivot distance
                if insn_op3 == idaapi.o_imm:

                    # NOTE: adb and sbb may also be useful, but let the user
                    #       determine their use by locating the operations "stack"
                    if insn_mnem == "add" or insn_mnem == "addi":
                        insn_pivot += insn.Operands[2].value

                    elif insn_mnem == "sub" or insn_mnem == "subi":
                        insn_pivot -= insn.Operands[2].value

            # Check for operations
            if insn_op3 == idaapi.o_reg:
                insn_operations.add("reg-to-reg")
            elif insn_op3 == idaapi.o_phrase or insn_op3 == idaapi.o_displ:
                insn_operations.add("mem-to-reg")

        # Check second operand.
        if insn_op2 == idaapi.o_reg or insn_op2 == idaapi.o_displ:

            reg2_name = self.get_o_reg_name(insn, 1)
            insn_use_registers.add(reg2_name)

            # Check if the register is used or modified or both.
            if insn_feature & idaapi.CF_CHG2:
                insn_chg_registers.add(reg2_name)

            # Check if the third operand is used and if not determine the instruction type.
            if insn_feature & idaapi.CF_USE3 == 0:
                # Two operand register
                if insn_op2 == idaapi.o_reg:
                    insn_operations.add("reg-to-reg")

                # Two operand immediate
                elif insn_op2 == idaapi.o_imm:
                    insn_operations.add("imm-reg")

                # Two operand reference
                elif insn_op2 == idaapi.o_phrase or insn_op2 == idaapi.o_displ:
                    # Hack to try and determine if the instruction is a load or store instruction.
                    if insn_mnem[0] == "l":
                        insn_operations.add("mem-reg")
                    else:
                        insn_operations.add("reg-mem")

        # Check third operand.
        if insn_op3 == idaapi.o_reg:

            reg3_name = self.get_o_reg_name(insn, 2)

            # Check if the register is used or modified or both.
            if insn_feature & idaapi.CF_USE3:
                insn_use_registers.add(reg3_name)

            if insn_feature & idaapi.CF_CHG3:
                insn_chg_registers.add(reg3_name)

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

class ppc_Sploiter(Sploiter):
    def __init__(self):

        Sploiter.__init__(self)

        # Initialize fields specific to this architecture.
        self.bad_instructions = "sc, rfid, twi"

        self.reg_list = [ "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10",
                          "r11", "r12", "r13", "r14", "r15", "r16", "r17", "r18", "r19", "r20",
                          "r21", "r22", "r23", "r24", "r25", "r26", "r27", "r28", "r29", "r30", "r31" ]

    def is_func_ptr_supported(self):
        return False

    def get_func_ptr_instance(self):

        # Currently not supported.
        return None

    def get_rop_instance(self):

        return ppc_Rop(self)
		

class idasploiter_ppc_t(plugin_t):

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
    return idasploiter_ppc_t()