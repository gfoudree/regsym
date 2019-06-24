#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Jun 13 10:38:08 2019

@author: grantfoudree
"""

import r2pipe
import pyvex
import archinfo
import binascii

class BasicBlock():
    instructions = []
    callTargets = []
    jumpTargets = []
    startAddr = 0
    endAddr = 0
    size = 0
    ir = None
    
    def __init__(self, instructions, size, startAddr):
        self.size = size
        self.instructions = instructions
        self.startAddr = startAddr
        self.endAddr = startAddr + size
        self.genIr()
        
    def genIr(self):
        opcodeBytes = b""
        for instr in self.instructions:
            opcodeBytes += instr.opcodes

        #irsb = pyvex.lift(opcodeBytes, self.startAddr, archinfo.ArchAMD64())
        #self.ir = irsb
       
        
class Instruction():
    assembly = None
    opcodes = None
    addr = 0
    ir = None
    arch = archinfo.ArchAMD64()
    
    def __init__(self, assembly, opcodes, addr):
        self.assembly = assembly
        self.opcodes = binascii.unhexlify(opcodes)
        self.addr = addr
        self.ir = pyvex.lift(self.opcodes, addr, self.arch)
        
    def __str__ (self):
        output = ""
        for stmt in self.ir.statements:
            if isinstance(stmt, pyvex.stmt.Put):
                output += stmt.__str__(reg_name=self.arch.translate_register_name(stmt.offset,  stmt.data.result_size(self.ir.tyenv) // 8)) \
                    + "\n"
            elif isinstance(stmt, pyvex.stmt.Exit):
                output += stmt.__str__(reg_name=self.arch.translate_register_name(stmt.offsIP, self.ir.arch.bits //8)) + "\n"
            elif isinstance(stmt, pyvex.stmt.IMark):
                output += hex(stmt.addr) + ":\t" + self.assembly + "\n"
            elif isinstance(stmt, pyvex.stmt.WrTmp) and isinstance(stmt.data, pyvex.expr.Get):
                output += stmt.__str__(reg_name=self.arch.translate_register_name(stmt.data.offset, stmt.data.result_size(self.ir.tyenv) // 8)) + "\n"
            else:
                output += stmt.__str__() + "\n"
        return output
        
class Function():
    name = ""
    machine = None
    basicBlocks = []
    
    def __init__(self, funcName):
        self.name = funcName
        
        cfgJson = r2.cmdj('agj @ ' + funcName)[0]
        for block in cfgJson['blocks']: #For each basic block
            instrs = []
            for op in block['ops']: #For each instruction
                instr = Instruction(op['disasm'], op['bytes'], op['offset'])
                instrs.append(instr)
                #print(str(instr))
                #print("{}: {}".format(op['offset'], op['disasm']))
            bb = BasicBlock(instrs, block['size'], block['offset'])
            ##bb.pp()
            
            #Add exit addresses
            if 'switchop' in block.keys():
                for jmpTarget in block['switchop']:
                    bb.jumpTargets.append(jmpTarget)
            if 'jump' in block.keys():
                bb.jumpTargets.append(block['jump'])
            if 'fail' in block.keys():
                bb.jumpTargets.append(block['fail'])
            self.basicBlocks.append(bb)

    def getBasicBlockFromAddr(self, addr):
        for bb in self.basicBlocks:
            if bb.startAddr == addr:
                return bb
        return None
    
    def generateInstructionSlice(self, basicBlockAddrs):
        instructions = []
        for addr in basicBlockAddrs:
            bb = self.getBasicBlockFromAddr(addr)
            if bb == None:
                raise Exception("Address {} does not correspond to a basic block in function {}".format(addr, self.name))
            
            for inst in bb.instructions:
                instructions.append(inst)
        return instructions
            
r2 = r2pipe.open("a.out")
r2.cmd("aaa")

functions = r2.cmdj("aflj")

parsedFunctions = []
for _func in functions:
    name = _func['name']
    func = Function(_func['name'])
    parsedFunctions.append(func)