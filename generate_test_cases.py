#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
Created on Wed Oct  9 13:59:35 2019

@author: gfoudree
"""
from __future__ import print_function

import r2pipe
import binascii
import json

from triton     import TritonContext, ARCH, Instruction, MemoryAccess, CPUSIZE

def process(code):
    Triton = TritonContext()
    Triton.setArchitecture(ARCH.X86_64)
    for (addr, opcode) in code:
        # Build an instruction
        inst = Instruction()

        # Setup opcode
        inst.setOpcode(opcode)

        # Setup Address
        inst.setAddress(addr)

        # Process everything
        Triton.processing(inst)

        print(inst)
        for expr in inst.getSymbolicExpressions():
            print('\t', expr)
            
    for k, v in list(Triton.getSymbolicRegisters().items()):
        if 'rax' in str(Triton.getRegister(k)):
            print(Triton.getRegister(k), v)

def getFunctions():
    funcs = []
    f = open('test.c', 'r')
    for line in f.readlines():
        if 'main' not in line and '{' in line:
            func_name = line.split(' ')[1].split('(')[0]
            funcs.append(func_name)
    return funcs

p = r2pipe.open('./linear')
p.cmd('aaa')

for func in getFunctions():
    code = []
    funcData = p.cmdj('pdfj @ sym.' + func)
    funcName = funcData['name'].split('.')[1]
    for op in funcData['ops']:
        #print("{0}: [{1}], {2}".format(funcName, op['offset'], binascii.unhexlify(op['bytes'])))
        code.append(tuple((int(op['offset']), binascii.unhexlify(op['bytes']))))
    
    print("Processing " + funcName)
    process(code)
    print("\n")