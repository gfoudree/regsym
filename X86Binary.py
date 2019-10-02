#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Sep 20 10:32:29 2019

@author: gfoudree
"""
import r2pipe
import pyvex
import archinfo
import binascii
from hexdump import hexdump

class X86Binary():
    filename = ""
    radarePipe = ""
    arch = ""
    
    def __init__(self, filepath, arch = archinfo.ArchAMD64()):
        self.filename = filepath
        self.radarePipe = r2pipe.open(filepath)
        self.radarePipe.cmd("aaaa")
        self.arch = arch
        
    def getBinaryChunkOfFunction(self, funcName):
        fn_info = self.getFunctionInfo(funcName)
        
        fn_machinecode = self.radarePipe.cmd('pcs ' + str(fn_info['size'])).strip()
        fn_machinecode = binascii.unhexlify(fn_machinecode.replace('\\', '').replace('x', '')[1:-1])
        
        return fn_machinecode
    
    def getFunctionInfo(self, funcName):
        self.radarePipe.cmd("s sym." + funcName)
        return self.radarePipe.cmdj('afij')[0]
    
    def getVEXIROfFunction(self, funcName):
        fn_info = self.getFunctionInfo(funcName)
        fn_machinecode = self.getBinaryChunkOfFunction(funcName)
        
        return pyvex.lift(fn_machinecode, fn_info['offset'], self.arch, opt_level=2)