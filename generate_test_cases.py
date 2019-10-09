#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Oct  9 13:59:35 2019

@author: gfoudree
"""
import r2pipe
import binascii
import json

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
    funcData = p.cmdj('pdfj @ sym.' + func)
    funcName = funcData['name']
    for op in funcData['ops']:
        print("{0}: [{1}], {2}".format(funcName, op['offset'], bytes.fromhex(op['bytes'])))