#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Jun 25 12:04:19 2019

@author: grantfoudree
"""

import networkx as nx
import matplotlib.pyplot as plt

G = nx.DiGraph()
varDefs = "t0:Ity_I64 t1:Ity_I64 t2:Ity_I64 t3:Ity_I64 t4:Ity_I64 t5:Ity_I64 t6:Ity_I64 t7:Ity_I64 t8:Ity_I64 t9:Ity_I32 t10:Ity_I64 t11:Ity_I64"

def generateVarNodes(varDefs, G):
    regs = ['rax', 'rsi', 'rdi', 'rsp']
    for var in varDefs.split(" "):
        G.add_node(var.split(":")[0])
    for reg in regs:
        G.add_node(reg)
        
def generateDDG(ir, G):
    for line in ir.split("\n"):
        stmt = line.split(" = ")
        lhs = stmt[0]
        rhs = stmt[1]
        if lhs[0] == 't': #It's an assignment to a tmp variable
            if rhs[0] == 't':
                G.add_edge(lhs, rhs)
            else: #Have a ADD(), etc...
                startIndex = rhs.find('(')
                endIndex = rhs.find(')')
                dependencies = rhs[startIndex+1:endIndex].split(",")
                for dep in dependencies:
                    if dep[0] == '0':
                        continue
                    G.add_edge(lhs, dep)
ir = """t6 = GET:I64(rsi)
t7 = GET:I64(rdi)
t4 = Add64(t7,t6)
t9 = 64to32(t4)
t8 = 32Uto64(t9)
PUT(rax) = t8
PUT(rip) = 0x000000000000112c
t1 = GET:I64(rsp)
t2 = LDle:I64(t1)
t3 = Add64(t1,0x0000000000000008)
PUT(rsp) = t3
t10 = Sub64(t3,0x0000000000000080)"""

if __name__ == '__main__':
    generateVarNodes(varDefs, G)
    generateDDG(ir, G)
    nx.draw(G, with_labels=True, font_weight='bold')
    plt.show()