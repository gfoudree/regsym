#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Sep 20 12:50:40 2019

@author: gfoudree
"""
from X86Binary import *
from DFGGraph import *

if __name__ == '__main__':
    b = X86Binary('./linear')
    irsb = b.getVEXIROfFunction('_baz')
    G = DFGGraph(b.arch)
    G.generateGraphFromIR(irsb)
    print(G.getGraphViz())
    
    print("*"*30)
    print(G.generateDependencyGraph('RAX'))