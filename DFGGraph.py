#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Sep 20 11:01:54 2019

@author: gfoudree
"""
import networkx as nx
import pyvex

class DFGGraph():
    G = None
    arch = None
    nodeId = 0
    
    def __init__(self, arch):
        self.G = nx.DiGraph()
        self.arch = arch
        
    def addNode(self, name):
        self.G.add_node(self.nodeId, label=name)
        self.nodeId += 1
        return self.nodeId - 1 #Return ID
    
    def getGraphViz(self):
        return nx.nx_agraph.to_agraph(self.G)
    
    def getNodeFromLabel(self, label):
        for n in self.G.nodes().items():
            if n[1]['label'] == label:
                return n[0]
        return None
    
    def generateGraphFromIR(self, irsb):
        assert isinstance(irsb, pyvex.block.IRSB), "Expected VEX IR parameter!"
        
        for stmt in irsb.statements:
            #Skip statements we don't care about for dataflow
            if isinstance(stmt, pyvex.stmt.IMark) or isinstance(stmt, pyvex.stmt.AbiHint):
                continue
            #Skip instruction pointer changes
            if isinstance(stmt, pyvex.stmt.Put) and self.arch.register_names[stmt.offset] == 'rip':
                continue
            #Print actual VEX IR line
            print("[VEX Stmt] " + str(stmt))
            
            if isinstance(stmt, pyvex.stmt.WrTmp): # temp variable assignment (ex: t0 = 5)
                tmp_node = self.addNode("t" + str(stmt.tmp))
                if isinstance(stmt.data, pyvex.stmt.Get): # Is the data coming from a register?
                    register_name = self.arch.register_names[stmt.data.offset].upper()
                    print("t" + str(stmt.tmp) + " = \n" + register_name)
                    reg_node = self.addNode(register_name)
                    self.G.add_edge(tmp_node, reg_node)
                else:
                    stmtStr = str(stmt)
                    operation = stmtStr[0:stmtStr.find('(')].split("=")[1].strip()
                    opNode = self.addNode(operation)
                    self.G.add_edge(tmp_node, opNode)
                    
                    for exp in stmt.expressions:
                        for chi in exp.child_expressions:
                            print(chi)
                            childNode = self.addNode(str(chi))
                            self.G.add_edge(opNode, childNode)

            elif isinstance(stmt, pyvex.stmt.Store): # Can be a store to memory addr or temp var dereference
                print("Store *{0} = {1}".format(stmt.addr, stmt.data))
                
            elif isinstance(stmt, pyvex.stmt.Put): # Put register
                register_name = self.arch.register_names[stmt.offset].upper()
                print(register_name + " = \n" + str(stmt.data))
                regNode = self.addNode(register_name)
                
                if isinstance(stmt.data, pyvex.expr.Const):
                    constNode = self.addNode(str(stmt.data))
                    self.G.add_edge(regNode, constNode)
                else:
                    tmp_node = self.getNodeFromLabel(str(stmt.data))
                    self.G.add_edge(regNode, tmp_node)