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
    dependencyGraph = None
    arch = None
    nodeId = 0
    dependencyGraphNodeId = 0
    
    def __init__(self, arch):
        self.G = nx.DiGraph()
        self.arch = arch
        
    def addNode(self, name):
        self.G.add_node(self.nodeId, label=name)
        self.nodeId += 1
        return self.nodeId - 1 #Return ID
    
    def getGraphViz(self):
        return nx.nx_agraph.to_agraph(self.G)
    
    def getNodeIdFromLabel(self, graph, label):
        for node in graph.nodes().items():
            if 'label' in node[1].keys() and node[1]['label'] == label:
                return node[0]
        return None
    
    def DFS(self, G, V, visited=[]):
        visited += [V]
        
        nodeLabel = G.nodes[V]['label']
        if self.getNodeIdFromLabel(self.dependencyGraph, nodeLabel) == None:
            self.dependencyGraph.add_node(self.dependencyGraphNodeId, label=nodeLabel)
            self.dependencyGraphNodeId += 1
            print("Adding " + nodeLabel + " to final graph")
    
        prevnodes = list(G.predecessors(V))
        if len(prevnodes) > 0:
            prevNodeStr = G.nodes[prevnodes[0]]['label']
            print(G.nodes[V]['label'] + " Prev "  + prevNodeStr)
            self.dependencyGraph.add_edge(self.getNodeIdFromLabel(self.dependencyGraph, prevNodeStr), 
                                          self.getNodeIdFromLabel(self.dependencyGraph, nodeLabel))
            print(prevNodeStr + " -> " + nodeLabel)
            
        if len(list(G.successors(V))) == 0: #Leaf node? Find other graphs with this node as root
            for subgraph in G.nodes().items():
                if subgraph[1]['label'] == nodeLabel and len(list(G.predecessors(subgraph[0]))) == 0:
                        print("Found disjoint graph for " + nodeLabel)
                        print(nodeLabel + " -> " + subgraph[1]['label'])
                        self.DFS(G, subgraph[0])
                        
        for N in G.successors(V):
            if N not in visited:
                self.DFS(G, N, visited)
                
    def generateDependencyGraph(self, register):
        registerNodeId = self.getNodeIdFromLabel(self.G, register + "_w") # Want the written value
        regNode = self.G.node(registerNodeId)
        #assert len(self.G.predecessors(registerNodeId)) == 0, "Register should be the root node in the dependency graph!"
        #need to do a DFS or BFS on each node, building a new graph
        self.dependencyGraph = nx.DiGraph()
        self.DFS(self.G, registerNodeId)
        
        return str(nx.nx_agraph.to_agraph(self.dependencyGraph))
    
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
                    register_name = self.arch.register_names[stmt.data.offset].upper() + "_r" # _r = read
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
                register_name = self.arch.register_names[stmt.offset].upper() + "_w" # _w = write
                print(register_name + " = \n" + str(stmt.data))
                regNode = self.addNode(register_name)
                
                if isinstance(stmt.data, pyvex.expr.Const):
                    constNode = self.addNode(str(stmt.data))
                    self.G.add_edge(regNode, constNode)
                else:
                    tmp_node = self.getNodeIdFromLabel(self.G, str(stmt.data))
                    self.G.add_edge(regNode, tmp_node)