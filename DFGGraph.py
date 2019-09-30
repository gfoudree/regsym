#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Sep 20 11:01:54 2019

@author: gfoudree
"""
import networkx as nx
import pyvex
import sys
import re

class DFGGraph():
    G = None
    dependencyGraph = None
    arch = None
    nodeId = 0
    dependencyGraphNodeId = 0
    tmpVarRegex = re.compile(r't\d+')
    
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
        
        if len(list(G.successors(V))) == 0: #Leaf node? Find other graphs with this node as root
            for subgraph in G.nodes().items():
                if subgraph[1]['label'] == nodeLabel and len(list(G.predecessors(subgraph[0]))) == 0:
                        G.add_edge(V, subgraph[0])
                        self.DFS(G, subgraph[0])
        for N in G.successors(V):
            if N not in visited:
                self.DFS(G, N, visited)
        return visited
    
    def mergeNodes(self, G):
        remove_edges = []
        remove_nodes = []
        add_edges = []
        for E in G.edges:
            n1Label = G.nodes[E[0]]['label']
            n2Label = G.nodes[E[1]]['label']
            
            if n1Label == n2Label and self.tmpVarRegex.match(n1Label) and self.tmpVarRegex.match(n2Label):
                print("Removing edge {0} -> {1}".format(n1Label, n2Label))
                remove_edges.append((E[0], E[1]))
                remove_nodes.append(E[0])
                
                parent = list(G.predecessors(E[0]))[0]
                add_edges.append((parent, E[1]))
        G.remove_edges_from(remove_edges)
        G.remove_nodes_from(remove_nodes)
        G.add_edges_from(add_edges)
        
    def generateDependencyGraph(self, register):
        registerNodeId = self.getNodeIdFromLabel(self.G, register + "_w") # Want the written value
        regNode = self.G.node(registerNodeId)
        assert len(list(self.G.predecessors(registerNodeId))) == 0, "Register should be the root node in the dependency graph!"
        #need to do a DFS or BFS on each node, building a new graph
        
        connectedNodes = self.DFS(self.G, registerNodeId)
        removeNodes = []
        for node in list(self.G.nodes):
            if node not in connectedNodes:
                removeNodes.append(node)
        self.G.remove_nodes_from(removeNodes)
        
        self.mergeNodes(self.G)
        #self.DFS_Equation(self.G, list(nx.topological_sort(self.G))[0])
        self.constPropogateDepGraph(self.G)
        return str(nx.nx_agraph.to_agraph(self.G))
    
    def constPropogateDepGraph(self, G):
        remove_edges = []
        remove_nodes = []
        add_edges = []
        for E in G.edges:
            n1Label = G.nodes[E[0]]['label']
            n2Label = G.nodes[E[1]]['label']
            n1OutDegree = len(list(G.successors(E[0])))
            n2OutDegree = len(list(G.successors(E[1])))
            
            if self.tmpVarRegex.match(n1Label) and not self.tmpVarRegex.match(n2Label) and n1OutDegree == 1 and len(list(G.predecessors(E[0]))) > 0:
                remove_edges.append((E[0], E[1]))
                remove_nodes.append(E[0])
                
                parent = list(G.predecessors(E[0]))[0]
                add_edges.append((parent, E[1]))
            elif self.tmpVarRegex.match(n2Label) and not self.tmpVarRegex.match(n1Label) and n2OutDegree == 1 and len(list(G.successors(E[1]))) > 0:
                remove_edges.append((E[0], E[1]))
                remove_nodes.append(E[1])
                
                successor = list(G.successors(E[1]))[0]
                add_edges.append((E[0], successor))            
            #print("{0} deg={1} -> {2} deg={3}".format(n1Label, n1OutDegree, n2Label, n2OutDegree))
            
        G.remove_edges_from(remove_edges)
        G.remove_nodes_from(remove_nodes)
        G.add_edges_from(add_edges)
    
    depth = 0
    def DFS_Equation(self, G, V, visited=[]):
        visited += [V]
        nodeLabel = G.nodes[V]['label']
        
        sys.stdout.write(nodeLabel + "=")
        for N in G.successors(V):
            if N not in visited:
                self.depth += 1
                self.DFS_Equation(G, N, visited)
            self.depth -= 1
    
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