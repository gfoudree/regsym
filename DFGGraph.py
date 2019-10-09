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
                graphLabel = subgraph[1]['label']
                graphPredecessors = len(list(G.predecessors(subgraph[0])))
                if graphLabel == nodeLabel and graphPredecessors == 0:
                        G.add_edge(V, subgraph[0])
                        self.DFS(G, subgraph[0])
                elif graphLabel == nodeLabel and graphPredecessors == 1:
                    predNode = list(G.predecessors(subgraph[0]))[0]
                    predNodeLabel = G.nodes[predNode]['label']
                    if predNodeLabel == graphLabel:
                        G.add_edge(V, subgraph[0])
                        self.DFS(G, subgraph[0])

        for N in G.successors(V):
            #if N not in visited:
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
        
    def getSubgraphs(self):
        subGraphs = []
        for node in self.G.nodes().items():
            numPredecessors = len(list(self.G.predecessors(node[0])))
            if numPredecessors == 0 or (numPredecessors == 1 and self.G.nodes[list(self.G.predecessors(node[0]))[0]]['label'] == node[1]['label']):
                subGraphs.append(node[0])
        return subGraphs
    
    def getPreorderTraversal(self, node):
            # Start comparing from the 2nd node downward for equality 
            nextNode = list(self.G.successors(node))[0]
            
            traversal = list(nx.dfs_preorder_nodes(self.G, nextNode))
            traversalLabels = [] # List of the labels of the nodes in preorder
            for n in traversal:
                traversalLabels.append(self.G.nodes[n]['label'])
            return traversalLabels
    
    def mergeRedundantTmpVars(self):
        redundantGraphs = set()
        nodesInGraph = []
        edgesInGraph = []
        
        for subgraph in self.getSubgraphs():
            labels = self.getPreorderTraversal(subgraph)
                
            for sub_subgraph in self.getSubgraphs():
                sub_labels = self.getPreorderTraversal(sub_subgraph)
                
                if labels == sub_labels and sub_subgraph != subgraph:
                    redundantGraphs.add(tuple(sorted(tuple((subgraph, sub_subgraph)))))
        
        for redundantGraph in redundantGraphs:
            # Queue deletion of G2 from subgraph pool
            nodesInGraph.extend(list(nx.dfs_postorder_nodes(self.G, redundantGraph[1])))
            edgesInGraph.extend(list(nx.dfs_edges(self.G, redundantGraph[1])))
            
            # Merge references to the root node of G2 with G1
            g2Name = self.G.nodes[redundantGraph[1]]['label']
            g1Name = self.G.nodes[redundantGraph[0]]['label']
            print("{0} == {1}, Replacing all references to {0} with {1}".format(g2Name, g1Name))
            
            for n in self.G.nodes().items():
                if n[1]['label'] == g2Name:
                    n[1]['label'] = g1Name
                    
        self.G.remove_nodes_from(nodesInGraph)
        self.G.remove_edges_from(edgesInGraph)
        
    def patchUpLoadStores(self, G):
        # This fixes up the bug where store tmp variables depend on a store instruction 
        # instead of the other way around...
        # AKA (https://imgur.com/a/BhrJlLc) -> https://imgur.com/a/LNS80jW
        deleteEdges = []
        addEdges = []
        
        for node in G.nodes().items():
            if 'STLe' in node[1]['label']: #Store operation node
                # Change incoming edge to be an outgoing edge to that same node
                prevNode = list(G.predecessors(node[0]))[0]
                deleteEdges.append((prevNode, node[0]))
                addEdges.append((node[0], prevNode))
                
        G.remove_edges_from(deleteEdges)
        G.add_edges_from(addEdges)
        
    def generateDependencyGraph(self, register):
        registerNodeId = self.getNodeIdFromLabel(self.G, register + "_w") # Want the written value
        regNode = self.G.node(registerNodeId)
        assert len(list(self.G.predecessors(registerNodeId))) == 0, "Register should be the root node in the dependency graph!"
        #need to do a DFS or BFS on each node, building a new graph
        
        self.mergeRedundantTmpVars()
        
        connectedNodes = self.DFS(self.G, registerNodeId)
        removeNodes = []
        for node in list(self.G.nodes):
            if node not in connectedNodes:
                removeNodes.append(node)
        self.G.remove_nodes_from(removeNodes)
        
        self.mergeNodes(self.G)
        self.constPropogateDepGraph(self.G)
        
        self.patchUpLoadStores(self.G)
        #self.DFS_Equation(self.G, list(nx.topological_sort(self.G))[0])
        print("\n")
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
        
        if len(list(G.successors(V))) > 1:
            sys.stdout.write(nodeLabel + ",")
        else:
            sys.stdout.write(nodeLabel + "(")
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
            #print("[VEX Stmt] " + str(stmt))
            
            if isinstance(stmt, pyvex.stmt.WrTmp): # temp variable assignment (ex: t0 = 5)
                tmp_node = self.addNode("t" + str(stmt.tmp))
                if isinstance(stmt.data, pyvex.stmt.Get): # Is the data coming from a register?
                    register_name = self.arch.register_names[stmt.data.offset].upper() + "_r" # _r = read
                    #print("t" + str(stmt.tmp) + " = \n" + register_name)
                    reg_node = self.addNode(register_name)
                    self.G.add_edge(tmp_node, reg_node)
                else:
                    stmtStr = str(stmt)
                    operation = stmtStr[0:stmtStr.find('(')].split("=")[1].strip()
                    opNode = self.addNode(operation)
                    self.G.add_edge(tmp_node, opNode)
                    
                    for exp in stmt.expressions:
                        for chi in exp.child_expressions:
                            #print(chi)
                            childNode = self.addNode(str(chi))
                            self.G.add_edge(opNode, childNode)

            elif isinstance(stmt, pyvex.stmt.Store): # Can be a store to memory addr or temp var dereference
                #print("Store *{0} = {1}".format(stmt.addr, stmt.data))
                tmp_node = self.getNodeIdFromLabel(self.G, str(stmt.data))
                pointer_node = self.getNodeIdFromLabel(self.G, str(stmt.addr))
                op = self.addNode("STLe({})".format(str(stmt.addr)))
                self.G.add_edge(pointer_node, op)
                self.G.add_edge(op, tmp_node)
                
            elif isinstance(stmt, pyvex.stmt.Put): # Put register
                register_name = self.arch.register_names[stmt.offset].upper() + "_w" # _w = write
                #print(register_name + " = \n" + str(stmt.data))
                regNode = self.addNode(register_name)
                
                if isinstance(stmt.data, pyvex.expr.Const):
                    constNode = self.addNode(str(stmt.data))
                    self.G.add_edge(regNode, constNode)
                else:
                    tmp_node = self.getNodeIdFromLabel(self.G, str(stmt.data))
                    self.G.add_edge(regNode, tmp_node)