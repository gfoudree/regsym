#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Sep 24 11:47:00 2019

@author: gfoudree
"""

import networkx as nx

def graphContainsLabel(graph, label):
    for node in graph.nodes().items():
        if 'label' in node[1].keys() and node[1]['label'] == label:
            return True
    return False

def getNodeIdFromLabel(graph, label):
    for node in graph.nodes().items():
        if 'label' in node[1].keys() and node[1]['label'] == label:
            return node[0]
    return None

G2 = nx.DiGraph()
nodeId = 0
def DFS(G, V, visited=[]):
    visited += [V]
    
    global G2
    global nodeId
    
    nodeLabel = G.nodes[V]['label']
    if not graphContainsLabel(G2, nodeLabel):
        G2.add_node(nodeId, label=nodeLabel)
        nodeId += 1
        print("Adding " + nodeLabel + " to final graph")

    prevnodes = list(G.predecessors(V))
    if len(prevnodes) > 0:
        prevNodeStr = G.nodes[prevnodes[0]]['label']
        print(G.nodes[V]['label'] + " Prev "  + prevNodeStr)
        G2.add_edge(getNodeIdFromLabel(G2, prevNodeStr), getNodeIdFromLabel(G2, nodeLabel))
        print(prevNodeStr + " -> " + nodeLabel)
        
    if len(list(G.successors(V))) == 0: #Leaf node? Find other graphs with this node as root
        for subgraph in G.nodes().items():
            if subgraph[1]['label'] == nodeLabel and len(list(G.predecessors(subgraph[0]))) == 0:
                    print("Found disjoint graph for " + nodeLabel)
                    print(nodeLabel + " -> " + subgraph[1]['label'])
                    DFS(G, subgraph[0])
                    
    for N in G.successors(V):
        if N not in visited:
            DFS(G, N, visited)

cfg = nx.DiGraph()
cfg.add_node(1, label="1")
cfg.add_node(2, label="2")
cfg.add_node(3, label="3r")

cfg.add_node(4, label="3r")
cfg.add_node(5, label="4")
cfg.add_node(6, label="7")
cfg.add_node(7, label="8")

cfg.add_node(8, label="4")
cfg.add_node(9, label="9")
cfg.add_node(10, label="10")
cfg.add_node(11, label="11")

# Disconnected graph
cfg.add_node(12, label='22')
cfg.add_node(13, label='25')
cfg.add_node(14, label='27')

cfg.add_edges_from([(1,2), (1, 3), (4, 5), (4, 6), (6, 7), (8, 9), (9, 10), (9, 11), (12, 13), (12, 14)])

print(nx.nx_agraph.to_agraph(cfg))

DFS(cfg, 1)

print(nx.nx_agraph.to_agraph(G2))