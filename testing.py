#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Sep 24 11:47:00 2019

@author: gfoudree
"""

import networkx as nx

G2 = nx.DiGraph()

def DFS(G, V, visited=[]):
    visited += [V]
    
    if V not in G2:
        G2.add_node(V, label=G.nodes[V]['label'])
        print("Adding node to final graph: " + G.nodes[V]['label'])
        
    prevnodes = list(G.predecessors(V))
    if len(prevnodes) > 0:
        prevNodeStr = G.nodes[prevnodes[0]]['label']
        print(G.nodes[V]['label'] + " Prev "  + prevNodeStr)
        G2.add_edge(prevnodes[0], V)
        print(prevNodeStr + " -> " + G.nodes[V]['label'])
    else:
        print(G.nodes[V]['label'])
    
        
    if len(list(G.successors(V))) == 0: #Leaf node? Find other graphs with this node as root
        for subgraph in G.nodes().items():
            if subgraph[1]['label'] == G.nodes[V]['label'] and len(list(G.predecessors(subgraph[0]))) == 0:
                    print("Found disjoint graph for " + G.nodes[V]['label'])
                    
                    if V not in G2:
                        G2.add_node(subgraph[0], label=subgraph[1]['label'])
                        print("Adding node to final graph: " + subgraph[1]['label'])
                    G2.add_edge(V, subgraph[0])
                    print(G.nodes[V]['label'] + " -> " + subgraph[1]['label'])
                    DFS(G, subgraph[0])
    for N in G.successors(V):
        if N not in visited:
            DFS(G, N, visited)

cfg = nx.DiGraph()
cfg.add_node(1, label="1")
cfg.add_node(2, label="2")
cfg.add_node(3, label="3")

cfg.add_node(4, label="3")
cfg.add_node(5, label="4")
cfg.add_node(6, label="7")
cfg.add_node(7, label="8")

cfg.add_node(8, label="4")
cfg.add_node(9, label="9")
cfg.add_node(10, label="10")
cfg.add_node(11, label="11")

cfg.add_edges_from([(1,2), (1, 3), (4, 5), (4, 6), (6, 7), (8, 9), (9, 10), (9, 11)])

print(nx.nx_agraph.to_agraph(cfg))

DFS(cfg, 1)

print(nx.nx_agraph.to_agraph(G2))
