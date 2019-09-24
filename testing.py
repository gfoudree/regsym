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
    
    print(G.nodes[V]['label'])

    if len(list(G.successors(V))) == 0: #Leaf node? Find other graphs with this node as root
        for subgraph in G.nodes().items():
            if subgraph[1]['label'] == G.nodes[V]['label'] and len(list(G.predecessors(subgraph[0]))) == 0:
                    print("Found disjoint graph for " + G.nodes[V]['label'])
    for N in G.successors(V):
        if N not in visited:
            DFS(G, N, visited)

G = nx.DiGraph()
G.add_node(1, label="1")
G.add_node(2, label="2")
G.add_node(3, label="3")

G.add_node(4, label="3")
G.add_node(5, label="4")
G.add_node(6, label="7")
G.add_node(7, label="8")

G.add_node(8, label="4")
G.add_node(9, label="9")
G.add_node(10, label="10")
G.add_node(11, label="11")

G.add_edges_from([(1,2), (1, 3), (4, 5), (4, 6), (6, 7), (8, 9), (9, 10), (9, 11)])

print(nx.nx_agraph.to_agraph(G))

DFS(G, 8)