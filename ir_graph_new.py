import r2pipe
import pyvex
import archinfo
from hexdump import hexdump
import binascii
import networkx as nx
import matplotlib.pyplot as plt

def ir_build_graph(irsb):
    G = nx.DiGraph()
    node_id = 0
    labels = {}
    
    for stmt in irsb.statements:
        if isinstance(stmt, pyvex.stmt.IMark) or isinstance(stmt, pyvex.stmt.AbiHint):
            continue
        print(stmt)
        
        tmpVar = ""
        if isinstance(stmt, pyvex.stmt.WrTmp): # tx = ....
            tmpVar = "t{}".format(stmt.tmp)
            print(tmpVar + " =")
            G.add_node(node_id, value=tmpVar)
            labels[node_id] = tmpVar
            node_id += 1
            
        elif isinstance(stmt, pyvex.stmt.Store):
            print("Store")
        elif isinstance(stmt, pyvex.stmt.Put):
            continue
            print("Put")

        #print(stmt.data)
        stmtStr = str(stmt.data)
        operation = stmtStr[0:stmtStr.find('(')]
        print(operation)
        
        
        G.add_node(node_id, value=str(operation))
        labels[node_id] = str(operation)
        
        G.add_edge(node_id - 1, node_id)
        parent_id = node_id
        
        node_id += 1
        for exp in stmt.expressions:
            for chi in exp.child_expressions:
                print(chi)
                G.add_node(node_id, value=str(chi))
                labels[node_id] = str(chi)
                G.add_edge(parent_id, node_id)
                node_id += 1
        print("-"*20 + "\n")
        
    
    pos = nx.circular_layout(G)
    nx.draw_circular(G, node_size=200, with_labels=False)
    nx.draw_networkx_labels(G, pos, labels, font_size=9)
    plt.savefig("graph.png", format="PNG")
    return G

r2 = r2pipe.open("./linear")
r2.cmd('aaaa')
r2.cmd('s sym._baz')

fn_info = r2.cmdj('afij')[0]

fn_machinecode = r2.cmd('pcs ' + str(fn_info['size'])).strip()
fn_machinecode = binascii.unhexlify(fn_machinecode.replace(b'\\', b'').replace(b'x', b'').decode('utf-8')[1:-1])
hexdump(fn_machinecode)

base_addr = fn_info['offset']
arch = archinfo.ArchAMD64()

irsb = pyvex.lift(fn_machinecode, base_addr, arch)

ir_build_graph(irsb)