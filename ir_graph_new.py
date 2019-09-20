import r2pipe
import pyvex
import archinfo
from hexdump import hexdump
import binascii
import networkx as nx
import matplotlib.pyplot as plt

arch = archinfo.ArchAMD64()

def ir_build_graph(irsb):
    G = nx.DiGraph()
    node_id = 0
    labels = {}
    
    for stmt in irsb.statements:
        #Skip statements we don't care about for dataflow
        if isinstance(stmt, pyvex.stmt.IMark) or isinstance(stmt, pyvex.stmt.AbiHint):
            continue
        #Skip instruction pointer changes
        if isinstance(stmt, pyvex.stmt.Put) and arch.register_names[stmt.offset] == 'rip':
            continue
        #Print actual VEX IR line
        print("[VEX Stmt] " + str(stmt))
        
        tmpVar = ""
        if isinstance(stmt, pyvex.stmt.WrTmp): # temp variable assignment (ex: t0 = 5)
            tmpVar = "t{}".format(stmt.tmp)
            G.add_node(node_id, label=tmpVar) # Create datanode for tmp variable
            labels[node_id] = tmpVar
            node_id += 1
            
            if isinstance(stmt.data, pyvex.stmt.Get): # t0 = Get(___) ?
                register_name = arch.register_names[stmt.data.offset].upper()
                print(tmpVar + " = \n" + register_name)
                G.add_node(node_id, label=register_name)
                labels[node_id] = register_name
                G.add_edge(node_id - 1, node_id)
                node_id += 1
                continue
            
            stmtStr = str(stmt)
            operation = stmtStr[0:stmtStr.find('(')].split("=")[1].strip()
            print(tmpVar + " =\n" + operation)
            
            G.add_node(node_id, label=str(operation))
            labels[node_id] = str(operation)
            
            G.add_edge(node_id - 1, node_id)
            parent_id = node_id
            
            node_id += 1
            for exp in stmt.expressions:
                for chi in exp.child_expressions:
                    print(chi)
                    G.add_node(node_id, label=str(chi))
                    labels[node_id] = str(chi)
                    G.add_edge(parent_id, node_id)
                    node_id += 1
            
        elif isinstance(stmt, pyvex.stmt.Store): #Can be a store to memory addr or temp var dereference
            #register_name = arch.register_names[stmt.data.offset]
            print("Store *{0} = {1}".format(stmt.addr, stmt.data))
            
        elif isinstance(stmt, pyvex.stmt.Put): # Put register
            register_name = arch.register_names[stmt.offset].upper()
            print(register_name + " = \n" + str(stmt.data))
            
            """ Find two nodes and link them - This is an issue b/c we are unsure of the dependency ordering...
            reg_node_id = 0
            tmpvar_node_id = 0
            if register_name in labels.values(): #Look up node ID for register otherwise add it
                reg_node_id = list(labels.keys())[list(labels.values()).index(register_name)]
            else:
                G.add_node(node_id, label=register_name)
                labels[node_id] = register_name
                reg_node_id = node_id
                node_id += 1
                
            if stmt.data in labels.values():
                tmpvar_node_id = list(labels.keys())[list(labels.values()).index(str(stmt.data))]
            else:
                G.add_node(node_id, label=str(stmt.data))
                labels[node_id] = str(stmt.data)
                tmpvar_node_id = node_id
                node_id += 1
            
            G.add_edge(reg_node_id, tmpvar_node_id)
            """
            G.add_node(node_id, label=register_name)
            labels[node_id] = register_name
            reg_node_id = node_id
            node_id += 1
            
            if isinstance(stmt.data, pyvex.expr.Const):
                G.add_node(node_id, label=str(stmt.data))
                labels[node_id] = str(stmt.data)
                G.add_edge(reg_node_id, node_id)
                
                node_id += 1
            else:
                tmpvar_node_id = list(labels.keys())[list(labels.values()).index(str(stmt.data))]
                G.add_edge(reg_node_id, tmpvar_node_id)
            
        #print(stmt.data)
        
        print("-"*20 + "\n")
        
    #pos = nx.circular_layout(G)
    #nx.draw_circular(G, node_size=200, with_labels=False)
    #nx.draw_networkx_labels(G, pos, labels, font_size=9)
    
    print(nx.nx_agraph.to_agraph(G))
    #plt.savefig("graph.png", format="PNG")
    return G

r2 = r2pipe.open("./linear")
r2.cmd('aaaa')
r2.cmd('s sym._baz')

fn_info = r2.cmdj('afij')[0]

fn_machinecode = r2.cmd('pcs ' + str(fn_info['size'])).strip()
fn_machinecode = binascii.unhexlify(fn_machinecode.replace('\\', '').replace('x', '')[1:-1])
hexdump(fn_machinecode)

base_addr = fn_info['offset']

irsb = pyvex.lift(fn_machinecode, base_addr, arch)

G = ir_build_graph(irsb)