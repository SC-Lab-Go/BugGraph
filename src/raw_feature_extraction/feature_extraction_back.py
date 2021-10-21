import idc
import idaapi
import idautils
import networkx as nx
from sets import Set

class func_block_class:
    def __init__(self):
        self.block_id = 0
        self.func_name = ""
        self.func_id = 0
        self.block_id_in_func = 0
        self.block_type = 0
        self.start_addr = 0
        self.end_addr = 0


class block_class:
    def __init__(self):
        self.function = ""
        self.block_id = ""
        self.block_id_in_func = 0
# Statistical Features
        self.numeric_constants = 0
        self.string_constants = 0
        self.num_transfer_instruc = 0
        self.num_calls = 0
        self.num_instruc = 0
        self.num_arith_instruc = 0
        self.num_logic = 0
#        self.num_local_variable = 0
# Structural Features
        self.num_offspring = 0
        self.betweenness = 0.0
#        self.edges = 0

    def write_file(self, file_name):
        line = str(self.block_id) + "," + str(self.numeric_constants) + "," + str(self.string_constants) + "," + str(self.num_transfer_instruc) + "," + str(self.num_calls) + "," + str(self.num_instruc) + "," + str(self.num_arith_instruc) + "," + str(self.num_logic) + "," + str(self.num_offspring) + "," + str(self.betweenness)
        fp = open(file_name, "a")
        fp.write(line + "\n")
        fp.close()

def write_head(file_name):
    log = open(file_name, "w")
    line = "block_id.func_id,numeric constants,string constants,No. of transfer instructions,No. of calls,No. of instructinos,No. of arithmetic instructions,No. of logic instructions,No. of offspring,betweenness centrality"
    log.write(line + "\n")
    log.close()


# statistical feature 1: num of numeric constants
def check_numeric_constants(instruc, offset):
    optype1 = GetOpType(instruc, offset)
#    optype2 = GetOpType(instruc, 1)
    if optype1 == 5:# or optype2 == 5:
        return True
    return False

def check_transfer_instruc(m):
    x86_TI = {'jmp':1, 'jz':1, 'jnz':1, 'js':1, 'je':1, 'jne':1, 'jg':1, 'jle':1, 'jge':1, 'ja':1, 'jnc':1, 'call':1}
    mips_TI = {'beq':1, 'bne':1, 'bgtz':1, "bltz":1, "bgez":1, "blez":1, 'j':1, 'jal':1, 'jr':1, 'jalr':1}
    arm_TI = {'MVN':1, "MOV":1}

    transfer_set = {}
    transfer_set.update(x86_TI)
    transfer_set.update(mips_TI)
    transfer_set.update(arm_TI)

    if m in transfer_set:
        return True
    return False

def check_calls_instruc(m):
    call_set = {'call':1, 'jal':1, 'jalr':1}
    if m in call_set:
        return True
    return False

def check_logic_instruc(m):
    x86_LI = {'and':1, 'andn':1, 'andnpd':1, 'andpd':1, 'andps':1, 'andnps':1, 'test':1, 'xor':1, 'xorpd':1, 'pslld':1}
    mips_LI = {'and':1, 'andi':1, 'or':1, 'ori':1, 'xor':1, 'nor':1, 'slt':1, 'slti':1, 'sltu':1}
    logic_set = {}
    logic_set.update(x86_LI)
    logic_set.update(mips_LI)
    if m in logic_set:
        return True
    return False

def check_arith_instruc(m):
    x86_AI = {'add':1, 'sub':1, 'div':1, 'imul':1, 'idiv':1, 'mul':1, 'shl':1, 'dec':1, 'inc':1}
    mips_AI = {'add':1, 'addu':1, 'addi':1, 'addiu':1, 'mult':1, 'multu':1, 'div':1, 'divu':1}
    arith_set = {}
    arith_set.update(x86_AI)
    arith_set.update(mips_AI)

    if m in arith_set:
        return True
    return False



def getConst(ea, offset):
    strings = []
    consts = []
    optype1 = GetOpType(ea, offset)
    if optype1 == idaapi.o_imm:
        imm_value = GetOperandValue(ea, offset)
        if 0<= imm_value <= 10:
            consts.append(imm_value)
        else:
            if idaapi.isLoaded(imm_value) and idaapi.getseg(imm_value):
                str_value = GetString(imm_value)
                if str_value is None:
                    str_value = GetString(imm_value+0x40000)
                    if str_value is None:
                        consts.append(imm_value)
                    else:
                        re = all(40 <= ord(c) < 128 for c in str_value)
                        if re:
                            strings.append(str_value)
                        else:
                            consts.append(imm_value)
                else:
                    re = all(40 <= ord(c) < 128 for c in str_value)
                    if re:
                        strings.append(str_value)
                    else:
                        consts.append(imm_value)
            else:
                consts.append(imm_value)
    return len(strings), len(consts)

def get_local_variable(func):
    return 0

def get_stackVariables(func_addr):
    #print func_addr
    args = []
    stack = GetFrame(func_addr)
    if not stack:
        return 0
    firstM = GetFirstMember(stack)
    lastM = GetLastMember(stack)
    i = firstM
    while i <=lastM:
        mName = GetMemberName(stack,i)
        mSize = GetMemberSize(stack,i)
        if mSize:
            i = i + mSize
        else:
            i = i+4
        if mName not in args and mName and 'var_' in mName:
            args.append(mName)
    return len(args)

def get_statistical_feature(instruc, block_feature):

# get the Mnemonic of the instruction
    m = idc.GetMnem(instruc)

# statistical feature 4: num of instructions
    block_feature.num_instruc += 1

# statistical feature 1, 2: num of numeric constants & num of string constants
#    if check_numeric_constants(instruc, 0) == True:
#        block_feature.numeric_constants += 1
#
#    if check_numeric_constants(instruc, 1) == True:
#        block_feature.numeric_constants += 1

    num_str, num_const = getConst(instruc, 0)
    block_feature.numeric_constants += num_const
    block_feature.string_constants += num_str

    num_str, num_const = getConst(instruc, 1)
    block_feature.numeric_constants += num_const
    block_feature.string_constants += num_str

# statistical feature 3: num of transfer instructions
    if check_transfer_instruc(m) == True:
        block_feature.num_transfer_instruc += 1

# statistical feature 4: num of calls instructions
        if check_calls_instruc(m) == True:
            block_feature.num_calls += 1

# statistical feature 5: num of arithmatic instructions
    if check_arith_instruc(m) == True:
        block_feature.num_arith_instruc += 1

# statistical feature 6: num of logic instructions
    if check_logic_instruc(m) == True:
        block_feature.num_logic += 1

# statistical feature 7: num of local variables


# graph feature 1: no. of offsprings
def get_offsprings(block, block_feature, out_file):
    out_degree = 0
    for succ_block in block.succs():
        out_degree += 1
    block_feature.num_offspring = out_degree


#def get_func_cfg(fp, func, func_id):
#
#    flow_chart = idaapi.FlowChart(idaapi.get_func(func))
#    fp.write(" " + str(flow_chart.size) + "\n")
#    for block in flow_chart:
#        line = "\t" + str(block.id) + ":"
#        for succ_block in block.succs():
#            line += " " + str(succ_block.id)
#        fp.write(line + "\n")

# graph feature 2: betweenness
# 1. store the cfg to networkx, 2. networkx generates BC, 3.
def get_betweenness(flow_chart):

#    fp = open("test_bc.txt", "w")
    func_cfg = nx.DiGraph()

    for block in flow_chart:
        func_cfg.add_node(block.id)
        for succ_block in block.succs():
            func_cfg.add_node(succ_block.id)
            func_cfg.add_edge(block.id, succ_block.id)
#    fp.write("before %d %d\n" %(func_cfg.number_of_nodes(), func_cfg.number_of_edges()))
#    bc = nx.betweenness_centrality(func_cfg)
#    fp.write("bc" + str(bc[0]))
#    fp.close()

    return nx.betweenness_centrality(func_cfg)


def iterate_each_block(block, block_feature):
    cur_ad = block.startEA
    end_ad = block.endEA

    get_offsprings(block, block_feature, out_file)
    while cur_ad < end_ad:
        get_statistical_feature(cur_ad, block_feature)
        cur_ad = NextHead(cur_ad)

def feature_extraction(out_file, block_key_id, func_name_id):

    write_head(out_file)
# iterate all the functions
#    fp = open(out_file, "a")
    for func in idautils.Functions():
        func_name = GetFunctionName(func)
# iterate the basic block of each flow graph
        flow_chart = idaapi.FlowChart(idaapi.get_func(func))

# graph feature 2: betweenness centrality
        func_bc = get_betweenness(flow_chart)
        for block in flow_chart:
            block_feature = block_class()
# function name
            block_feature.function = func_name

            func_id = func_name_id[func_name]
## block id in func
            block_feature.block_id_in_func = block.id

# block index
            block_feature.block_id = block_key_id[str(func_id) + "." + str(block.id)]

            block_feature.betweenness = func_bc[block.id]

            iterate_each_block(block, block_feature)
            block_feature.write_file(out_file)
#    fp.close()


# First step: simply iterate each function and store them into a dict
def iterate_func():
    dict_func_id = {}
    index = 0
    fp = open("func_to_id.csv", "w")
    fp.write("func_id" + "," + "func_name" + "\n")
    for func in idautils.Functions():
        func_name = GetFunctionName(func)
        dict_func_id[func_name] = index
        fp.write(str(index) + "," + func_name + "\n")
        index += 1

    fp.close()
    return dict_func_id

def get_func_call_graph(func_name_to_id):
    fcg = nx.DiGraph()

#    os.system("echo 'in fcg' >> debug.log")
    # traverse all the functions
    for func in idautils.Functions():
        func_name = GetFunctionName(func)
        if func_name not in func_name_to_id:
            continue
#            os.system("echo 'func_name not in func_name_to_id' >> debug.log")
        src_id = func_name_to_id[func_name]

        fcg.add_node(src_id)
        adj_set = Set()
        adj_set.add(src_id)


#        line = func_name
        # traverse all the instructions in a specific function
        instru_list = list(idautils.FuncItems(func))
        for instru in instru_list:
# check the Code reference from this instruction
            for call_addr in idautils.CodeRefsFrom(instru, 0):
                out_func_name = GetFunctionName(call_addr)

                if out_func_name not in func_name_to_id:
                    continue
#                    os.system("echo 'out_func_name not in func_name_to_id' >> debug.log")
                dest_id = func_name_to_id[out_func_name]
                # remove redundant edges
                if dest_id in adj_set:
                    continue
#                else:
                adj_set.add(dest_id)
                fcg.add_edge(src_id, dest_id)
#                line += "! " + out_func_name
        #fp.write(line + "\n")
#    fp.close()
#    fp.close()
#    fp = open("fcg_edge_list.graph", "a")
#    fp.write("v_count = %d, e_count = %d\n" %(len(func_name_to_id), len(edge_set)))
    os.system("echo 'before output of fcg' >> debug.log")
    fp = open("fcg_edge_list.graph", "w")
    fp.write("# v_count = %d, e_count = %d\n" %(fcg.number_of_nodes(), fcg.number_of_edges()))
    nx.write_edgelist(fcg, fp, data = False)
    fp.close()


#def get_func_cfg(fp, func, func_id):
#
#    flow_chart = idaapi.FlowChart(idaapi.get_func(func))
#    fp.write(" " + str(flow_chart.size) + "\n")
#    for block in flow_chart:
#        line = "\t" + str(block.id) + ":"
#        for succ_block in block.succs():
#            line += " " + str(succ_block.id)
#        fp.write(line + "\n")

def get_control_flow_graph(func_name_to_id):
    cfg = nx.DiGraph()
    block_id_to_info = {}
    node_index = 0
    block_key_to_id = {}

#class func_block_class:
#    def __init__(self):
#        self.block_id = 0
#        self.func_name = ""
#        self.func_id = 0
#        self.block_id_in_func = 0

#    fp = open("block_to_id.txt", "w")

    for func in idautils.Functions():
        func_name = GetFunctionName(func)
        func_id = func_name_to_id[func_name]

#        fp.write(hex(func) + " " + func_name)
#        get_func_cfg(fp, func, func_id)
        block_dict = {}
        flow_chart = idaapi.FlowChart(idaapi.get_func(func))
#        fp.write(" " + str(flow_chart.size) + "\n")
        for block in flow_chart:
            src_block_index = -1
#            block_set = Set()
#            block_set.add(block.id)

#            fp.write(hex(func) + " " + func_name + "\n")
            if block.id not in block_dict:
                src_block_index = node_index
                cfg.add_node(node_index)
                block_dict[block.id] = node_index

                func_block_object = func_block_class()
                func_block_object.block_id = node_index
                func_block_object.func_name = func_name
                func_block_object.func_id = func_id
                func_block_object.block_id_in_func = block.id
                func_block_object.block_type = block.type
                func_block_object.start_addr = block.startEA
                func_block_object.end_addr = block.endEA

                block_id_to_info[node_index] = func_block_object

                node_index += 1
            else:
                src_block_index = block_dict[block.id]

            #line = "\t" + str(block.id) + ":"
            for succ_block in block.succs():
#                if succ_block.id in block_set:
#                    dest_block_index = block_dict[succ_block.id]
#                else:
#                block_set.add(succ_block.id)
                dest_block_index = node_index
                cfg.add_node(dest_block_index)
                block_dict[succ_block.id] = node_index
                cfg.add_edge(src_block_index, dest_block_index)

                func_block_object = func_block_class()
                func_block_object.block_id = node_index
                func_block_object.func_name = func_name
                func_block_object.func_id = func_id
                func_block_object.block_id_in_func = succ_block.id
                func_block_object.block_type = succ_block.type
                func_block_object.start_addr = succ_block.startEA
                func_block_object.end_addr = succ_block.endEA

                block_id_to_info[node_index] = func_block_object
                node_index += 1


    fp = open("cfg_edge_list.graph", "w")
    fp.write("# v_count = %d, e_count = %d\n" %(cfg.number_of_nodes(), cfg.number_of_edges()))
    nx.write_edgelist(cfg, fp, data = False)
    fp.close()

    fp = open("block_id_to_info.csv", "w")
    line = "block_id,func_name,func_id,block_id_in_func"
    fp.write(line + "\n")
    for block_id in sorted(block_id_to_info.iterkeys()):
        line = str(block_id) + "," + block_id_to_info[block_id].func_name + "," + str(block_id_to_info[block_id].func_id) + "," + str(block_id_to_info[block_id].block_id_in_func)
        fp.write(line + "\n")
    fp.close()


def get_dfg(func_name_to_id, block_key_id, block_key_addr):
    '''id is defined as func_id.block_id'''
    '''dfg edge list: <src_id, dest_id, weight>, weight is the number of data references from src_id to dest_id; Let's first assume it is an undirected graph, later we can add the frequency as weight'''

#    fp = open("block_addr.txt", "w")
#    for bb in block_key_addr:
#        fp.write(bb + " " + hex(block_key_addr[bb][0]) + " " + hex(block_key_addr[bb][1]) + "\n")
#    fp.close()

#    fp = open("log", "w")
    dfg = nx.DiGraph()
    times = 0
    for func in idautils.Functions():
        func_name = GetFunctionName(func)
        func_id = func_name_to_id[func_name]

        func_class = idaapi.get_func(func)
        flow_chart = idaapi.FlowChart(func_class)
        for block in flow_chart:
            node_key = str(func_id) + "." + str(block.id)
            src_id = block_key_id[node_key]
#            fp.write(node_id + " " + str(block_key_id[node_id])+"\n")
            dfg.add_node(src_id)

            cur_addr = block.startEA
            while cur_addr < block.endEA:
                for addr in idautils.DataRefsFrom(cur_addr): #in-edge
                    times += 1
#                    fp.write("addr = " + str(hex(addr)) + "\n")
                    is_in_block = False
                    for bb in block_key_addr:
# Extend to frequency or something else later
#                        fp.write("\t" + str(hex(block_key_addr[bb][0])) + ", " + str(hex(block_key_addr[bb][1])) + "\n")
                        if addr >= block_key_addr[bb][0] and addr < block_key_addr[bb][1]:
                            dest_id = block_key_id[bb]
                            dfg.add_edge(src_id, dest_id)
                            is_in_block = True
                            break
#                    if is_in_block == False:
#                        fp.write(hex(addr) + " ")
#                        dest_func = idaapi.get_func(addr)
#                        fp.write(hex(idaapi.get_func(addr).startEA) + "\n")

                cur_addr = idc.NextHead(cur_addr)
#    fp.close()

    fp = open("dfg_edge_list.graph", "w")

    fp.write("# |V| = " + str(dfg.number_of_nodes()) + ", |E| = " + str(dfg.number_of_edges()) + "\n")
    fp.write("# Data reference times = " + str(times) + "\n")
    for edge in dfg.edges():
        fp.write(str(edge[0]) + " " + str(edge[1]) + "\n")
    fp.close()

    return dfg

# use "func_id.block_id" as the key
def get_cfg(func_name_to_id):
    cfg = nx.DiGraph()
    node_index = 0
    block_key_id = {} #{"func_id.bb_id" : bb_index}
    block_key_addr = {} #{"func_id.bb_id" : (src_addr, dest_addr)}
    block_id_to_info = {}

#    fp = open("func_addr.txt", "w")
#    fp = open("cfg_edge_list.graph", "w")
    for func in idautils.Functions():
        func_name = GetFunctionName(func)
        func_id = func_name_to_id[func_name]
        func_class = idaapi.get_func(func)

#        fp.write(func_name + ":" +  hex(func_class.startEA) + ", " + hex(func_class.endEA) + "\n")

        flow_chart = idaapi.FlowChart(func_class)
        for block in flow_chart:
            src_key = str(func_id) + "." + str(block.id)
            src_id = -1
            if src_key not in block_key_addr:
                block_key_addr[src_key] = (block.startEA, block.endEA)

#            if block.id == 0:
#                block_key_addr[src_key] = (func_class.startEA, block.endEA)
#            elif block.id == flow_chart.size - 1:
#                block_key_addr[src_key] = (block.endEA, func_class.endEA)

            if src_key not in block_key_id:
                block_key_id[src_key] = node_index
                src_id = node_index
                cfg.add_node(node_index)

                func_block_object = func_block_class()
                func_block_object.block_id = node_index
                func_block_object.func_name = func_name
                func_block_object.func_id = func_id
                func_block_object.block_id_in_func = block.id
                func_block_object.block_type = block.type
                func_block_object.start_addr = block.startEA
                func_block_object.end_addr = block.endEA

                block_id_to_info[node_index] = func_block_object

                node_index += 1
            else:
                src_id = block_key_id[src_key]

            for succ_block in block.succs():
                dest_id = node_index
                dest_key = str(func_id) + "." + str(succ_block.id)

                if dest_key in block_key_id:
                    cfg.add_edge(src_id, dest_id)
                else:
                    block_key_id[dest_key] = dest_id
                    cfg.add_node(node_index)
                    cfg.add_edge(src_id, dest_id)

                    func_block_object = func_block_class()
                    func_block_object.block_id = node_index
                    func_block_object.func_name = func_name
                    func_block_object.func_id = func_id
                    func_block_object.block_id_in_func = succ_block.id
                    func_block_object.block_type = succ_block.type
                    func_block_object.start_addr = succ_block.startEA
                    func_block_object.end_addr = succ_block.endEA

                    block_id_to_info[node_index] = func_block_object
                    node_index += 1

#            fp.write("start\n")
#    fp.close()

    fp = open("cfg_edge_list.graph", "w")
    fp.write("# v_count = %d, e_count = %d\n" %(cfg.number_of_nodes(), cfg.number_of_edges()))
    nx.write_edgelist(cfg, fp, data = False)
    fp.close()

    fp = open("block_id_to_info.csv", "w")
    line = "block_id,func_name,func_id,block_id_in_func"
    fp.write(line + "\n")

    for block_id in sorted(block_id_to_info.iterkeys()):
        line = str(block_id) + "," + block_id_to_info[block_id].func_name + "," + str(block_id_to_info[block_id].func_id) + "," + str(block_id_to_info[block_id].block_id_in_func)
        fp.write(line + "\n")
    fp.close()

    fp = open("block_id_to_label.csv", "w")
    line = "block_id,type,src_addr,dest_addr"
    fp.write(line + "\n")

    for block_id in sorted(block_id_to_info.iterkeys()):
        line = str(block_id) + "," + str(block_id_to_info[block_id].block_type) + "," + str(block_id_to_info[block_id].start_addr) + "," + str(block_id_to_info[block_id].end_addr)
        fp.write(line + "\n")
    fp.close()

    return block_key_id, block_key_addr

if __name__ == '__main__':
    # later, this should be extended with command line parameters
    out_file = "feature.csv"
    idaapi.autoWait()
    func_name_to_id = iterate_func()
##    os.system("echo '1' >> debug.log")
#    get_func_call_graph(func_name_to_id)
##    os.system("echo '2' >> debug.log")
#    #get_control_flow_graph(func_name_to_id)
#    block_key_id, block_key_addr = get_cfg(func_name_to_id)
##    get_dfg(func_name_to_id, block_key_id, block_key_addr)
#    feature_extraction(out_file, block_key_id, func_name_to_id)
    idc.Exit(0)

