import idc
import idaapi
import idautils
from sets import Set

def iterate_function(out_file):
    func_num = 0
    fp = open(out_file, "w")
    for func in idautils.Functions():
        func_name = GetFunctionName(func)
        line = hex(func) + " " + func_name

        # using CodeRefsTo
        for addr in idautils.CodeRefsTo(func, 0):
            line += ", " + hex(addr) + " " + idc.GetDisasm(addr)
        fp.write(line + "\n")
        func_num += 1

#        # using XrefsTo
#        for xref in idautils.XrefsTo(func, 0):
#            line += ", " + hex(xref.frm) + " " + hex(xref.to) + " " + idc.GetDisasm(xref.frm)
#        fp.write(line + "\n")
#        func_num += 1

    line = "function number is %d" %(func_num)
    fp.write(line + "\n")
    print line
    fp.close()

def get_func_call_graph(out_file):

    v_count = 0
    e_count = 0
    fp = open(out_file, "w")
    # traverse all the functions
    for func in idautils.Functions():
        v_count += 1
        func_name = GetFunctionName(func)
        line = hex(func) + " " + func_name
        # traverse all the instructions in a specific function
        instru_list = list(idautils.FuncItems(func))
        for instru in instru_list:
# check the Mnemonic of the instruction
            m = idc.GetMnem(instru)
# make sure the mnenomic key word
            if m == "call":# or m == "jmp":
                line += " ! " + idc.GetDisasm(instru)
                e_count += 1
# check the Code reference from this instruction
#            for call_addr in idautils.CodeRefsFrom(instru, 0):
#                line += "! " + hex(call_addr) + " " + idc.GetDisasm(call_addr)
#                e_count += 1
        fp.write(line + "\n")
    fp.write("v_count = %d, e_count = %d\n" %(v_count, e_count))
    fp.close()

def get_func_cfg(fp, func):

    flow_chart = idaapi.FlowChart(idaapi.get_func(func))
    fp.write(" " + str(flow_chart.size) + "\n")
    for block in flow_chart:
        line = "\t" + str(block.id) + ":"
        for succ_block in block.succs():
            line += " " + str(succ_block.id)
        fp.write(line + "\n")

def get_control_flow_graph(out_file):

    fp = open(out_file, "w")
    for func in idautils.Functions():
        func_name = GetFunctionName(func)
        fp.write(hex(func) + " " + func_name)
        get_func_cfg(fp, func)
        fp.write("\n")

    fp.close()


if __name__ == '__main__':
    # later, this should be extended with command line parameters
    out_file = "control_flow_graph.log"
    idaapi.autoWait()
#    iterate_function(out_file)
    get_control_flow_graph(out_file)
    idc.Exit(0)

