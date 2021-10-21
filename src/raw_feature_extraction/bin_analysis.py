import idc
import idaapi
import idautils

idaapi.autoWait()

count = 0
for func in idautils.Functions():
    # Ignore Library Code
    flags = idc.GetFunctionFlags(func)
    if flags & FUNC_LIB:
        continue
    for instru in idautils.FuncItems(func):
        count += 1

f = open("instru_count.txt", 'w')
print_me = "Instruction Count is % d" % (count)
f.write(print_me)
f.close()
idc.Exit(0)


