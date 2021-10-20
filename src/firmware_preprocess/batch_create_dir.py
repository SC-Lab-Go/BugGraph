import os
import subprocess
import os.path
import sys

ignore_ext = (".py", ".cpp", ".c", ".h", ".hpp", ".cc", ".cs", ".csv", ".txt", ".graph", ".asm", ".dump", ".idb")

correct_ext = ("x86", "X86", "x64", "X64", "exe", "EXE", "dll", "DLL", "arm", "ARM", "mips", "MIPS")

usage = "Usage: python batch_disassembly_dir.py <dir_path>\nGiven a folder, list all the binaries only under this folder, create a folder for each binary without extension, and move the binary to the folder\n"

def create_dir(root_path):
    '''for each binary, create a directory without extension, and move the binary to that directory'''
    if not root_path.endswith("/"):
        root_path = root_path + "/"
    os.chdir(root_path)
    binary_list = os.listdir(root_path)
    for one in binary_list:
# remove the extension, .xxx
        if not os.path.isfile(one):
            continue

#        if "." in one:
#            binary_name = one.rsplit(".")[0]
#            binary_ext = one.rsplit(".")[-1]
#            if binary_ext not in correct_ext:
#                continue
#            os.system("mkdir " + binary_name)
#            os.system("mv " + one + " " + binary_name)
#        else:
        os.system("mkdir " + one + "_dir")
        os.system("mv " + one + " " + one + "_dir")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Wrong parameters!\n"
        print usage
        exit()

    root_path = sys.argv[1]
    if not os.path.exists(root_path):
        print "Path does not exist!"
        exit()
    else:
        create_dir(root_path)
