import os
import subprocess
import os.path
import sys
#from tqdm import tqdm

ignore_extension = (".py", ".cpp", ".c", ".h", ".hpp", ".cc", ".cs", ".csv", ".txt", ".graph", ".asm", ".dump", "idb", "id0", "id1", "id2", "nam", "til")

usage = "Usage: python batch_disassembly_dir.py <dir_path> <32/64(architecture, 32 for x86, 64 for x64)\n>"

def iterate_all(root_path, ida_path):
    # iterate all the files under the root_path
    num_all = 0
    num_done = 0
    num_idb = 0
    for subdir, dirs, files in os.walk(root_path):
        for one in files:
            file_path = os.path.join(subdir, one)
            # print file_path
            if file_path.endswith(ignore_extension): # or "." in file_path:
                continue

            num_all += 1

            if os.path.exists(file_path + ".idb"): #and os.path.exists(file_path + ".asm"):
                num_idb += 1
                continue

            if os.path.exists(file_path + "_dir"):
                num_done += 1
                continue
#            print file_path
# Fix the error
            subprocess.call([ida_path, "-B", file_path])
# Original version
#            subprocess.call([ida_path, "-B", file_path])
    print "num_all", num_all, "num_done", num_done, "num_idb", num_idb, "num_left", num_all - num_done - num_idb

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print "Wrong parameters!\n"
        print usage
        exit()

    root_path = sys.argv[1]
    architect = int(sys.argv[2])
    if architect != 32 and architect != 64:
        print "Wrong architecture!\n"
        print usage

    if not os.path.exists(root_path):
        print "Path does not exist!"
        exit()
    else:
        ida_path = "/home/chicken/ida-6.95/idal"
        if architect == 64:
            ida_path += "64"
        iterate_all(root_path, ida_path)
