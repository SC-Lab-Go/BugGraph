import os
import subprocess
import os.path
import sys

ignore_extension = (".py", ".cpp", ".c", ".h", ".hpp", ".cc", ".cs", ".csv", ".txt", ".graph", ".asm", ".dump", "idb", ".log")

usage = "Usage: python batch_disassembly_dir.py <dir_path> <32/64(architecture, 32 for x86, 64 for x64)\n>"

def iterate_all(root_path, ida_path):
    # iterate all the files under the root_path
    for subdir, dirs, files in os.walk(root_path):
        for one in files:
            file_path = os.path.join(subdir, one)
            #print file_path
            if file_path.endswith(ignore_extension):
                continue
#            print file_path
# ignore already disassembled binaries

            temp_path = (file_path.rsplit('.', 1))[0] + "_dir"
#            print temp_path
            if os.path.isdir(temp_path):
                continue
            print temp_path
            subprocess.call([ida_path, "-B", file_path])

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
