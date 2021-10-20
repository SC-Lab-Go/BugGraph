import os
import subprocess
import re
import sys
import os.path


def iterate_all(root_path):
    '''iterate all the files under the root_path, extract the firmwares and create file 'firm_id_to_name.csv' '''
    firm_list = sorted(os.listdir(root_path))

# ignore file (not folder);
# ignore folder name starts with a "."

    if not root_path.endswith("/"):
        root_path = root_path + "/"

    result_file = root_path + "firm_id_to_name.csv"

    fp = open(result_file, "w")
    index = 0
    for i in xrange(len(firm_list)):
        cur_path = root_path + firm_list[i]
        if os.path.isdir(cur_path) and firm_list[i][0] != ".":
            fp.write(str(index) + "," + firm_list[i] + "\n")
            index += 1
    fp.close()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Wrong parameters!\nUsage: python firmware_process.py <dir_path>"
        exit();
    root_path = sys.argv[1]
    if os.path.isdir(root_path):
        iterate_all(root_path)
    else:
        print "Path does not exist!"
        exit();
