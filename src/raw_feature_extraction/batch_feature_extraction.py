import os
import subprocess
import re
import sys
import os.path

# add others if needed
ida_extension = [".i64", ".idb"]
usage = "Usage: python batch_load_idm_dir.py <dir_path> <32/64(architecture, 32 for x86, 64 for x64)>\n"

def iterate_all(root_path, ida_path, ida_python_path):

    subdir_list = os.listdir(root_path)
    if not root_path.endswith("/"):
        root_path = root_path + "/"

    for one in subdir_list:
        one_path = root_path + one
        if os.path.isdir(one_path) and not one.startswith("."):
            iterate_one_firm(one_path, ida_path, ida_python_path)

def iterate_one_firm(root_path, ida_path, ida_python_path):
    # iterate all the files under the root_path
    program_name_to_id = {}
    index = 0
    for subdir, dirs, files in os.walk(root_path):
        for one in files:
            #print file_path
#            print one
            for ida_ext in ida_extension:
                if one.endswith(ida_ext):
                    if one.startswith("Generator") or one.startswith("Como"):
                        continue
                    # Step 1: find one
                    file_path = subdir + os.sep + re.sub(ida_ext, "", one) + "_dir"
#                    print file_path
                    if not os.path.isdir(file_path):
                        cmd_mkdir = "mkdir " + file_path
#                        print cmd_mkdir
                        os.system(cmd_mkdir)

                    os.chdir(file_path)

                    if one not in program_name_to_id:
                        program_name_to_id[one] = index
                        index += 1

                    cmd_exe = ida_path + " -A -S" + ida_python_path + os.sep + "feature_extraction.py" + " " + subdir + os.sep + one
#                    cmd_exe = ida_path + " -A -S" + ida_python_path + os.sep + "feature_extraction_back.py" + " " + subdir + os.sep + one

#                    cmd_exe = ida_path + " -A -S" + "feature_extraction.py" + " " + subdir + os.sep + one
                    print cmd_exe
                    os.system(cmd_exe)

# Reduce space
                    one_path = subdir + os.sep + one
                    os.system("rm " + one_path)

                    one_asm_path = subdir + os.sep + one[:-3] + "asm"
                    os.system("rm " + one_asm_path)

    program_name_file = root_path
    if program_name_file.endswith("/"):
        program_name_file = program_name_file + "program_id_to_name.csv"
    else:
        program_name_file = program_name_file + os.sep + "program_id_to_name.csv"

    os.chdir(root_path)

    fp = open(program_name_file, "w")
    for program_name in program_name_to_id:
        fp.write(str(program_name_to_id[program_name]) + "," + program_name + "\n")

    fp.close()



if __name__ == "__main__":
    if len(sys.argv) != 3:
        print "Wrong parameters!\n"
        print usage
        exit();
    root_path = sys.argv[1]
    if os.path.exists(root_path):
        architect = int(sys.argv[2])
        if architect != 32 and architect != 64:
            print "Wrong architecture!\n"
            print usage
        ida_path = "/home/chicken/ida-6.95/idal"
        if architect == 64:
            ida_path = ida_path + "64"

        ida_python_path = "/home/chicken/binary_analysis/src/raw_feature_extraction"
#        ida_python_path = ""
        iterate_all(root_path, ida_path, ida_python_path)
    else:
        print "Path does not exist!"
        exit();
