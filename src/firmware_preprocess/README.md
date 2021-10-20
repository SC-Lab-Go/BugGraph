# Usage of The Scripts

1. batch_create_dir.py:

For the binaries under a given folder, create a directory without extension for each binary, and move the binary to that directory.

2. batch_disassembly_dir.py:

For the valid binaries under a given folder, using ida-pro to automatically disassembly them.

3. bash_disassembly_dir.sh:

The command of calling batch_disassembly_dir.py

4. firmware_preprocess.py:

Iterate all the files under the given path, extract the firmwares and create file 'firm_id_to_name.csv' under the given path
