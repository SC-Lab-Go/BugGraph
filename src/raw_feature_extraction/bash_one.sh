#./idal -A -Spython/count_instruction.py python/a.idb 
#./idal -A -Spython/function_call_graph.py python/a.idb 
#./idal -A -Spython/control_flow_graph.py python/a.idb 
ida_home="/home/chicken/ida-6.95"
#firm_path="/home/chicken/binary_analysis/data/firm_sample/test_dfg/dfg_test_o0.idb"
#firm_path="/home/chicken/firmware_db_binary/clj5550fw_07_150_3.rfu/2BD90.idb"
firm_path="/home/chicken/code_ida/test_malware/fff9f595a6ebc7e3cfe52a69764530d474c27d1cf149a634df7a2c4d3ffa702b/fff9f595a6ebc7e3cfe52a69764530d474c27d1cf149a634df7a2c4d3ffa702b.idb"
#firm_path="/home/chicken/binary_openssl_case1_disassemble/openssl-1.0.1n.openssl.clang-3.3.O0.bin_dir/openssl-1.0.1n.openssl.clang-3.3.O0.idb"

echo $ida_home/idal -A -Sfunc_assembly.py $firm_path 
$ida_home/idal -A -Sfunc_assembly.py $firm_path 

#echo $ida_home/idal -A -Sfeature_extraction.py $firm_path 
#$ida_home/idal -A -Sfeature_extraction.py $firm_path 
#echo $ida_home/idal -A -Sfunction_call_graph.py $firm_path 
#$ida_home/idal -A -Sfunction_call_graph.py $firm_path 
#vim feature.csv

