# Raw Feature Extraction from Firmware Binaries

In this folder, we write several scripts to extract the features from a firmware binary using IDA Pro (version 6.95).

### Usage:
1. Extract features from one binary file:
```python
command: ./bash_one.sh (change "firm_path" to the .idb file you want to run)
```
    bash_one.sh runs feature_extraction.py and write the feature files under current folder.

    feature_extraction.py extracts the features for a binary (.idb or .i64).

2. Extract features for all the binaries under a folder:
```python
command: ./batch_feature_extraction.sh (change to the correct folder path, and architecture type)
```

    batch_feature_extraction.sh runs batch_feature_extraction.py for a folder.

    batch_feature_extraction.py iterates all the binaries under a folder path. 
For each valid .idb or .i64 file, it would call feature_extraction.py to extract the features

### Output feature files:

1. block_id_to_info.csv:

     block_id | func_name | func_id | block_id_in_func
     --- | --- | --- | ---
    0 | .init_proc | 0 | 0
    1 | .init_proc | 0 | 1

2. block_id_to_label.csv:

    block_id | type | src_addr | dest_addr
    --- | --- | --- | ---
    0 | 0 | 134513364 | 134513389
    1 | 0 | 134513389 | 134513394

3. feature.csv:

    block_id.func_id | numeric constants | No. of transfer instructions | No. of calls | No. of instructinos | No. of arithmetic instructions | No. of offspring | betweenness centrality
    --- | --- | --- | --- | --- | --- | --- | ---
    0 | 2 | 2 | 1 | 7 | 2 | 2 | 0.0
    1 | 0 | 1 | 1 | 1 | 0 | 1 | 0.0

4. func_to_id.csv:

    func_id | func_name
    --- | ---
    0 | .init_proc
    1 | .printf

5. cfg_edge_list.graph:
    
    **Control flow graph (CFG)** represented as an edge list.

    v_count=49 | e_count=34
    --- | ---
    0 | 1
    0 | 2

6. fcg_edge_list.graph:
    
    **Function call graph (FCG)** represented as an edge list.

    v_count=22 | e_count=15
    --- | ---
    0 | 3
    0 | 6

7. dfg_edge_list.graph:
    
    **Data flow graph (DFG)** represented as an edge list. However, there exists some **errors** in current version.


### Others:
Other files are testing files for different purposes

