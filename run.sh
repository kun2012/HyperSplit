#!/bin/bash
INPUT_DIR="../filters"
OUTPUT_DIR="output"

mkdir -p $OUTPUT_DIR

outputfile="$OUTPUT_DIR"/"hypersplit.stat"

>$outputfile

for i in acl1 ipc1 fw1
do
    for j in 100 1K 5K 10K
    do
        filter="$i"_$j
        echo $filter
        rf="$INPUT_DIR"/"$filter".txt
        tf="$INPUT_DIR"/"$filter"_trace.txt
        echo -n -e "$filter\t" >> $outputfile
        ./hs $rf $tf >>$outputfile
    done
done
