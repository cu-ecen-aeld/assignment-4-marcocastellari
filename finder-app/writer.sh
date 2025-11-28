#!/bin/sh

# validate input args
if [ "$#" -ne 2 ]; then
    echo "ERROR: Two argumets required. Usage: <writefile> <writestr>"
    exit 1
fi

writefile=$1
writestr=$2

dirpath=$(dirname "$writefile")
if ! mkdir -p "$dirpath"; then
    echo "ERROR: Cannot to create directory path '$dirpath'"
    exit 1
fi

if ! echo "$writestr" > "$writefile"; then
    echo "ERROR: Failed to write to file '$writefile'"
    exit 1
fi