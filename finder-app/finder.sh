#!/bin/sh

# input validation
if [ "$#" -ne 2 ]; then
	echo "ERROR: Two arguments required <filestr> <searchstr>"
	exit 1
fi

filesdir=$1
searchstr=$2

# check if it is a directory
if [ ! -d "$filesdir" ]; then
	echo "ERROR: '$filesdir' is not a directory or does not exist."
	exit 1
fi

# count number of files
num_files=$(find "$filesdir" -type f | wc -l)

# count number of lines
num_matching_lines=$(
  if [ "$num_files" -eq 0 ]; then
    echo 0
  else
    find "$filesdir" -type f -exec grep -F -s "$searchstr" {} + | wc -l
  fi
)

echo "The number of files are ${num_files} and the number of matching lines are ${num_matching_lines}"
