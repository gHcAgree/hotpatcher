# !/bin/sh

if [ $# -ne 2 ]; then
    echo "Usage: $0 hotpatcher <function_name> <lib_file>"
	exit 1
fi

export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:./"

./hotpatcher $1 $2