#!/bin/bash

if [ $# -lt 1 ];
then
    echo "Usage: $0 <afl-fuzz-run-name>"
    exit 1
fi

kill -9 `ps -ef | grep "afl-fuzz" | grep "$1" | grep -v "grep" | awk '{ print $2 }'`
