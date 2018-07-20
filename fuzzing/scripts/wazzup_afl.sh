#!/bin/bash

if [ $# -lt 1 ];
then
    echo "Usage: $0 <fullpath-basedir-afl-out>"
    exit 1
fi

RP=`realpath $1`
for d in `find $RP -type d -maxdepth 1`;
do
    echo "$d"
    echo `basename $d`
    afl-whatsup `realpath $d` | tail -n 10
done

