#!/bin/bash
# 2018 Giulio Ginesi
dir=""
exe=""
interactive=1
while getopts ":d:b:ih" opt; do
    case $opt in 
	d)
	    dir=$OPTARG
	    ;;
	b)
	    exe=$OPTARG
	    ;;
	i)
	    interactive=0
	    ;;
        h)
	    echo "Usage: ./runner.sh -d filesDir -b binary [-i]"
	    echo "use -i if you want the program to run non interactively"
	    exit 0
	    ;;
	\?)
	    echo "Invalid option: -$OPTARG. Use -h for help"
	    exit 1
	    ;;
    esac
done
	    
if [[ ! -d $dir ]] || [[ ! -f $exe ]];then
	echo "$dir or $exe either not a directory/file or not in path"
	exit 1
fi

dir=${dir%/*}

for filename in $(ls $dir); do
	echo $dir/$filename
	cat $dir/$filename | $exe
	if [ $interactive == 1 ];then
		echo "Continue? [Y/n]: "
		read status
		if [ "$status" == "n" ]; then
			exit 0
		fi
	fi
done
