#!/bin/bash
# those are our main variables
CORES=4
afl_opts=""
params=""
resume=0
# we want the script to have 4 options:
# -c -> number of cores
# -b -> path to binary
# -d -> path to data file
# -a -> afl options
# -r -> resume a previous run with the same binary ( and the same input) it basically looks at the name
# maybe we can add another option to specify the sync directory
while getopts ":c:b:d:a:hkr" opt; do
	case "$opt" in
		c)
			CORES=$OPTARG
			printf "Using %s cores.\n" $CORES
			;;
		b)
			bin_path=$OPTARG
			bin_name=$(basename $bin_path)
			;;
		d)
			data_path=$OPTARG
			data_name=$(basename $data_path)
			;;
		a)
			afl_opts=$OPTARG
			;;
		r)
			echo "Resuming..."
			resume=1
			;;
		h)	echo "Usage: ./start.sh Options [-r] [binParameters]"
			printf '\t -c Number of cores \n\t -b path to binary \n\t -d path to data file \n\t -a afl options (right now only "-Q") \n\t -r Resume a previous run, it is based on the name so if you add this option it will try to resume a previous instance.  \n binParameters are the parameters needed by the binary beeing fuzzed.\n\n Tipical run:\n\t ./start.sh -c 3 -b bin/dump1090-llvm-stratux-latest -d data/1090_small.bin -- "--no-crc-check --ifile @@" \n OR \n\t ./start.sh -r -c 3 -b bin/dump1090-llvm-stratux-latest -d data/1090_small.bin -- "--no-crc-check --ifile @@" \n if you want to resume\n'
			exit 1
			;;
		\?)
			echo "Invalid option: -$OPTARG. Use -h for help."
			exit 1
			;;
	esac
done

if [[ ! -f $bin_path ]] || [[ ! -f $data_path ]]; then
	echo "-b or -d not specified or not in path"
	exit 1
fi

#printf "Debug: \t cores - %i \n\t binary - %s \n\t data - %s \n\t afl opt - %s\n" $CORES $bin $data $afl_opts
shift $((OPTIND-1))
params=$*

input="afl/in/$bin_name-${data_name%.*}"
output="afl/out/$bin_name-${data_name%.*}"
version=$(echo $bin_name | cut -d'-' -f2)
if [ ! -d "afl" ]; then
	if [ $resume != 0 ]; then 
		echo "Error! Can't resume, afl directory doesen't exists"
		exit 1
	fi
	mkdir "afl" "afl/in" "afl/out"
fi

if [[ ! -d $input && ! -d $output && $resume != 0 ]]; then
	echo "Error! You can't resume a fuzzer that never started (no relative directory found)"
	exit 1;
fi

if [ ! -d $input ]; then
	mkdir $input
	cp $data_path $input
fi

if [ ! -d $output ];then
	mkdir $output
fi

if [ $resume == 1 ]; then
	input="-"
fi

echo "Spawning master"
( afl-fuzz -M "${data_name%.*}${version}_M" $afl_opts -i $input -o $output $bin_path $params > ${output}/logM &)
ind=0
while [ $ind -lt $((CORES-1)) ]; do
	echo "Spawning slave $ind"
	( afl-fuzz -S "${data_name%.*}${version}_S$ind" $afl_opts -i $input -o $output $bin_path $params > ${output}/logS$ind &)
	((ind++))
done
