#!/bin/bash
# Script to convert the data we got in bin format to the corresponding hexdump. It also add some 
# characters boundaries so it can be parsed by the dump978 tools
# 2018 Giulio Ginesi
input=""
output=""
dir=0
while getopts ":di:o:h" opt; do
    case $opt in 
	i)
	    input=$OPTARG
	    ;;
	o)  output=$OPTARG
	    ;;
	d)
	    dir=1
	    ;;
	h)
	    echo "Usage: ./converter.sh [-d inputDirectory] or [-i inputFile] [-o outputFile]"
	    echo "with -d it will create another directory inside the one specified containing the converted data"
	    echo "To use with the RTCA DO-358 supplement file or with hex to be converted in uplink, 1 hex per line."
	    exit 0
	    ;;
	\?)
	    echo "Invalid option: -$OPTARG. Use -h for help"
	    exit 1
	    ;;
    esac
done

#printf "Debug info: input %s , output %s , isDir = %i" $input $output $dir
#exit 0
if [ dir ]; then
	input=${input%/*}
	if [[ -d $input ]]; then
		mkdir $input/converted 2> /dev/null || echo "Destination directory exists, continuing..."
		for filename in $(ls $input); do
			if [[ -f $input/$filename ]]; then
				outfile=$(echo $filename | cut -d. -f1)".hex"
				destination=$input/converted/$outfile
				echo $destination
				echo $(xxd -p $input/$filename | tr -d "\n" | awk '{print "+"$0";"}') > "$destination"
			fi
		done
		exit 0
	fi
	echo "$input is not a directory!"
	exit 1
fi

echo $(xxd -p $input | tr -d "\n" | awk '{print "+"$0";"}') > "$output"
