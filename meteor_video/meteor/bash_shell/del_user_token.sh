#!/bin/bash

#token start
if [ $# -gt 0 ]
then
	case "$1" in
	 -h | --help )
		echo "first is the token start number only number second is the end of token number"
		echo "Usage: "$0" [start_number_token  end_number_token ] [1 100]"
		exit 0
		;;
	 * ) 
		min=$1
		max=$2
		;;
	esac
	
else
	min=1001
	max=100001	
fi
# i=017
#sum=$i
while [  $min  -le  $max ]
 do
    min=`expr $min + 1`
    #tmp=$i

echo  "del  hash.order.token:$min  " | redis-cli
done
