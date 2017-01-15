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

#rm -rf test.txt

#i=1001
#sum=$i
while [  $min  -le  $max ] 
 do 
    min=`expr $min + 1`
    #tmp=$i
    
echo  "hmset  hash.order.token:$min  orderBalance 2099999999  todayUsedFlow  79  todayUsedFlowTime  0   orderStatus  3  activityId  0  orderEndTime  1588473874567  orderId  1470190673259000035   phoneId 18092815945   orderKey  123456    orderKeyEndTime  1548544434567     orderApps  com.tencent.mobileqq|" | redis-cli
done
