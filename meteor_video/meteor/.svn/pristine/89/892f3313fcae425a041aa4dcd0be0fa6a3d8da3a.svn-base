#!/bin/bash
#PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
PATH=$PATH
export PATH
rm -rf tcptmp2.txt
rm -rf udptmp2.txt
#touch huadan.txt
if [ $# -gt 0 ]
then
	case "$1" in
	 -h | --help )
		echo "the name of balance file "
		#echo "Usage: "$0" [start_number_token  end_number_token ] [1 100...]"
		exit 0
		;;
	 * ) 
		name_balance=$1
		#max=$2
		;;
	esac
	
else
	#name_balance=huadan.txt
	#max=100001	
	echo "please input the balance file name !"
fi
(cat $name_balance | grep tcp | awk  -F ' ' '{print $17}')>>tcptmp2.txt
 tcp_sum=0
 #lastline=$(sed 'N;D' tcptmp2.txt)
 #tcp_balance_lastline=`echo $lastline | awk -F ' ' '{print $1}'`
 #echo "$tcp_balance_lastline"
(cat tcptmp2.txt)| while read LINE
    do
        tcp_balance=`echo $LINE | awk -F ' ' '{print $1}'`
		tcp_sum=$[  $tcp_sum  +  $tcp_balance ]

		echo "$tcp_sum" >tmp.txt
    done
cat tmp.txt

(cat $name_balance | grep udp |grep "0--total" | awk  -F ' ' '{print $17}')>>udptmp2.txt  

 udp_sum=0
 #udp_lastline=$(sed 'N;D' udptmp2.txt)
 #udp_balance_lastline=`echo $udp_lastline | awk -F ' ' '{print $1}'`
 #echo "$udp_balance_lastline"
(cat udptmp2.txt)| while read LINE
    do
        udp_balance=`echo $LINE | awk -F ' ' '{print $1}'`
		udp_sum=$[  $udp_sum  +  $udp_balance ]
		#echo "$udp_sum" 
		echo "$udp_sum" >tmp1.txt
    done
cat tmp1.txt
   
