#!/bin/bash
 i=1001
 sum=$i
while [  $i  -le  100001 ] 
 do 
    i=`expr $i + 1`
    tmp=$i
    
echo  "hmset  hash.order.token:$tmp  orderBalance 2099999999  todayUsedFlow  79  todayUsedFlowTime  0   orderStatus  3  contractId  0  orderEndTime  1588473874567  orderId  1470190673259000035   phoneId 18092815945   orderKey  123456    orderKeyEndTime  1548544434567     orderApps  com.tencent.mobileqq|" | redis-cli
done
