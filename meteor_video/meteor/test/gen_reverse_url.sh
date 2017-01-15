#!/bin/bash 

#http url
if [ $# -gt 0 ]
then
	case "$1" in
	 -h | --help )
		echo "change a normal http_url to a reverse url form"
		echo "Usage: "$0" [http_url:http://...]"
		exit 0;;
	 * ) url=$1;;
	esac
	
else
	url=http://www.man7.org/training/index.html
fi


#host:port
meteor_host=192.168.136.135:1080  

at_flag=4
domain_flag=1
token=1003
apps=com.tencent.mobileqq
orderkey=123456


website=${url#*//}
domain=`echo ${website%%/*} | awk -F ':' '{print $1}'`
passwd=`echo -en "${token}|${orderkey}|${domain}" | md5sum | cut -d ' ' -f 1`
proxy_url="http://${meteor_host}/meteorq|${at_flag}|${domain_flag}|1|${token}|${apps}|${passwd}/${website}"

echo $proxy_url
exit 0

##m3u8

# #content-type:text/plain
# http://10.16.32.152:1080/meteorq|4|1|1|1003|com.tencent.mobileqq|e4020d887cdb7d5ec12bba0dbb56c242/www.swr3.de/vr.m3u8
# http://10.16.32.152:1080/meteorq|4|1|1|1003|com.tencent.mobileqq|4187e6b12753fc889013f790b56ced03/www.endlesspools.com/iphone/iphone_streams/WaterWell/MasterPlayList.m3u8
# http://10.16.32.152:1080/meteorq|4|1|1|1003|com.tencent.mobileqq|c111a725c147622026be5ecc9daa45c6/www.r2.co.nz/20131119/index2.m3u8
# http://10.16.32.152:1080/meteorq|4|1|1|1003|com.tencent.mobileqq|aebd853045321ee95944f0784dfd3f8f/xinflix.com:888/54/stream.m3u8
# http://alexryzhenko.iptvspy.ru/iptv/VD9UP7QMBHGRE4/232/index.m3u8
# https://dawrat.com/om/en/course/basics-of-editing-portrait/uc3mv2/playlist.m3u8?ex=1447498380&h=d3U-9qzOnrzHCsxNcty91w&m=c6mCM_yhVrJjLHjKfraEkA&l=kauXnSUyKGs2BW2iy62VFw
  
# #content-type:text/html
# http://bf.086wl.com/gydq/s/edge2.everyon.tv/etv2sb/phd60/hasbahca.m3u8
# #transfer-encoding:chunked
# http://vindi.ir/video/1/2/720.m3u8 

