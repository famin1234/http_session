#!/bin/sh
for ((i = 0; i < 1; i++))
do
#curl -vo/dev/null http://192.168.136.100/
#curl --limit-rate 1024k -o/dev/null 61.134.86.15:5011/1024m -v
#/root/sflowtool/src/sflowtool -r /root/6343.pcap -f 192.168.136.100/6343
#curl -vo/dev/null -x 127.0.0.1:8080 http://39.98.87.1/media/elFinder/files/tmp/a.jpg -r 100-
curl -vo/dev/null -x 127.0.0.1:8080 http://www.baidu.com/
#curl -vo/dev/null -x 127.0.0.1:8080 http://vr.sina.cn/interface/gettophtml.shtml
#curl -vo/dev/null -x 127.0.0.1:8080 http://127.0.0.1/4g
#wget -d -e--http_proxy=127.0.0.1:8080 http://127.0.0.1/4g -O/dev/null
done
