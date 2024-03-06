#!/bin/sh

PROCPID=`ps -ef|grep proxyserver |grep -v "grep"|grep -v "grep proxyserver"|grep -v "su"|grep -v tail |grep -v vi|grep -v auto|awk '{print $2}'`
if [ "$PROCPID" != "" ]
then
	# pkill -9 proxyserver
    echo "11"
    echo " service exist... $PROCPID" >> /home/guanhuanglu/proxyserver/serviceexist.log
    
else
    echo "22"
	        echo "Starting service ..." >> /home/guanhuanglu/proxyserver/service.log
		        /home/guanhuanglu/proxyserver/proxyserver -n 10800 &
fi

