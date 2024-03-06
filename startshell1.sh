# if test $( pgrep -f proxyserver | wc -l ) -eq 0 
# then 
# echo "Starting service ..." >> /home/guanhuanglu/proxyserver/service.log
# 		        /home/guanhuanglu/proxyserver/proxyserver -n 10800 &
# echo "进程不存在"
# else 
# echo "存在进程" 
#     # pkill -9 proxyserver
#     echo "kill service ... " >> /home/guanhuanglu/proxyserver/serviceee.log
# fi


#!/bin/bash

check_port() {
        echo "正在检测端口......"
        netstat -tlpn | grep "\b$1\b"
}
if check_port 10800                                 #端口
then
        echo "端口存在"
        echo " 端口存在" >> /home/guanhuanglu/proxyserver/serviceexist.log
    exit 1
else
        echo "端口死亡"
        DATE_N=`date "+%Y-%m%d %H:%M:%S"`
        echo "时间：${DATE_N}" >> check_port.log #记录死亡日志
          echo "端口死亡" >> /home/guanhuanglu/proxyserver/service.log
		/home/guanhuanglu/proxyserver/proxyserver -n 10800 &
fi


PROCPID=`ps -ef|grep ModemManager |grep -v "grep"|grep -v "grep ModemManager"|grep -v "su"|grep -v tail |grep -v vi|awk '{print $2}'`
#PROCPID=`ps -ef|grep rakeserver |grep -v "grep"|grep -v "grep rakeserver"|grep -v "su"|grep -v tail |grep -v vi|awk '{print $2}'`
if [ -z "$PROCPID" ]
then
#if [ "$run" ] ; then 
        echo " Starting service.. " >> /home/guanhuanglu/proxyserver/ModemManager1.log
         /usr/sbin/ModemManager --debug &
else
    echo " exist service ..." >> /home/guanhuanglu/proxyserver/notModemManager1.log
fi