pkill -9 proxyserver
ulimit -c 102400
ulimit -n 1024000

./proxyserver  -n 10800 &
