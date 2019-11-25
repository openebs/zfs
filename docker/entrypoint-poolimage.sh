#!/bin/sh

set -o errexit
trap 'call_exit $LINE_NO' EXIT

call_exit()
{
echo "at call_exit.."     
echo  "exit code:" $?
echo "reference: "  $0 
}


if [ -z "$LOGLEVEL" ]; then
	LOGLEVEL=info
fi
echo "sleeping for 2 sec"
sleep 2
ARCH=$(uname -m)
export LD_PRELOAD=/usr/lib/${ARCH}-linux-gnu/libjemalloc.so
exec /usr/local/bin/zrepl -l $LOGLEVEL
