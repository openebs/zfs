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
export LD_PRELOAD=/usr/lib/aarch64-linux-gnu/libjemalloc.so
exec /usr/local/bin/zrepl -l $LOGLEVEL
