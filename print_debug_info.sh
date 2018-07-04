#!/bin/bash

while sleep 300; do
    echo "=====[ $SECONDS seconds still running ]=====";
    ps -auxwww;
    netstat -nap;
    echo "============================================";
done
