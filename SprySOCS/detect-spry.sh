#!/usr/bin/bash

################################################################
# Application: detect-spry.sh
#
# Purpose: This script will detect to see if the malware
#          SprySOCS is running and will attempt to kill it
#
# Created By: Christopher Tarricone chris at uconn dot edu
#
# Version:
#          1.0 - Initial Creation
################################################################

################################################################
# Set Boolean for results
################################################################
FOUND_IOC="false"

################################################################
# Try to locate the process and PID
################################################################
FIND_PROC=`ps -e |grep "kworker/0:22"`
FIND_PID=`ps -e |grep "kworker/0:22" |awk ' { print $1 } '`

################################################################
# If the process is found then try to kill it. If it is not let
# the admin know that it was not found to be running.
################################################################
if [ "$FIND_PROC" -eq ""]; then
    echo "Process does not appear to be running"
else
    echo "Process appears to be running"
    echo "Killing..."
    /usr/bin/kill -9 $FIND_PID
    echo "Done..."
    FOUND_IOC="true"
fi

################################################################
# Encrypted SprySOCKS payload (libmonitor.so.2)
################################################################
SHA254_LIBMON_IOC="6f84b54c81d29cb6ff52ce66426b180ad0a3b907e2ef1117a30e95f2dc9959fc"

IFS=$'\n'
FILES=($(find / -name "libmonitor.so.2"))
unset IFS
for element in "${FILES[@]}"
do
        IOC=`sha256sum $element | awk ' { print $1  } '`
        if [ "$IOC" == "$SHA254_LIBMON_IOC" ]; then
                echo "Found IOC in $element"
                FOUND_IOC="true"
        else
                echo "IOC not found in $element"
        fi
done

if [ "$FOUND_IOC" == "true"]; then
    echo "SprySOCKS was detected on this system please remediate ASAP"
fi