#!/bin/bash

cd $(dirname $0)
mkdir -p ../log/valgrind_log

mkdir -p /run/tmp
./../platform/laputa/scripts/build.sh
dpkg -i ../platform/laputa/build/*.deb
make debug -C ..
valgrind --leak-check=yes --error-exitcode=1 --keep-debuginfo=yes --log-file=../log/valgrind_log/valgrind_mx-cert-mgmtd.log ../platform/laputa/bin/mx-cert-mgmtd &

valgrind_pid=$!

echo sleep 3s......  
sleep 3

#----- add something here to interact with the daemon -----#

#----- add something here to interact with the daemon end -----#

killall memcheck-amd64-
wait $valgrind_pid
valgrind_exit_code=$?

if [ $valgrind_exit_code -eq 0 ]
then
  echo [PASSED]
  exit 0
else
  echo [FAILED]. exit code:$valgrind_exit_code
  exit $valgrind_exit_code
fi