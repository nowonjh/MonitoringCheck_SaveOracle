#!/bin/sh

SYNC_PID=`ps -ef | grep monitoringCheckModule | grep -v grep | grep -v /bin/sh | awk '{print $2}'`
if [ "$SYNC_PID" == "" ]
then
echo 'monitoringCheckModule does not exist'
else
kill -9 `ps -ef | grep monitoringCheckModule | grep -v grep | grep -v /bin/sh | awk '{ print $2 }'`
echo 'kill monitoringCheckModule'
fi
