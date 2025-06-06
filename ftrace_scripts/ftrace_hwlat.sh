#!/bin/sh
tracefs=`grep debugfs /proc/mounts | awk '{ print $2; }'`/tracing
echo nop > $tracefs/current_tracer
echo 0 > $tracefs/tracing_on

echo hwlat > $tracefs/current_tracer
echo 1 > $tracefs/tracing_on
sleep 5
