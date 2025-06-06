#!/bin/sh
tracefs=`grep debugfs /proc/mounts | awk '{ print $2; }'`/tracing
echo nop > $tracefs/current_tracer
echo 0 > $tracefs/tracing_on
echo 0 > $tracefs/options/function-trace

echo wakeup > $tracefs/current_tracer
echo 0 > $tracefs/tracing_max_latency
echo 1 > $tracefs/tracing_on
