#!/bin/sh
tracefs=`grep debugfs /proc/mounts | awk '{ print $2; }'`/tracing
echo nop > $tracefs/current_tracer
echo 0 > $tracefs/tracing_on
echo 0 > $tracefs/options/function-trace
# enable events can induce larger lat, but smaller than function-trace
echo 0 > $tracefs/events/enable

echo wakeup_rt > $tracefs/current_tracer
echo 0 > $tracefs/tracing_max_latency
echo 1 > $tracefs/tracing_on
