#!/bin/sh
tracefs=`grep debugfs /proc/mounts | awk '{ print $2; }'`/tracing
echo nop > $tracefs/current_tracer
echo 0 > $tracefs/tracing_on
echo ":mod:nfs" > $tracefs/set_ftrace_filter

# print callee's stacktrace
#echo 1 > $tracefs/options/func_stack_trace

echo function > $tracefs/current_tracer
echo 1 > $tracefs/tracing_on
exec $*
