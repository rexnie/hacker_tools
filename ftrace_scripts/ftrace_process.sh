#!/bin/sh
TRACE_CUR_PROCESS=1

tracefs=`grep debugfs /proc/mounts | awk '{ print $2; }'`/tracing
echo nop > $tracefs/current_tracer
echo 0 > $tracefs/tracing_on
echo 0 > $tracefs/options/func_stack_trace

if [ $TRACE_CUR_PROCESS -eq 1 ]; then
        # to trace current process
        echo $$ > $tracefs/set_ftrace_pid
else
        # to trace all processes
        echo > $tracefs/set_ftrace_pid
fi

echo function > $tracefs/current_tracer
echo > $tracefs/trace
echo 1 > $tracefs/tracing_on
exec $*
