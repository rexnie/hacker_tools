#!/bin/sh
tracefs=`grep debugfs /proc/mounts | awk '{ print $2; }'`/tracing
echo nop > $tracefs/current_tracer
echo 0 > $tracefs/tracing_on

echo ghes_do_proc.isra.16 > $tracefs/set_ftrace_filter
#echo hrtimer_interrupt >> $tracefs/set_ftrace_filter

#echo 'hrtimer_*' > $tracefs/set_ftrace_filter
#echo hrtimer_cancel > $tracefs/set_ftrace_notrace

# print callee's stacktrace
#echo 1 > $tracefs/options/func_stack_trace

echo function > $tracefs/current_tracer
echo 1 > $tracefs/tracing_on
exec $*
