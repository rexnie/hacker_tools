#!/bin/sh
tracefs=`grep debugfs /proc/mounts | awk '{ print $2; }'`/tracing
echo nop > $tracefs/current_tracer
echo 0 > $tracefs/tracing_on
echo > $tracefs/trace

echo > $tracefs/set_ftrace_filter
echo > $tracefs/set_ftrace_notrace
echo > $tracefs/set_ftrace_pid
echo > $tracefs/set_ftrace_notrace_pid

echo > $tracefs/set_graph_function
echo > $tracefs/set_graph_notrace

echo > $tracefs/set_event
echo > $tracefs/set_event_pid
echo > $tracefs/set_event_notrace_pid

echo 0 > $tracefs/tracing_max_latency
echo 0 > $tracefs/options/func_stack_trace
