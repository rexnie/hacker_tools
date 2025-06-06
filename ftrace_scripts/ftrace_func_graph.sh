#!/bin/sh
tracefs=`grep debugfs /proc/mounts | awk '{ print $2; }'`/tracing/
echo $tracefs
echo nop > $tracefs/current_tracer
echo 0 > $tracefs/tracing_on
echo > $tracefs/set_ftrace_filter
echo > $tracefs/set_ftrace_notrace

# print callee's stacktrace
#echo 1 > $tracefs/options/func_stack_trace

#echo soft_offline_page > $tracefs/set_graph_function
#echo migrate_pages >> $tracefs/set_graph_function

echo function_graph > $tracefs/current_tracer
echo 0 > $tracefs/options/funcgraph-tail
#echo 1 > $tracefs/funcgraph-retval
echo 1 > $tracefs/tracing_on
echo > $tracefs/trace
exec $*
