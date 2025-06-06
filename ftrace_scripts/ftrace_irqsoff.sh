#!/bin/sh
tracefs=`grep debugfs /proc/mounts | awk '{ print $2; }'`/tracing
echo nop > $tracefs/current_tracer
echo 0 > $tracefs/tracing_on

# set function_tracer will get much larger latency
echo 0 > $tracefs/options/function_tracer

# get function graph
#echo 1 > $tracefs/options/display-graph

echo irqsoff > $tracefs/current_tracer
echo 1 > $tracefs/tracing_on
