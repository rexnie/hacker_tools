#!/bin/sh
TRACE_CUR_PROCESS=1
tracefs=`grep debugfs /proc/mounts | awk '{ print $2; }'`/tracing
echo 0 > $tracefs/tracing_on
echo > $tracefs/trace

if [ $TRACE_CUR_PROCESS -eq 1 ]; then
	# trace current process
	echo $$ > $tracefs/set_event_pid
else
	# trace all processes
	echo > $tracefs/set_event_pid
fi

# enable a single event
#echo 1 > $tracefs/events/sched/sched_wakeup/enable

# enable all sched subsystem events
#echo 1 > $tracefs/events/sched/enable

# enable all events
echo 1 > $tracefs/events/enable

echo "enabled events is:"
cat $tracefs/set_event

echo 1 > $tracefs/tracing_on
exec $*
