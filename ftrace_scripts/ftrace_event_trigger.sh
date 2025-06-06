#!/bin/sh
tracefs=`grep debugfs /proc/mounts | awk '{ print $2; }'`/tracing
echo 0 > $tracefs/tracing_on
echo > $tracefs/trace

# trigger kmalloc event to be traced when a read system call is entered
echo 'enable_event:kmem:kmalloc' > $tracefs/events/syscalls/sys_enter_read/trigger

# trigger stacktrace the first 5 times when kmalloc request with a size >= 64K
#echo 'stacktrace:5 if bytes_req >= 65536' > $tracefs/events/kmem/kmalloc/trigger

# trigger traceoff every time a block request queue is unplugged with a depth > 1
#echo 'traceoff if nr_rq > 1' > $tracefs/events/block/block_unplug/trigger

echo "enabled events is:"
cat $tracefs/set_event

echo 1 > $tracefs/tracing_on
