// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/delay.h>

static int lockup_seconds = 30;
module_param(lockup_seconds, int, 0644);
MODULE_PARM_DESC(lockup_seconds, "Time in seconds to hold the CPU to create a softlockup");

static struct task_struct *softlockup_task;

static int softlockup_thread(void *data)
{
    unsigned long timeout = jiffies + lockup_seconds * HZ;
    
    pr_info("Softlockup: Thread started, locking CPU for %d seconds...\n", lockup_seconds);

    while (time_before(jiffies, timeout)) {
        cpu_relax();
    }

    pr_info("Softlockup: Thread completed.\n");

    return 0;
}

static int __init softlockup_init(void)
{
    pr_info("Softlockup: Initializing module...\n");

    softlockup_task = kthread_run(softlockup_thread, NULL, "softlockup_thread");

    if (IS_ERR(softlockup_task)) {
        pr_err("Softlockup: Failed to create thread\n");
        return PTR_ERR(softlockup_task);
    }

    pr_info("Softlockup: Module loaded\n");

    return 0;
}

static void __exit softlockup_exit(void)
{
    if (softlockup_task) {
        kthread_stop(softlockup_task);
        pr_info("Softlockup: Module unloaded\n");
    }
}

module_init(softlockup_init);
module_exit(softlockup_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Rex Nie");
MODULE_DESCRIPTION("module to trigge softlockup for testing purposes");
