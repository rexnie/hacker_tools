// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/workqueue.h>
#include <linux/delay.h>
 
MODULE_LICENSE("GPL");
MODULE_AUTHOR("rex nie");
MODULE_DESCRIPTION("Test hardlockup");
 
static struct workqueue_struct *my_workqueue;
 
static void my_work_function(struct work_struct *work) {
    int cpu, intr1, intr2, intr3;
 
    cpu = get_cpu();
    intr1 = irqs_disabled();
    local_irq_disable();
    intr2 = irqs_disabled();
    put_cpu();
 
    mdelay(20000);
    intr3 = irqs_disabled();
 
    printk("irq status: %d %d %d %d\n", cpu, intr1, intr2, intr3);
}
 
static DECLARE_WORK(my_work, my_work_function);
 
static int __init my_module_init(void) {
    my_workqueue = create_workqueue("my_workqueue");
 
    if (!my_workqueue) {
        pr_err("Failed to create workqueue\n");
        return -ENOMEM;
    }
 
    queue_work_on(0, my_workqueue, &my_work);
 
    return 0;
}
 
static void __exit my_module_exit(void) {
    destroy_workqueue(my_workqueue);
}
 
module_init(my_module_init);
module_exit(my_module_exit);
