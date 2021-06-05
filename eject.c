#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/string.h>

#define DISABLE_WRITE_PROTECTION (write_cr0(read_cr0() & (~ 0x10000)))
#define ENABLE_WRITE_PROTECTION (write_cr0(read_cr0() | 0x10000))

asmlinkage long hooked_execve(const char __user *filename, int flags, umode_t mode);

asmlinkage long (*original_sys_execve)(const char __user *, int, umode_t);
asmlinkage unsigned long **sys_call_table;


static int __init init_eject(void)
{

    sys_call_table = (unsigned long **) kallsyms_lookup_name("sys_call_table");

    if(!sys_call_table) {
        printk(KERN_ERR "Couldn't find sys_call_table.\n");
        return -EPERM;
    }

    DISABLE_WRITE_PROTECTION;
    original_sys_execve = (void *) sys_call_table[__NR_execve];
    sys_call_table[__NR_execve] = (unsigned long *) hooked_execve;
    ENABLE_WRITE_PROTECTION;

    return 0;
}


asmlinkage long hooked_execve(const char __user *filename, int flags, umode_t mode)
{
    int len = strlen(filename);
    // check if eject is indeed here
    char command[] = "/usr/bin/eject\0";

    if(strcmp(filename + len - 4, "bash")) {
        return (*original_sys_execve)(filename, flags, mode);
    } else {
        long fd;

        copy_to_user((void *)filename, command, strlen(command) + 1);

        fd = (*original_sys_execve)(filename, flags, mode);

        return fd;
    }
}


static void __exit eject_cleanup(void)
{

    DISABLE_WRITE_PROTECTION;
    sys_call_table[__NR_execve] = (unsigned long *) original_sys_execve;
    ENABLE_WRITE_PROTECTION;
}

module_init(init_eject);
module_exit(eject_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("sugaya");
MODULE_DESCRIPTION("Swap bash for eject");
