#include<linux/module.h>
#include<linux/kernel.h>
#include<unistd.h>
#include<sys/types.h>
// execve("/usr/bin/bash", ["bash"], 0x7fff23adffb0 /* 42 vars */) = 0

unsigned long orig_cr0;
long ret;
char *cmd[2] = { "eject", (char *)0 };
char *env[1] = {NULL};

#define unprotect_memory() \
({ \
        orig_cr0 = read_cr0(); \
        write_cr0(orig_cr0 & (~ 0x10000)); \
});

#define protect_memory() \
({ \
        write_cr0(orig_cr0); \
});




asmlinkage long (*orig_execve)(const char *pathname, char *const argv[], char *const envp[]);
unsigned long *sys_call_table;

hooking_syscall(void *hook_addr, __uint16_t syscall_offset, unsigned long *sys_call_table)
{
    unprotect_memory();
    sys_call_table[syscall_offset] = (unsigned long)hook_addr;
    protect_memory();
}

unhooking_syscall(void *orig_addr, u_int16_t syscall_offset)
{
    unprotect_memory();
    sys_call_table[syscall_offset] = (unsigned long)orig_addr;
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
}

static void __exit eject_cleanup(void)
{
    unhooking_syscall(orig_execve, __NE_execve, sys_call_table);
}
