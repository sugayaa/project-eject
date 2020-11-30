#include<unistd.h>
#include<sys/types.h>
// execve("/usr/bin/bash", ["bash"], 0x7fff23adffb0 /* 42 vars */) = 0

#define unprotect_memory() \
({ \
        orig_cr0 = read_cr0(); \
        write_cr0(orig_cr0 & (~ 0x10000)); \
});

#define protect_memory() \
({ \
        write_cr0(orig_cr0); \
});




asmlinkage long (*orig_eject)(int, int);
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

asmlinkage int hooked_eject(int magic1, int magic2)
{
    printk("Hooked!");
    return orig_eject(magic1, magic2);
}

int main(void){
    int ret;
    char *cmd[2] = { "eject", (char *)0 };
    char *env[1] = {NULL};

    ret = execve ("/bin/eject", cmd, env);

    return 0;
}
