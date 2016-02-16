//
//  test.c
//  test
//
//  Created by eyakovlev on 06.02.16.
//  Copyright © 2016 acme. All rights reserved.
//

///////////////////////////////////////////////////////////////////////////////////////////////////

#include <mach-o/loader.h>
#include <mach/mach_types.h>
#include <mach/message.h>
#include <mach/mach_port.h>
#include <mach/task.h>

#include <kern/task.h>
#include <kern/clock.h>

#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/proc.h>

#include <libkern/OSMalloc.h>
#include <libkern/version.h>

#include <IOKit/IOLib.h>

#include "test.h"
#include "sysent.h"
#include "resolver.h"

#define MSR_EFER        0xc0000080 /* extended feature register */
#define MSR_STAR        0xc0000081 /* legacy mode SYSCALL target */
#define MSR_LSTAR       0xc0000082 /* long mode SYSCALL target */
#define MSR_CSTAR       0xc0000083 /* compat mode SYSCALL target */

#define INVALID_VADDR   ((uintptr_t)-1)

#if !defined(assert)
#   define assert(cond)    \
         ((void) ((cond) ? 0 : panic("assertion failed: %s", # cond)))
#endif

OSMallocTag g_tag = NULL;
lck_grp_t* g_lock_group = NULL;

// Traced task context
static task_t g_task = NULL;
static int32_t g_pid = 0;       // PID we will protect, set through sysctl node
static int g_unhook = 0;        // Dummy sysctl node var to unhook everything before exiting

// Hooked syscall tables
static void* g_sysent_table = NULL;
static void* g_mach_trap_table = NULL;

// Private kernel symbols manually resolved on kext start
static task_t(*proc_task)(proc_t) = NULL;
static ipc_space_t(*get_task_ipcspace)(task_t) = NULL;
static task_t(*port_name_to_task)(mach_port_name_t) = NULL;

static lck_mtx_t* g_task_lock = NULL;

static void* sysent_get_call(int callnum) {
    switch(version_major) {
        case 14: return ((struct sysent_yosemite*)g_sysent_table)[callnum].sy_call;
        case 13: return ((struct sysent_mavericks*)g_sysent_table)[callnum].sy_call;
        default: return ((struct sysent*)g_sysent_table)[callnum].sy_call;
    }
}

static void sysent_set_call(int callnum, void* sy_call) {
    switch(version_major) {
        case 14: ((struct sysent_yosemite*)g_sysent_table)[callnum].sy_call = sy_call; break;
        case 13: ((struct sysent_mavericks*)g_sysent_table)[callnum].sy_call = sy_call; break;
        default: ((struct sysent*)g_sysent_table)[callnum].sy_call = sy_call; break;
    }
}

static void* sysent_hook_call(int callnum, void* hook) {
    void* orig = sysent_get_call(callnum);
    sysent_set_call(callnum, hook);
    return orig;
}

static void* mach_table_get_trap(int trapnum) {
    if (version_major >= 13) {
        return ((mach_trap_mavericks_t*)g_mach_trap_table)[trapnum].mach_trap_function;
    } else {
        return ((mach_trap_t*)g_mach_trap_table)[trapnum].mach_trap_function;
    }
}

static void mach_table_set_trap(int trapnum, void* trap_function) {
    if (version_major >= 13) {
        ((mach_trap_mavericks_t*)g_mach_trap_table)[trapnum].mach_trap_function = trap_function;
    } else {
        ((mach_trap_t*)g_mach_trap_table)[trapnum].mach_trap_function = trap_function;
    }
}

static void* mach_table_hook_trap(int trapnum, void* hook) {
    void* orig = mach_table_get_trap(trapnum);
    mach_table_set_trap(trapnum, hook);
    return orig;
}

static uint64_t rdmsr(uint32_t index)
{
    uint32_t lo=0, hi=0;
    __asm__ __volatile__ ("rdmsr" : "=a"(lo), "=d"(hi) : "c"(index));
    return (((uint64_t)hi) << 32) | ((uint64_t)lo);
}

// Clear CR0 page read only protection bit
static void disable_vm_protection(void)
{
    __asm__ __volatile__(
                         "cli    \n\t" \
                         "mov    %%cr0, %%rax \n\t" \
                         "and    $0xfffffffffffeffff, %%rax \n\t" \
                         "mov    %%rax, %%cr0 \n\t" \
                         "sti    \n\t"
                         :::"rax"
                         );
}

// Set CR0 page read only protection bit
static void enable_vm_protection(void)
{
    __asm__ __volatile__(
                         "cli    \n\t" \
                         "mov    %%cr0, %%rax \n\t" \
                         "or     $0x10000, %%rax \n\t" \
                         "mov    %%rax, %%cr0 \n\t" \
                         "sti    \n\t"
                         :::"rax"
                         );
}

// Finds and returns 64bit loaded kernel base address or INVALID_VADDR if failed
static uintptr_t find_kernel_base(void)
{
    // In case of ASLR kernel find real kernel base.
    // For that dump MSR_LSTAR which contains a pointer to kernel syscall handler
    uint64_t ptr = rdmsr(MSR_LSTAR);
    
    // Round up to next page boundary - kernel should start at a page boundary ASLR or no ALSR
    ptr = ptr & ~PAGE_MASK_64;
    while (ptr) {
        if (*(uint32_t*)ptr == MH_MAGIC_64) {
            return ptr;
        }
        
        ptr -= PAGE_SIZE;
    }
    
    return INVALID_VADDR;
}

// Matches sysent table in memory at given address
static int is_sysent_table(uintptr_t addr)
{
    #define sysent_verify(_sysent)              \
        ((_sysent)[SYS_exit].sy_narg == 1 &&    \
         (_sysent)[SYS_fork].sy_narg == 0 &&    \
         (_sysent)[SYS_read].sy_narg == 3 &&    \
         (_sysent)[SYS_wait4].sy_narg == 4 &&   \
         (_sysent)[SYS_ptrace].sy_narg == 4)
    
    if (version_major == 14) {
        struct sysent_yosemite* sysent = (struct sysent_yosemite*)addr;
        return sysent_verify(sysent);
    } else if (version_major == 13) {
        struct sysent_mavericks* sysent = (struct sysent_mavericks*)addr;
        return sysent_verify(sysent);
    } else {
        struct sysent* sysent = (struct sysent*)addr;
        return sysent_verify(sysent);
    }
    
    #undef sysent_verify
    return FALSE;
}

// Matches mach trap table in memory at given address
static int is_mach_trap_table(uintptr_t addr)
{
    #define traps_verify(_traps)                                \
        ((_traps)[0].mach_trap_arg_count == 0 &&                \
         (_traps)[1].mach_trap_arg_count == 0 &&                \
         (_traps)[MACH_MSG_TRAP].mach_trap_arg_count == 7 &&    \
         (_traps)[MACH_MSG_OVERWRITE_TRAP].mach_trap_arg_count == 8)
    
    if (version_major >= 13) {
        mach_trap_mavericks_t* res = (mach_trap_mavericks_t*)addr;
        return traps_verify(res);
    } else {
        mach_trap_t* res = (mach_trap_t*)addr;
        return traps_verify(res);
    }
    
    #undef traps_verify
    return FALSE;
}

// Search kernel data segment for BSD sysent table and mach trap table
static int find_syscall_tables(const struct segment_command_64* dataseg, void** psysent, void** pmach_traps)
{
    assert(dataseg);
    assert(psysent);
    assert(pmach_traps);
    
    void* sysent = NULL;
    void* mach_traps = NULL;
    
    uintptr_t addr = dataseg->vmaddr;
    uint64_t size = dataseg->vmsize;
    
    while(size != 0) {
        
        if (!sysent && is_sysent_table(addr)) {
            sysent = (void*)addr;
        }
        
        if (!mach_traps && is_mach_trap_table(addr)) {
            mach_traps = (void*)addr;
        }
    
        if (sysent && mach_traps) {
            *psysent = sysent;
            *pmach_traps = mach_traps;
            return TRUE;
        }
        
        addr++;
        size--;
    }
    
    return FALSE;
}

//
// Mach hooks
//

static mach_msg_return_t (*g_mach_msg_trap)(void* args) = NULL;
static mach_msg_return_t (*g_mach_msg_overwrite_trap)(void* args) = NULL;

#define MIG_TASK_TERMINATE_ID 3401 /* Taken from osfmk/mach/task.defs */

struct mach_msg_overwrite_trap_args {
    PAD_ARG_(user_addr_t, msg);
    PAD_ARG_(mach_msg_option_t, option);
    PAD_ARG_(mach_msg_size_t, send_size);
    PAD_ARG_(mach_msg_size_t, rcv_size);
    PAD_ARG_(mach_port_name_t, rcv_name);
    PAD_ARG_(mach_msg_timeout_t, timeout);
    PAD_ARG_(mach_port_name_t, notify);
    PAD_ARG_8
    PAD_ARG_(user_addr_t, rcv_msg);  /* Unused on mach_msg_trap */
};

// User mode message header definition differs from in-kernel one
typedef	struct
{
    mach_msg_bits_t     msgh_bits;
    mach_msg_size_t     msgh_size;
    __darwin_natural_t	msgh_remote_port;
    __darwin_natural_t	msgh_local_port;
    __darwin_natural_t	msgh_voucher_port;
    mach_msg_id_t		msgh_id;
} mach_user_msg_header_t;

mach_msg_return_t mach_msg_trap_common(struct mach_msg_overwrite_trap_args *args, mach_msg_return_t(*orig_handler)(void* args))
{
    if (!g_task || !(args->option & MACH_SEND_MSG)) {
        return orig_handler(args);
    }
    
    mach_user_msg_header_t hdr;
    if (args->send_size < sizeof(hdr)) {
        return MACH_SEND_MSG_TOO_SMALL; // "Sorry, your message is too small for this rootkit to process correctly"
    }
    
    copyin(args->msg, &hdr, sizeof(hdr));
    task_t remote_task = port_name_to_task(hdr.msgh_remote_port);
    if (g_task == remote_task) {
        // TODO: also check if this is a task kernel port
        printf("my_mach_msg_trap: blocking task_terminate\n");
        return MACH_SEND_INVALID_RIGHT;
    }
    
    return orig_handler(args);
}

// mach_msg_trap hook
mach_msg_return_t my_mach_msg_trap(struct mach_msg_overwrite_trap_args *args)
{
    return mach_msg_trap_common(args, g_mach_msg_trap);
}

// mach_msg_overwrite_trap hook
mach_msg_return_t my_mach_msg_overwrite_trap(struct mach_msg_overwrite_trap_args *args)
{
    return mach_msg_trap_common(args, g_mach_msg_overwrite_trap);
}

//
// BSD kill(2) hook
//

static int(*g_orig_kill)(proc_t cp, void *uap, __unused int32_t *retval) = NULL;

struct kill_args {
    char pid_l_[PADL_(int)]; int pid; char pid_r_[PADR_(int)];
    char signum_l_[PADL_(int)]; int signum; char signum_r_[PADR_(int)];
    char posix_l_[PADL_(int)]; int posix; char posix_r_[PADR_(int)];
};

int my_kill(proc_t cp, struct kill_args *uap, __unused int32_t *retval)
{
    // Negative pid is a killpg case
    pid_t pid = (uap->pid > 0 ? uap->pid : -uap->pid);
    
    if (!g_pid || (pid != g_pid)) {
        return g_orig_kill(cp, uap, retval);
    }
    
    printf("signal %d from pid %d to pid %d, posix %d\n", uap->signum, proc_pid(cp), uap->pid, uap->posix);
    
    // TODO: process cannot ignore or handle SIGKILL so we intercept it here.
    // However there are other signals that will terminate a process if it doesn't handle or ignore these signals (i.e. SIGTERM)
    // We don't handle those here for now.
    if (uap->signum == SIGKILL || uap->signum == SIGTERM) {
        printf("blocking SIGKILL\n");
        return EPERM;
    }
    
    return g_orig_kill(cp, uap, retval);
}

//
// Entry and init
//

// kext uses sysctl nodes to communicate with the client:
// 'debug.killhook.pid' - set 32bit pid value for process to protect
// 'debug.killhook.unhook' - set to 1 to unhook all syscalls before unloading kext

static int sysctl_killhook_pid SYSCTL_HANDLER_ARGS;
static int sysctl_killhook_unhook SYSCTL_HANDLER_ARGS;

SYSCTL_NODE(_debug, OID_AUTO, killhook, CTLFLAG_RW, 0, "kill hook API");
SYSCTL_PROC(_debug_killhook, OID_AUTO, pid, (CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_SECURE), &g_pid, 0, sysctl_killhook_pid, "I", "");
SYSCTL_PROC(_debug_killhook, OID_AUTO, unhook, (CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_SECURE), &g_unhook, 0, sysctl_killhook_unhook, "I", "");

static int sysctl_killhook_pid(struct sysctl_oid *oidp, void *arg1, int arg2, struct sysctl_req *req)
{
    int32_t curPid = g_pid;
    int res = sysctl_handle_int(oidp, oidp->oid_arg1, oidp->oid_arg2, req);
    
    if (g_pid != curPid) {
        
        proc_t proc = proc_find(g_pid);
        if (proc) {
            g_task = proc_task(proc);
            proc_rele(proc);
            printf("PID changed to %d, task %p\n", g_pid, g_task);
        }
    }
    
    return res;
}

static int syscalls_hooked(void)
{
    return ((mach_table_get_trap(MACH_MSG_OVERWRITE_TRAP) == my_mach_msg_overwrite_trap) &&
            (mach_table_get_trap(MACH_MSG_TRAP) == my_mach_msg_trap) &&
            (sysent_get_call(SYS_kill) == my_kill));
}

static int sysctl_killhook_unhook(struct sysctl_oid *oidp, void *arg1, int arg2, struct sysctl_req *req)
{
    int res = sysctl_handle_int(oidp, oidp->oid_arg1, oidp->oid_arg2, req);
    if (g_unhook && syscalls_hooked())
    {
        // Unhook syscalls
        // See comments in test_stop why this is done in sysctl handler
        disable_vm_protection();
        {
            mach_table_set_trap(MACH_MSG_OVERWRITE_TRAP, g_mach_msg_overwrite_trap);
            mach_table_set_trap(MACH_MSG_TRAP, g_mach_msg_trap);
            sysent_set_call(SYS_kill, (sy_call_t*)g_orig_kill);
        }
        enable_vm_protection();
    }
    
    return res;
}

kern_return_t test_start(kmod_info_t * ki, void *d)
{
    g_tag = OSMalloc_Tagalloc("test.kext", OSMT_DEFAULT);
    if (!g_tag) {
        printf("Failed to allocate OSMalloc tag\n");
        return KERN_FAILURE;
    }
    
    g_lock_group = lck_grp_alloc_init("test.kext", LCK_GRP_ATTR_NULL);
    if (!g_lock_group) {
        printf("Failed to create lock group\n");
        return KERN_FAILURE;
    }
    
    g_task_lock = lck_mtx_alloc_init(g_lock_group, LCK_ATTR_NULL);
    if (!g_task_lock) {
        printf("Failed to create lock group\n");
        return KERN_FAILURE;
    }
    
    //
    // We will attempt to hook sysent table to intercept syscalls we are interested in
    // For that we will find kernel base address, find data segment in kernel mach-o headers
    // and finally search for sysent pattern in data segment
    //
    
    uintptr_t kernel_base = find_kernel_base();
    if (kernel_base == INVALID_VADDR) {
        printf("Can't find kernel base address\n");
        return KERN_FAILURE;
    }
    
    struct mach_header_64* kernel_hdr = (struct mach_header_64*)kernel_base;
    if (kernel_hdr->magic != MH_MAGIC_64) {
        printf("Wrong kernel header\n");
        return KERN_FAILURE;
    }

    printf("kernel base @ %p\n", kernel_hdr);

    // Resolve some private symbols we're going to need
    proc_task = resolve_kernel_symbol("_proc_task", kernel_base);
    get_task_ipcspace = resolve_kernel_symbol("_get_task_ipcspace", kernel_base);
    port_name_to_task = resolve_kernel_symbol("_port_name_to_task", kernel_base);
    if (!proc_task || !get_task_ipcspace || !port_name_to_task) {
        printf("Could not resolve private symbols\n");
        return KERN_FAILURE;
    }
    
    struct segment_command_64* dataseg = find_segment_64(kernel_hdr, SEG_DATA);
    if (!dataseg) {
        printf("Can't find kernel data segment\n");
        return KERN_FAILURE;
    }
    
    printf("kernel data segment @ 0x%llx, %llu bytes\n", dataseg->vmaddr, dataseg->vmsize);

    // TODO: non-yosemite structures
    if (!find_syscall_tables(dataseg, &g_sysent_table, &g_mach_trap_table)) {
        printf("Can't find syscall tables\n");
        return KERN_FAILURE;
    }
    
    printf("sysent @ %p\n", g_sysent_table);
    printf("mach trap table @ %p\n", g_mach_trap_table);
    
    // sysent is in read-only memory since 10.8.
    // good thing that intel architecture allows us to disable vm write protection completely from ring0 with a CR0 bit
    disable_vm_protection();
    {
        g_orig_kill = sysent_hook_call(SYS_kill, (sy_call_t*)my_kill);
        g_mach_msg_trap = mach_table_hook_trap(MACH_MSG_TRAP, my_mach_msg_trap);
        g_mach_msg_overwrite_trap = mach_table_hook_trap(MACH_MSG_OVERWRITE_TRAP, my_mach_msg_overwrite_trap);
    }
    enable_vm_protection();

    sysctl_register_oid(&sysctl__debug_killhook);
    sysctl_register_oid(&sysctl__debug_killhook_pid);
    sysctl_register_oid(&sysctl__debug_killhook_unhook);

    return KERN_SUCCESS;
}

kern_return_t test_stop(kmod_info_t *ki, void *d)
{
    // At this point a pointer to one of our hooked syscall may already be loaded by unix_syscall64
    // which leads to a race condition with our unload process (in-flight syscall may execute unloaded kext code)
    // This is a bad situation we can't really do anything about since we're not a part of syscall implementation path.
    // Disabling interrupts won't help since syscalls can be in flight on another core.
    // For now the best thing i can think of is to do unhook separetely, using a sysctl node and then unloading
    if (syscalls_hooked()) {
        printf("Please unhook syscalls before unloading (debug.killhook.unhook)\n");
        return KERN_ABORTED;
    }
    
    sysctl_unregister_oid(&sysctl__debug_killhook);
    sysctl_unregister_oid(&sysctl__debug_killhook_pid);
    sysctl_unregister_oid(&sysctl__debug_killhook_unhook);

    lck_mtx_free(g_task_lock, g_lock_group);
    lck_grp_free(g_lock_group);
    
    OSMalloc_Tagfree(g_tag);
    
    return KERN_SUCCESS;
}
