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

#include <kern/task.h>

#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/proc.h>

#include <libkern/OSMalloc.h>
#include <libkern/version.h>

#include "arch.h"
#include "sysent.h"

#define MSR_EFER        0xc0000080 /* extended feature register */
#define MSR_STAR        0xc0000081 /* legacy mode SYSCALL target */
#define MSR_LSTAR       0xc0000082 /* long mode SYSCALL target */
#define MSR_CSTAR       0xc0000083 /* compat mode SYSCALL target */

#define XNU_FIXED_BASE  (0xffffff8000200000ull)
#define INVALID_VADDR   ((uintptr_t)-1)

#if !defined(assert)
#   define assert(cond)    \
         ((void) ((cond) ? 0 : panic("assertion failed: %s", # cond)))
#endif

static OSMallocTag g_tag = NULL;

///////////////////////////////////////////////////////////////////////////////////////////////////

static uint64_t rdmsr(uint32_t index)
{
    uint32_t lo=0, hi=0;
    __asm__ __volatile__ ("rdmsr" : "=a"(lo), "=d"(hi) : "c"(index));
    return (((uint64_t)hi) << 32) | ((uint64_t)lo);
}

// Returns 64bit kernel base address or -1 if failed
static uintptr_t find_kernel_base(void)
{
    // In case of ASLR kernel find real kernel base.
    // For that dump MSR_LSTAR which contains a pointer to kernel syscall handler
    uint64_t ptr = rdmsr(MSR_LSTAR);
    
    // Round up to next page boundary - kernel should start at a page boundary ASLR or no ALSR
    ptr = ptr & ~PAGE_MASK_64;
    
    while (ptr >= XNU_FIXED_BASE) {
        if (*(uint32_t*)ptr == MH_MAGIC_64) {
            return ptr;
        }
        
        ptr -= PAGE_SIZE;
    }
    
    return INVALID_VADDR;
}


// Returns base address and size (in bytes) of a data segment inside kernel mach binary
static uintptr_t get_data_segment(const struct mach_header_64* mh, uint64_t* out_size)
{
    if (!mh || !out_size) {
        return INVALID_VADDR;
    }
    
    if (mh->magic != MH_MAGIC_64) {
        return INVALID_VADDR;
    }
    
    uintptr_t base = (uintptr_t)mh;
    uintptr_t addr = base + sizeof(*mh);
    
    // find the last command offset
    struct load_command* lc = NULL;
    
    for (uint32_t i = 0; i < mh->ncmds; i++)
    {
        lc = (struct load_command*)addr;
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *sc = (struct segment_command_64 *)lc;
            if (strncmp(sc->segname, "__DATA", 16) == 0) {
                *out_size = sc->vmsize;
                return sc->vmaddr;
            }
        }
        
        // advance to next command
        addr += lc->cmdsize;
    }
    
    return INVALID_VADDR;
}


static psysent_t find_sysent(uintptr_t start, size_t size)
{
    printf("kernel version is %d\n", version_major);
    
    uintptr_t addr = start;
    
    while(size != 0) {

        #define sysent_verify(_sysent)           \
            (_sysent[SYS_exit].sy_narg == 1 &&   \
            _sysent[SYS_fork].sy_narg == 0 &&   \
            _sysent[SYS_read].sy_narg == 3 &&   \
            _sysent[SYS_wait4].sy_narg == 4 &&  \
            _sysent[SYS_ptrace].sy_narg == 4)
        
        if (version_major == 14) {
            struct sysent_yosemite* sysent = (struct sysent_yosemite*)addr;
            if (sysent_verify(sysent)) {
                psysent_t res = {sysent, version_major};
                return res;
            }
        } else if (version_major == 13) {
            struct sysent_mavericks* sysent = (struct sysent_mavericks*)addr;
            if (sysent_verify(sysent)) {
                psysent_t res = {sysent, version_major};
                return res;
            }
        } else {
            struct sysent* sysent = (struct sysent*)addr;
            if (sysent_verify(sysent)) {
                psysent_t res = {sysent, version_major};
                return res;
            }
        }
        
        #undef sysent_verify
        
        addr++;
        size--;
    }
    
    psysent_t res = {NULL, 0};
    return res;
}


static mach_trap_table_t* find_mach_trap_table(uintptr_t start, size_t size)
{
    uintptr_t addr = start;
    while(size != 0) {

        mach_trap_table_t* traps = (mach_trap_table_t*)addr;
        
        if (traps[0].mach_trap_arg_count == 0 &&
            traps[1].mach_trap_arg_count == 0 &&
            traps[MACH_MSG_TRAP].mach_trap_arg_count == 7 &&
            traps[MACH_MSG_OVERWRITE_TRAP].mach_trap_arg_count == 8)
        {
            return traps;
        }
        
        addr++;
        size--;
    }
    
    return NULL;
}


///////////////////////////////////////////////////////////////////////////////////////////////////


static int32_t g_pid = 0;   // PID we will protect, set through sysctl node
static int g_unhook = 0;    // Dummy sysctl node var to unhook syscalls

static psysent_t g_sysent = {NULL, 0};
static mach_trap_table_t* g_mach_trap_table = NULL;

static int(*g_orig_kill)(proc_t cp, struct kill_args *uap, __unused int32_t *retval) = NULL;
static mach_msg_return_t (*g_mach_msg_trap)(void* args) = NULL;

static int sysctl_killhook_pid SYSCTL_HANDLER_ARGS;
static int sysctl_killhook_unhook SYSCTL_HANDLER_ARGS;

SYSCTL_NODE(_debug, OID_AUTO, killhook, CTLFLAG_RW, 0, "kill hook API");
SYSCTL_PROC(_debug_killhook, OID_AUTO, pid, (CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_SECURE), &g_pid, 0, sysctl_killhook_pid, "I", "Protected PID");
SYSCTL_PROC(_debug_killhook, OID_AUTO, unhook, (CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_SECURE), &g_unhook, 0, sysctl_killhook_unhook, "I", "");

static void* sysent_get_call(int callnum) {
    switch(g_sysent.ver) {
        case 14: return g_sysent.u.p14[callnum].sy_call;
        case 13: return g_sysent.u.p13[callnum].sy_call;
        default: return g_sysent.u.p12[callnum].sy_call;
    }
}

static void sysent_set_call(int callnum, void* sy_call) {
    switch(g_sysent.ver) {
        case 14: g_sysent.u.p14[callnum].sy_call = sy_call; break;
        case 13: g_sysent.u.p13[callnum].sy_call = sy_call; break;
        default: g_sysent.u.p12[callnum].sy_call = sy_call; break;
    }
}

static int sysctl_killhook_pid(struct sysctl_oid *oidp, void *arg1, int arg2, struct sysctl_req *req)
{
    printf("sysctl_killhook_pid: %p (%p), %d, %d\n", oidp->oid_arg1, &g_pid, *(int32_t*)oidp->oid_arg1, oidp->oid_arg2);
    
    int32_t curPid = g_pid;
    int res = sysctl_handle_int(oidp, oidp->oid_arg1, oidp->oid_arg2, req);
    
    if (g_pid != curPid) {
        proc_t proc = proc_find(g_pid);
        if (proc) {
            //g_task = proc_task(proc);
            proc_rele(proc);
        }
        
        printf("PID changed to %d\n", g_pid);
    }
    
    return res;
}

static int sysctl_killhook_unhook(struct sysctl_oid *oidp, void *arg1, int arg2, struct sysctl_req *req)
{
    int res = sysctl_handle_int(oidp, oidp->oid_arg1, oidp->oid_arg2, req);
    if (g_unhook && g_sysent.u.raw && g_mach_trap_table)
    {
        // TODO: it is dangerous to just overwrite syscalls again, we need to make sure that there are no pending syscalls
        AsmDisableWriteProtection();
        g_mach_trap_table[MACH_MSG_TRAP].mach_trap_function = g_mach_msg_trap;
        sysent_set_call(SYS_kill, (sy_call_t*)g_orig_kill);
        AsmEnableWriteProtection();
    }
    
    return res;
}

#define PAD_ARG_(arg_type, arg_name) \
   char arg_name##_l_[PADL_(arg_type)]; arg_type arg_name; char arg_name##_r_[PADR_(arg_type)];

#define PAD_ARG_8

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

mach_msg_return_t my_mach_msg_trap(struct mach_msg_overwrite_trap_args *args)
{
    //int pid = 0;
    //pid_for_task(current_task(), &pid);

    task_t task = current_task();
    proc_t proc = current_proc();
    pid_t pid = proc_pid(proc);
    
    if (!g_pid || pid != g_pid) {
        return g_mach_msg_trap(args);
    }
    
    printf("task = %p, proc = %p, pid = %d\n", task, proc, pid);
    
    printf("my_mach_msg_trap: %p (%zu)\n", args, sizeof(*args));
    printf(" msg = %llx\n", args->msg);
    printf(" option = %x\n", args->option);
    printf(" send_size = %d\n", args->send_size);
    printf(" rcv_size = %d\n", args->rcv_size);
    printf(" timeout = %d\n", args->timeout);
    
    if (args->option & MACH_RCV_MSG) {
        return MACH_RCV_TIMED_OUT;
    }
    
    return g_mach_msg_trap(args);
    
    /*
       
    //mach_msg_header_t* hdr = OSMalloc(args->send_size, g_tag);
    //if (hdr) {
    //    copyin(args->msg, hdr, args->send_size);
    //    printf(" msg bits 0x%x, size %d, id %d, %p -> %p\n", hdr->msgh_bits, hdr->msgh_size, hdr->msgh_id, hdr->msgh_local_port, hdr->msgh_remote_port);
    //    OSFree(hdr, args->send_size, g_tag);
    //}
    
        
    if ((args->option & MACH_SEND_MSG) && (args->send_size)) {
        mach_msg_header_t* hdr = OSMalloc(args->send_size, g_tag);
        if (hdr) {
            copyin(args->msg, hdr, args->send_size);
            printf(" msg bits 0x%x, size %d, id %d, %p -> %p\n", hdr->msgh_bits, hdr->msgh_size, hdr->msgh_id, hdr->msgh_local_port, hdr->msgh_remote_port);
            
            for (int i = 0; i < args->send_size; ++i) {
                if ((i % 32) == 0) {
                    printf("\n");
                }
                
                printf(" 0x%02x", ((uint8_t*)hdr)[i]);
            }
            
            OSFree(hdr, args->send_size, g_tag);
        }
    }
    
    int res = g_mach_msg_trap(args);
        
    printf("returning %d\n", res);
    return res;
    
    
    //for (int i = 0; i < 2; ++i) {
    //    printf(" 0x%x\n", ((uint32_t*)args)[i]);
    //}

    //return g_mach_msg_trap(args);
     */
    

}

struct kill_args {
    char pid_l_[PADL_(int)]; int pid; char pid_r_[PADR_(int)];
    char signum_l_[PADL_(int)]; int signum; char signum_r_[PADR_(int)];
    char posix_l_[PADL_(int)]; int posix; char posix_r_[PADR_(int)];
};

// TODO: indirect syscall(2), killpg(2), better signal parsing
int my_kill(proc_t cp, struct kill_args *uap, __unused int32_t *retval)
{
    
    if (!g_pid || (uap->pid != g_pid)) {
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


kern_return_t test_start(kmod_info_t * ki, void *d)
{
    g_tag = OSMalloc_Tagalloc("test.kext", OSMT_DEFAULT);
    if (!g_tag) {
        printf("Failed to allocate OSMalloc tag\n");
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

    uint64_t data_seg_size = 0;
    uint64_t data_seg_addr = get_data_segment(kernel_hdr, &data_seg_size);
    if (data_seg_addr == INVALID_VADDR) {
        printf("Can't find kernel base address\n");
        return KERN_FAILURE;
    }
    
    printf("kernel data segment @ 0x%llx, %llu bytes\n", data_seg_addr, data_seg_size);

    // TODO: non-yosemite structures
    g_sysent = find_sysent(data_seg_addr, data_seg_size);
    if (!g_sysent.u.raw) {
        printf("Can't find syscall table\n");
        return KERN_FAILURE;
    }
    
    printf("sysent @ %p, version %d\n", g_sysent.u.raw, g_sysent.ver);
    
    //mach_traps = (mach_trap_t*)(0xffffff8000a01890ull - XNU_FIXED_BASE + kernel_base);
    g_mach_trap_table = find_mach_trap_table(data_seg_addr, data_seg_size);
    if (!g_mach_trap_table) {
        printf("Can't find mach trap table\n");
        return KERN_FAILURE;
    }
    
    printf("mach trap table @ %p (should be at %p)\n", g_mach_trap_table, 0xffffff8000a01890ull - XNU_FIXED_BASE + kernel_base);
    
    // sysent is in read-only memory since 10.8.
    // good thing that intel architecture allows us to disable vm write protection completely from ring0 with a CR0 bit
    g_orig_kill = sysent_get_call(SYS_kill);
    g_mach_msg_trap = g_mach_trap_table[MACH_MSG_TRAP].mach_trap_function;
    
    AsmDisableWriteProtection();
    sysent_set_call(SYS_kill, (sy_call_t*)my_kill);
    g_mach_trap_table[MACH_MSG_TRAP].mach_trap_function = my_mach_msg_trap;
    AsmEnableWriteProtection();
    
    printf("original @ %p, hooked @ %p\n", g_orig_kill, my_kill);
    
    sysctl_register_oid(&sysctl__debug_killhook);
    sysctl_register_oid(&sysctl__debug_killhook_pid);
    sysctl_register_oid(&sysctl__debug_killhook_unhook);

    return KERN_SUCCESS;
}

kern_return_t test_stop(kmod_info_t *ki, void *d)
{
    sysctl_unregister_oid(&sysctl__debug_killhook);
    sysctl_unregister_oid(&sysctl__debug_killhook_pid);
    sysctl_unregister_oid(&sysctl__debug_killhook_unhook);

    return KERN_SUCCESS;
}
