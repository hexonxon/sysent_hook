//
//  test.c
//  test
//
//  Created by eyakovlev on 06.02.16.
//  Copyright © 2016 acme. All rights reserved.
//


///////////////////////////////////////////////////////////////////////////////////////////////////

#include <mach-o/loader.h>
#include <kern/task.h>
#include <mach/mach_types.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <libkern/OSMalloc.h>

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


static int get_kernel_version(void)
{
    size_t size = 0;
    
    if (sysctlbyname("kern.osrelease", NULL, &size, NULL, 0) )
    {
        printf("Failed to get kern.osrelease size.");
        return -1;
    }
    
    assert(size <= UINT32_MAX);
    uint32_t bufsize = (uint32_t)size;
    
    char *osrelease = OSMalloc(bufsize, g_tag);
    if (osrelease == NULL)
    {
        printf("Failed to allocate memory.");
        return -1;
    }
    
    if (sysctlbyname("kern.osrelease", osrelease, &size, NULL, 0))
    {
        printf("Failed to get kern.osrelease.");
        OSFree(osrelease, bufsize, g_tag);
        return -1;
    }
    
    char major[3] = {0};
    strncpy(major, osrelease, 2);
    OSFree(osrelease, bufsize, g_tag);
    
    return (int)strtol(major, (char**)NULL, 10);
}


static struct psysent find_sysent(uintptr_t start, size_t size)
{
    int major = get_kernel_version();
    printf("kernel version is %d\n", major);
    
    uintptr_t addr = start;
    
    while(size != 0) {

        #define sysent_verify(_sysent)           \
            (_sysent[SYS_exit].sy_narg == 1 &&   \
            _sysent[SYS_fork].sy_narg == 0 &&   \
            _sysent[SYS_read].sy_narg == 3 &&   \
            _sysent[SYS_wait4].sy_narg == 4 &&  \
            _sysent[SYS_ptrace].sy_narg == 4)
        
        if (major == 14) {
            struct sysent_yosemite* sysent = (struct sysent_yosemite*)addr;
            if (sysent_verify(sysent)) {
                struct psysent res = {sysent, major};
                return res;
            }
        } else if (major == 13) {
            struct sysent_mavericks* sysent = (struct sysent_mavericks*)addr;
            if (sysent_verify(sysent)) {
                struct psysent res = {sysent, major};
                return res;
            }
        } else {
            struct sysent* sysent = (struct sysent*)addr;
            if (sysent_verify(sysent)) {
                struct psysent res = {sysent, major};
                return res;
            }
        }
        
        #undef sysent_verify
        
        addr++;
        size--;
    }
    
    struct psysent res = {NULL, 0};
    return res;
}


///////////////////////////////////////////////////////////////////////////////////////////////////


static struct psysent g_sysent = {NULL, 0};

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

struct exit_args {
    char rval_l_[PADL_(int)]; int rval; char rval_r_[PADR_(int)];
};

typedef int32_t (*exit_fptr_t)(proc_t p, struct exit_args *uap, int *retval);

static exit_fptr_t g_orig_exit = NULL;


int32_t my_exit(proc_t p, struct exit_args *uap, int *retval)
{
    printf("Calling my_exit!\n");
    return g_orig_exit(p, uap, retval);
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

    // sysent is in read-only memory since 10.8.
    // good thing that intel architecture allows us to disable vm write protection completely from ring0 with a CR0 bit
    
    g_orig_exit = (exit_fptr_t) sysent_get_call(SYS_exit);
    AsmDisableWriteProtection();
    sysent_set_call(SYS_exit, (sy_call_t*)my_exit);
    AsmEnableWriteProtection();
    
    printf("original exit @ %p, hooked @ %p\n", g_orig_exit, my_exit);
    
    return KERN_SUCCESS;
}

kern_return_t test_stop(kmod_info_t *ki, void *d)
{
    if (g_orig_exit != NULL)
    {
        AsmDisableWriteProtection();
        sysent_set_call(SYS_exit, (sy_call_t*)g_orig_exit);
        AsmEnableWriteProtection();
        printf("original exit @ %p\n", g_orig_exit);
    }
    
    return KERN_SUCCESS;
}






