//
//  test.c
//  test
//
//  Created by eyakovlev on 06.02.16.
//  Copyright © 2016 acme. All rights reserved.
//

#include <mach/mach_types.h>
#include <sys/systm.h>
#include <sys/kernel.h>

#include "KernelResolver.h"

/*
 * System call prototypes.
 *
 * Derived from FreeBSD's syscalls.master by Landon Fuller, original RCS IDs below:
 *
 * $FreeBSD: src/sys/sys/sysproto.h,v 1.216 2008/01/08 22:01:26 jhb Exp $
 * created from FreeBSD: src/sys/kern/syscalls.master,v 1.235 2008/01/08 21:58:15 jhb Exp
 */

#define PAD_(t) (sizeof(uint64_t) <= sizeof(t) ? \
0 : sizeof(uint64_t) - sizeof(t))

#if BYTE_ORDER == LITTLE_ENDIAN
#define PADL_(t)        0
#define PADR_(t)        PAD_(t)
#else
#define PADL_(t)        PAD_(t)
#define PADR_(t)        0
#endif

/** ptrace request */
#define PT_DENY_ATTACH 31

/* nosys syscall */
#define SYS_syscall 0

/* exit syscall */
#define SYS_exit 1

/* fork syscall */
#define SYS_fork 2

/* read syscall */
#define SYS_read 3

/* wait4 syscall */
#define SYS_wait4 7

/* ptrace() syscall */
#define SYS_ptrace 26

struct ptrace_args {
    char req_l_[PADL_(int)]; int req; char req_r_[PADR_(int)];
    char pid_l_[PADL_(pid_t)]; pid_t pid; char pid_r_[PADR_(pid_t)];
    char addr_l_[PADL_(caddr_t)]; caddr_t addr; char addr_r_[PADR_(caddr_t)];
    char data_l_[PADL_(int)]; int data; char data_r_[PADR_(int)];
};

typedef int32_t	sy_call_t (struct proc *, void *, int *);
typedef void	sy_munge_t (const void *, void *);

struct sysent_yosemite {		/* system call table */
    sy_call_t	*sy_call;	/* implementing function */
//#if CONFIG_REQUIRES_U32_MUNGING
    sy_munge_t	*sy_arg_munge32; /* system call arguments munger for 32-bit process */
//#endif
    int32_t		sy_return_type; /* system call return types */
    int16_t		sy_narg;	/* number of args */
    uint16_t	sy_arg_bytes;	/* Total size of arguments in bytes for
                                 * 32-bit system calls
                                 */
};

#if 0
struct sysent {
    int16_t		sy_narg;		/* number of arguments */
    int8_t		reserved;		/* unused value */
    int8_t		sy_flags;		/* call flags */
    sy_call_t	*sy_call;		/* implementing function */
    sy_munge_t	*sy_arg_munge32;	/* munge system call arguments for 32-bit processes */
    sy_munge_t	*sy_arg_munge64;	/* munge system call arguments for 64-bit processes */
    int32_t		sy_return_type; /* return type */
    uint16_t	sy_arg_bytes;	/* The size of all arguments for 32-bit system calls, in bytes */
};
#endif // 0

/* This value is for OSX 10.7.1.  The exact _nsysent offset can be found
 * via:
 *
 *   nm -g /mach_kernel | grep _nsysent
 *
 * Due to a bug in the kext loading code, it's not currently possible
 * to link against com.apple.kernel to let the linker locate this.
 *
 * http://packetstorm.foofus.com/papers/attack/osx1061sysent.txt
 */
#define _NSYSENT_OSX_10_10_5_  ((uintptr_t)0xffffff8000a735b8ull)

static struct sysent *_sysent = NULL;
static int *_nsysent = (int *)_NSYSENT_OSX_10_10_5_;

//extern int nsysent;

/*
 * nsysent is placed directly before the hidden sysent, so skip ahead
 * and sanity check that we've found the sysent array.
 *
 * Clearly, this is extremely fragile and not for general consumption.
 */



//////////////////////////////////////////////////////////////////////////////////////////////

#define MSR_IA32_SYSENTER_CS            0x00000174
#define MSR_IA32_SYSENTER_ESP           0x00000175
#define MSR_IA32_SYSENTER_EIP           0x00000176

#define MSR_EFER                        0xc0000080 /* extended feature register */
#define MSR_STAR                        0xc0000081 /* legacy mode SYSCALL target */
#define MSR_LSTAR                       0xc0000082 /* long mode SYSCALL target */
#define MSR_CSTAR                       0xc0000083 /* compat mode SYSCALL target */

typedef struct __attribute__((packed)) idtr64 {
    uint16_t limit;
    uint64_t base;
} idtr64;

typedef struct __attribute__((packed)) idt_desc64 {
    uint16_t offset_low;
    uint16_t selector;
    uint8_t _zero;
    uint8_t attr;
    uint16_t offset_mid;
    uint32_t offset_high;
    uint32_t _zero2;
} idt_desc64;


extern void ReadIdtr(idtr64*);
extern uint64_t ReadCr3(void);
extern uint64_t ReadCr2(void);
extern uint64_t ReadCr0(void);

static uint64_t rdmsr(uint32_t index)
{
    uint32_t lo=0, hi=0;
    __asm__ __volatile__ ("rdmsr" : "=a"(lo), "=d"(hi) : "c"(index));
    return (((uint64_t)hi) << 32) | ((uint64_t)lo);
}

//06.02.16 16:53:42,000 kernel[0]: LSTAR = 0xffffff800e033670
//06.02.16 17:06:19,000 kernel[0]: kernel base @ 0xffffff800de00000


#define FIXED_BASE          0xffffff8000200000ull


// Returns 64bit kernel base address or -1 if failed
static uintptr_t find_kernel_base(void)
{
    uint64_t syscall_entry = rdmsr(MSR_LSTAR);
    uint32_t* test = (uint32_t*)syscall_entry;
    
    while ((uintptr_t)test > 0xffffff8000000000ull) {
        if (*test == MH_MAGIC_64) {
            return (uintptr_t)(test);
            break;
        }
        
        test--;
    }

    return (uint64_t)-1;
}

#include <mach-o/loader.h>
#include <mach/mach_vm.h>
#include <kern/task.h>
#include <mach/task_special_ports.h>
#include <mach/vm_map.h>

//#include <mach/mach.h>

extern vm_map_t get_task_map(task_t);

int process_header(const uint64_t base, uint64_t *data_address, uint64_t *data_size)
{
    // verify if it's a valid mach-o binary
    uint8_t *address    = NULL;
    
    struct mach_header_64 *mh = (struct mach_header_64*)base;
    
    switch (mh->magic)
    {
        case MH_MAGIC_64:
        {
            // first load cmd address
            address = (uint8_t*)(base + sizeof(struct mach_header_64));
            break;
        }
            /* 32 bits not supported */
        case MH_MAGIC:
        default:
            return -1;
    }
    
    // find the last command offset
    struct load_command *lc = NULL;
    
    for (uint32_t i = 0; i < mh->ncmds; i++)
    {
        lc = (struct load_command*)address;
        if (lc->cmd == LC_SEGMENT_64)
        {
            struct segment_command_64 *sc = (struct segment_command_64 *)lc;
            if (strncmp(sc->segname, "__DATA", 16) == 0)
            {
                *data_address = sc->vmaddr;
                *data_size = sc->vmsize;
                printf("[OK] Found __DATA segment at %p (size:0x%llx)\n", (void*)*data_address, *data_size);
                return 0;
            }
        }
        // advance to next command
        address += lc->cmdsize;
    }
    
    return -1;
}

static struct sysent_yosemite *find_sysent (uint64_t start, size_t size)
{
    uint64_t addr = start;
    while(size != 0) {
        struct sysent_yosemite *sysent = (struct sysent_yosemite*)addr;
        
        if(sysent[SYS_exit].sy_narg      == 1 &&
           sysent[SYS_fork].sy_narg      == 0 &&
           sysent[SYS_read].sy_narg      == 3 &&
           sysent[SYS_wait4].sy_narg     == 4 &&
           sysent[SYS_ptrace].sy_narg    == 4)// &&
           //sysent[SYS_getxattr].sy_narg  == 6 &&
           //sysent[SYS_listxattr].sy_narg == 4 &&
           //sysent[SYS_recvmsg].sy_narg   == 3 )
        {
            printf("[DEBUG] exit() address is %p\n", (void*)sysent[SYS_exit].sy_call);
            return sysent;
        }
        
        addr++;
        size--;
    }
    
#if 0
    unsigned int table_size;
    struct sysent_yosemite *table;
    
    table_size = sizeof(struct sysent_yosemite ) * *(_nsysent);
    table = (struct sysent_yosemite *) ( ((char *) _nsysent) - table_size);
    
    printf("[ptrace] Found nsysent at %p (count %d), calculated sysent location %p.\n", _nsysent, *_nsysent, table);
    
    for(int i = 0; i < 1000; ++i) {
        /* Sanity check */
        printf("[ptrace] Sanity check %d %d %d %d : ",
               table[SYS_syscall].sy_arg_bytes,
               table[SYS_exit].sy_arg_bytes,
               table[SYS_fork].sy_arg_bytes,
               table[SYS_read].sy_arg_bytes
               /*table[SYS_wait4].sy_arg_bytes,
                table[SYS_ptrace].sy_arg_bytes*/);
        
        if (table[SYS_syscall].sy_arg_bytes == 0 &&
            table[SYS_exit].sy_arg_bytes == 4  &&
            table[SYS_fork].sy_arg_bytes == 0 &&
            table[SYS_read].sy_arg_bytes == 12
            /*table[SYS_wait4].sy_arg_bytes == 4 &&
             table[SYS_ptrace].sy_arg_bytes == 4*/)
        {
            printf("sysent sanity check succeeded.\n");
            return table;
        } else {
            printf("sanity check failed, could not find sysent table.\n");
            //return NULL;
            table = (struct sysent*)((uintptr_t)table - 4);
        }
    }
#endif
    
    return NULL;
}

struct exit_args {
    char rval_l_[PADL_(int)]; int rval; char rval_r_[PADR_(int)];
};

typedef void (*exit_fptr_t)(proc_t p, struct exit_args *uap, int *retval);

static volatile exit_fptr_t g_orig_exit = NULL;

void my_exit(proc_t p, struct exit_args *uap, int *retval)
{
    printf("Calling my_exit!\n");
    g_orig_exit(p, uap, retval);
}

#define VMREMAP_ADDR 0xffffff80003daf50ull
#define VM_LOOKUP_ENTRY_ADDR 0xffffff800039eb60ull

#define VM_RELOC(base, addr) ((addr) - FIXED_BASE + (base))

typedef kern_return_t (*vm_remap_fptr_t) (
	vm_map_t target_task,
	vm_address_t *target_address,
	vm_size_t size,
	vm_address_t mask,
	int flags,
	vm_map_t src_task,
	vm_address_t src_address,
	boolean_t copy,
	vm_prot_t *cur_protection,
	vm_prot_t *max_protection,
	vm_inherit_t inheritance
 );

#include <vm/vm_map.h>

typedef struct vm_map_entry     *vm_map_entry_t;

struct vm_map_links {
         struct vm_map_entry     *prev;          /* previous entry */
         struct vm_map_entry     *next;          /* next entry */
         vm_map_offset_t         start;          /* start address */
         vm_map_offset_t         end;            /* end address */
};

#include <libkern/tree.h>

struct vm_map_store {
      RB_ENTRY(vm_map_store) entry;
};

typedef struct vm_object* vm_object_t;

struct vm_map_entry {
        struct vm_map_links     links;          /* links to other entries */
#define vme_prev                links.prev
#define vme_next                links.next
#define vme_start               links.start
#define vme_end                 links.end

        struct vm_map_store     store;
        //union vm_map_object     object;         /* object I point to */
    vm_object_t object;
        vm_object_offset_t      offset;         /* offset into object */
        unsigned int
        /* boolean_t */         is_shared:1,    /* region is shared */
        /* boolean_t */         is_sub_map:1,   /* Is "object" a submap? */
        /* boolean_t */         in_transition:1, /* Entry being changed */
        /* boolean_t */         needs_wakeup:1,  /* Waiters on in_transition */
        /* vm_behavior_t */     behavior:2,     /* user paging behavior hint */
                 /* behavior is not defined for submap type */
        /* boolean_t */         needs_copy:1,   /* object need to be copied? */
                 /* Only in task maps: */
         /* vm_prot_t */         protection:3,   /* protection code */
         /* vm_prot_t */         max_protection:3,/* maximum protection */
         /* vm_inherit_t */      inheritance:2,  /* inheritance */
        /* boolean_t */         use_pmap:1,     /* nested pmaps */
        /*
                 230          * IMPORTANT:
                 231          * The "alias" field can be updated while holding the VM map lock
                 232          * "shared".  It's OK as along as it's the only field that can be
                 233          * updated without the VM map "exclusive" lock.
                 234          */
        /* unsigned char */     alias:8,        /* user alias */
       /* boolean_t */         no_cache:1,     /* should new pages be cached? */
        /* boolean_t */         permanent:1,    /* mapping can not be removed */
        /* boolean_t */         superpage_size:3,/* use superpages of a certain size */
        /* boolean_t */         zero_wired_pages:1, /* zero out the wired pages of this entry it is being deleted without unwiring them */
        /* boolean_t */         used_for_jit:1,
        /* boolean_t */ from_reserved_zone:1;   /* Allocated from
                                                        242                                                  * kernel reserved zone  */
        unsigned short          wired_count;    /* can be paged if = 0 */
         unsigned short          user_wired_count; /* for vm_wire */
#if     DEBUG
#define MAP_ENTRY_CREATION_DEBUG (1)
#endif
#if     MAP_ENTRY_CREATION_DEBUG
        uintptr_t               vme_bt[16];
#endif
};
typedef boolean_t (*vm_map_lookup_entry_ptr_t)(register vm_map_t               map,
                                             register vm_map_offset_t        address,
                                             vm_map_entry_t                 *entry);

void dump_region_prot(vm_address_t addr)
{
    vm_size_t size;
    struct vm_region_basic_info info;
    mach_msg_type_number_t infoCnt = sizeof(info);
    kern_return_t err = vm_region(get_task_map(kernel_task), &addr, &size, VM_REGION_BASIC_INFO, (vm_region_info_t)&info, &infoCnt, NULL);
    if (err != KERN_SUCCESS) {
        printf("vm_region failed with %d\n", err);
    }
    
    printf("Region protection 0x%x, max protection 0x%x\n", info.protection, info.max_protection);
}

#include <vm/pmap.h>
#include <mach/vm_types.h>

kern_return_t test_start(kmod_info_t * ki, void *d)
{
    kern_return_t err = KERN_SUCCESS;
    
    printf("test_start\n");
    
    printf("LSTAR = 0x%016llx\n", rdmsr(MSR_LSTAR));
   
    uintptr_t kernel_base = find_kernel_base();
    if (kernel_base == -1) {
        return KERN_FAILURE;
    }
    
    printf("kernel base @ %p\n", (void*)kernel_base);
    
    struct mach_header_64* kernel_hdr = (struct mach_header_64*)kernel_base;
    if (kernel_hdr->magic != MH_MAGIC_64) {
        printf("Wrong kernel header\n");
        return KERN_FAILURE;
    }
    
    printf("0x%x\n", kernel_hdr->magic);
    
    vm_remap_fptr_t vm_remap_ptr = (vm_remap_fptr_t)(VMREMAP_ADDR - FIXED_BASE + kernel_base);
    (void)find_symbol(kernel_hdr, "_vm_remap");
    printf("vm_remap @ %p\n", vm_remap_ptr);
    uint8_t* p = (uint8_t*)vm_remap_ptr;
    for (int i = 0; i < 256; ++i) {
        if ((i % 32) == 0) {
            printf("\n");
        }
        
        printf("%02x ", p[i]);
    }
    
    _nsysent = (void*)(_NSYSENT_OSX_10_10_5_ - FIXED_BASE + kernel_base);
    printf("_nsysent @ %p = %d\n", _nsysent, *_nsysent);
    
    uint64_t data_seg_addr = 0;
    uint64_t data_seg_size = 0;
    
    process_header(kernel_base, &data_seg_addr, &data_seg_size);
    printf("data_seg_addr @ %p, size %llu\n", (void*)data_seg_addr, data_seg_size);
    
    struct sysent_yosemite* sysent = find_sysent(data_seg_addr, data_seg_size);
    printf("sysent @ %p\n", sysent);

    g_orig_exit = (exit_fptr_t) sysent[SYS_exit].sy_call;
    printf("exit @ %p\n", g_orig_exit);
    dump_region_prot((vm_address_t)g_orig_exit);
    
    //vm_map_t map = get_task_map(kernel_task);
    //printf("kernel_task @ %p, kernel_map @ %p\n", &kernel_task, map);

    vm_address_t addr = (vm_address_t)sysent;
    dump_region_prot(addr);
    
    vm_address_t newAddr = addr;
    vm_prot_t prot = VM_PROT_READ|VM_PROT_WRITE;
    vm_prot_t maxProt = VM_PROT_READ|VM_PROT_WRITE;
    //err = vm_remap_ptr(get_task_map(kernel_task), &newAddr, 4096, 0, VM_FLAGS_ANYWHERE, get_task_map(kernel_task), addr, FALSE, &prot, &maxProt, VM_INHERIT_SHARE);
    //err = vm_map(map, &newAddr, 4096, 0, VM_FLAGS_ANYWHERE, MEMORY_OBJECT_NULL, addr, FALSE, prot, maxProt, VM_INHERIT_SHARE);
    //if (err != KERN_SUCCESS) {
    //    printf("vm_remap failed with %d\n", err);
        //return err;
    //}
    
    printf("%p -> %p\n", addr, newAddr);//, ((struct sysent_yosemite*)newAddr)[SYS_exit].sy_call);
    dump_region_prot(newAddr);
   
    printf("CR0 = 0x%llx, CR2 = 0x%llx, CR3 = 0x%llx\n", ReadCr0(), ReadCr2(), ReadCr3());
    uint64_t pml4 = ReadCr3() & ~(4096 - 1);
    printf("pagedir @ %p\n", pml4);
    
    vm_map_entry_t entry;
    vm_map_lookup_entry_ptr_t vm_map_lookup_entry_ptr = (vm_map_lookup_entry_ptr_t)(VM_LOOKUP_ENTRY_ADDR - FIXED_BASE + kernel_base);
    
    if (!vm_map_lookup_entry_ptr(get_task_map(kernel_task), addr, &entry)) {
        printf("lookup failed\n");
    }
    
    printf("entry %p, protection %d, max %d\n", entry, entry->protection, entry->max_protection);
    entry->max_protection = VM_PROT_READ|VM_PROT_WRITE;
    dump_region_prot(addr);
    
    err = vm_protect(get_task_map(kernel_task), addr, 4096, FALSE, VM_PROT_READ|VM_PROT_WRITE);
    if (err) {
        printf("vm_protect: %d\n", err);
    }
    dump_region_prot(addr);
    
    //mach_vm_protect(kernel_map, sysent, 1, 1, 1);
    //sysent[SYS_exit].sy_call = sysent[SYS_exit].sy_call;
    
    //pmap_t pmap;
    
    //printf("kernel pmap @ %p\n", kernel_pmap);
    
    //entry->max_protection = 0;
    //err = vm_protect(get_task_map(kernel_task), addr, 4096, FALSE, 0);
    //if (err) {
    //    printf("vm_protect: %d\n", err);
   // }
    //dump_region_prot(addr);
    
    return KERN_SUCCESS;
}

kern_return_t test_stop(kmod_info_t *ki, void *d)
{
    printf("test_stop\n");
    return KERN_SUCCESS;
}
