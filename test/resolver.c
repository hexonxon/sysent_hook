//
//  resolver.c
//  test
//
//  Created by eyakovlev on 16.02.16.
//  Copyright © 2016 acme. All rights reserved.
//

#include <mach/mach_types.h>
#include <mach-o/loader.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/vnode.h>
#include <sys/vnode_if.h>

#include <libkern/libkern.h>
#include <libkern/version.h>
#include <libkern/OSMalloc.h>

#include "test.h"

//
// Original KernelResolver code by snare:
// https://github.com/snare/KernelResolver
//
//
// Since 10.8 apple removed kernel symbols from loaded image
// So we will have to load kernel image from disk and parse that
// Modified to parse static kernel images
//

/* Borrowed from kernel source. It doesn't exist in Kernel.framework. */
struct nlist_64 {
    union {
        uint32_t  n_strx;   /* index into the string table */
    } n_un;
    uint8_t n_type;         /* type flag, see below */
    uint8_t n_sect;         /* section number or NO_SECT */
    uint16_t n_desc;        /* see <mach-o/stab.h> */
    uint64_t n_value;       /* value of this symbol (or stab offset) */
};

struct segment_command_64* find_segment_64(const struct mach_header_64* mh, const char* segname)
{
    if (!mh) {
        return NULL;
    }
    
    if (mh->magic != MH_MAGIC_64) {
        return NULL;
    }
    
    if (!segname) {
        return NULL;
    }
    
    struct load_command *lc;
    struct segment_command_64 *seg, *foundseg = NULL;
    
    /* First LC begins straight after the mach header */
    lc = (struct load_command *)((uint64_t)mh + sizeof(struct mach_header_64));
    while ((uint64_t)lc < (uint64_t)mh + (uint64_t)mh->sizeofcmds) {
        if (lc->cmd == LC_SEGMENT_64) {
            /* Check load command's segment name */
            seg = (struct segment_command_64 *)lc;
            if (strcmp(seg->segname, segname) == 0) {
                foundseg = seg;
                break;
            }
        }
        
        /* Next LC */
        lc = (struct load_command *)((uint64_t)lc + (uint64_t)lc->cmdsize);
    }
    
    /* Return the segment (NULL if we didn't find it) */
    return foundseg;
}

struct section_64* find_section_64(struct segment_command_64 *seg, const char *name)
{
    struct section_64 *sect, *foundsect = NULL;
    u_int i = 0;
    
    /* First section begins straight after the segment header */
    for (i = 0, sect = (struct section_64 *)((uint64_t)seg + (uint64_t)sizeof(struct segment_command_64));
         i < seg->nsects;
         i++, sect = (struct section_64 *)((uint64_t)sect + sizeof(struct section_64)))
    {
        /* Check section name */
        if (strcmp(sect->sectname, name) == 0) {
            foundsect = sect;
            break;
        }
    }
    
    /* Return the section (NULL if we didn't find it) */
    return foundsect;
}

struct load_command *
find_load_command(struct mach_header_64 *mh, uint32_t cmd)
{
    struct load_command *lc, *foundlc;
    
    /* First LC begins straight after the mach header */
    lc = (struct load_command *)((uint64_t)mh + sizeof(struct mach_header_64));
    while ((uint64_t)lc < (uint64_t)mh + (uint64_t)mh->sizeofcmds) {
        if (lc->cmd == cmd) {
            foundlc = (struct load_command *)lc;
            break;
        }
        
        /* Next LC */
        lc = (struct load_command *)((uint64_t)lc + (uint64_t)lc->cmdsize);
    }
    
    /* Return the load command (NULL if we didn't find it) */
    return foundlc;
}

void *find_symbol(struct mach_header_64 *mh, const char *name, uint64_t loaded_base)
{
    /*
     * Check header
     */
    if (mh->magic != MH_MAGIC_64) {
        printf("magic number doesn't match - 0x%x\n", mh->magic);
        return NULL;
    }
    
    /*
     * Find __TEXT - we need it for fixed kernel base
     */
    struct segment_command_64 *seg_text = find_segment_64(mh, SEG_TEXT);
    if (!seg_text) {
        printf("couldn't find __TEXT\n");
        return NULL;
    }
    
    uint64_t fixed_base = seg_text->vmaddr;
    
    /*
     * Find the LINKEDIT and SYMTAB sections
     */
    struct segment_command_64 *seg_linkedit = find_segment_64(mh, SEG_LINKEDIT);
    if (!seg_linkedit) {
        printf("couldn't find __LINKEDIT\n");
        return NULL;
    }
    
    struct symtab_command *lc_symtab = (struct symtab_command *)find_load_command(mh, LC_SYMTAB);
    if (!lc_symtab) {
        printf("couldn't find SYMTAB\n");
        return NULL;
    }
   
    /*
     * Enumerate symbols until we find the one we're after
     */
    uintptr_t base = (uintptr_t)mh;
    void* strtab = (void*)(base + lc_symtab->stroff);
    void* symtab = (void*)(base + lc_symtab->symoff);
    
    //printf("Symbol table offset 0x%x (%p)\n", lc_symtab->symoff, symtab);
    //printf("String table offset 0x%x (%p)\n", lc_symtab->stroff, strtab);
    
    struct nlist_64* nl = (struct nlist_64 *)(symtab);
    for (uint64_t i = 0; i < lc_symtab->nsyms; i++, nl = (struct nlist_64 *)((uint64_t)nl + sizeof(struct nlist_64)))
    {
        const char* str = (const char *)strtab + nl->n_un.n_strx;
        if (strcmp(str, name) == 0) {
            /* Return relocated address */
            return (void*) (nl->n_value - fixed_base + loaded_base);
        }
    }
    
    /* Return the address (NULL if we didn't find it) */
    return NULL;
}

void* resolve_kernel_symbol(const char* name, uintptr_t loaded_kernel_base)
{
    void* addr = NULL;
    errno_t err = 0;
    
    if (!name) {
        return NULL;
    }
    
    const char* image_path = "/mach_kernel";
    if (version_major >= 14) {
        image_path = "/System/Library/Kernels/kernel"; // Since yosemite mach_kernel is moved
    }
    
    vfs_context_t context = vfs_context_create(NULL);
    if(!context) {
        printf("vfs_context_create failed: %d\n", err);
        return NULL;
    }
    
    char* data = NULL;
    uio_t uio = NULL;
    vnode_t vnode = NULL;
    err = vnode_lookup(image_path, 0, &vnode, context);
    if (err) {
        printf("vnode_lookup(%s) failed: %d\n", image_path, err);
        goto done;
    }
    
    // Read whole kernel file into memory.
    // It is not very efficient but it is the easiest way to adapt existing parsing code
    // For production builds we need to use less memory
    
    struct vnode_attr attr;
    err = vnode_getattr(vnode, &attr, context);
    if (err) {
        printf("can't get vnode attr: %d\n", err);
        goto done;
    }
    
    uint32_t data_size = (uint32_t)attr.va_data_size;
    data = OSMalloc(data_size, g_tag);
    if (!data) {
        printf("Could not allocate kernel buffer\n");
        goto done;
    }
    
    uio = uio_create(1, 0, UIO_SYSSPACE, UIO_READ);
    if (!uio) {
        printf("uio_create failed: %d\n", err);
        goto done;
    }
    
    err = uio_addiov(uio, CAST_USER_ADDR_T(data), data_size);
    if (err) {
        printf("uio_addiov failed: %d\n", err);
        goto done;
    }
    
    err = VNOP_READ(vnode, uio, 0, context);
    if (err) {
        printf("VNOP_READ failed: %d\n", err);
        goto done;
    }
    
    addr = find_symbol((struct mach_header_64*)data, name, loaded_kernel_base);
    
    
done:
    uio_free(uio);
    OSFree(data, data_size, g_tag);
    vnode_put(vnode);
    vfs_context_rele(context);
    
    return addr;
}
