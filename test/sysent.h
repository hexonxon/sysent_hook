//
//  sysent.h
//  test
//
//  Created by eyakovlev on 09.02.16.
//  Copyright © 2016 acme. All rights reserved.
//

#ifndef sysent_h
#define sysent_h

/*
 * System call prototypes.
 *
 * Derived from FreeBSD's syscalls.master by Landon Fuller, original RCS IDs below:
 *
 * $FreeBSD: src/sys/sys/sysproto.h,v 1.216 2008/01/08 22:01:26 jhb Exp $
 * created from FreeBSD: src/sys/kern/syscalls.master,v 1.235 2008/01/08 21:58:15 jhb
 */

/*
 * Modified by me to support yosemite
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

typedef int32_t	sy_call_t (struct proc *, void *, int *);
typedef void	sy_munge_t (const void *, void *);

// 10.8 and prior */
struct sysent {
    int16_t		sy_narg;            /* number of arguments */
    int8_t		reserved;           /* unused value */
    int8_t		sy_flags;           /* call flags */
    sy_call_t	*sy_call;           /* implementing function */
    sy_munge_t	*sy_arg_munge32;	/* munge system call arguments for 32-bit processes */
    sy_munge_t	*sy_arg_munge64;	/* munge system call arguments for 64-bit processes */
    int32_t		sy_return_type;     /* return type */
    uint16_t	sy_arg_bytes;       /* The size of all arguments for 32-bit system calls, in bytes */
};

// 10.9
struct sysent_mavericks {           /* system call table */
    sy_call_t	*sy_call;           /* implementing function */
    sy_munge_t	*sy_arg_munge32;    /* system call arguments munger for 32-bit process */
    sy_munge_t	*sy_arg_munge64;    /* system call arguments munger for 64-bit process */
    int32_t		sy_return_type;     /* system call return types */
    int16_t		sy_narg;            /* number of args */
    uint16_t	sy_arg_bytes;       /* Total size of arguments in bytes for
                                     * 32-bit system calls
                                     */
};

// 10.10+
struct sysent_yosemite {            /* system call table */
    sy_call_t	*sy_call;           /* implementing function */
    sy_munge_t	*sy_arg_munge32;    /* system call arguments munger for 32-bit process */
    int32_t		sy_return_type;     /* system call return types */
    int16_t		sy_narg;            /* number of args */
    uint16_t	sy_arg_bytes;       /* Total size of arguments in bytes for
                                     * 32-bit system calls
                                     */
};

// Generic holder
struct psysent {
    union {
        void* raw;
        struct sysent* p12;
        struct sysent_mavericks* p13;
        struct sysent_yosemite* p14;
    } u;
    
    int ver;
};

#endif /* sysent_h */
