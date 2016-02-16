//
//  resolver.h
//  test
//
//  Created by eyakovlev on 16.02.16.
//  Copyright © 2016 acme. All rights reserved.
//
//  Resolve private kernel symbols
//

#ifndef resolver_h
#define resolver_h

/**
 * \brief   Find kernel segment with name
 */
struct segment_command_64* find_segment_64(const struct mach_header_64* mh, const char* segname);

/**
 * \brief   Resolve private kernel symbol for loaded kernel image
 */
void* resolve_kernel_symbol(const char* name, uintptr_t loaded_kernel_base);

#endif /* resolver_h */
