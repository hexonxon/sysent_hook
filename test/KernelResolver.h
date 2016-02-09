//
//  KernelResolver.h
//  test
//
//  Created by eyakovlev on 09.02.16.
//  Copyright © 2016 acme. All rights reserved.
//

#ifndef KernelResolver_h
#define KernelResolver_h

#include <mach-o/loader.h>

void *
find_symbol(struct mach_header_64 *mh, const char *name);

#endif /* KernelResolver_h */
