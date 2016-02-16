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

void* resolve_kernel_symbol(const char* name, uintptr_t loaded_kernel_base);

#endif /* resolver_h */
