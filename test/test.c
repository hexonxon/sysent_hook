//
//  test.c
//  test
//
//  Created by eyakovlev on 06.02.16.
//  Copyright © 2016 acme. All rights reserved.
//

#include <mach/mach_types.h>

kern_return_t test_start(kmod_info_t * ki, void *d);
kern_return_t test_stop(kmod_info_t *ki, void *d);

kern_return_t test_start(kmod_info_t * ki, void *d)
{
    return KERN_SUCCESS;
}

kern_return_t test_stop(kmod_info_t *ki, void *d)
{
    return KERN_SUCCESS;
}
