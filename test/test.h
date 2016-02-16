//
//  test.h
//  test
//
//  Created by eyakovlev on 16.02.16.
//  Copyright © 2016 acme. All rights reserved.
//

#ifndef test_h
#define test_h

// kext-wide malloc tag
extern OSMallocTag g_tag;

// kext-wide lock group
extern lck_grp_t* g_lock_group;

#endif /* test_h */
