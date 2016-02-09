//
//  arch.h
//  test
//
//  Created by eyakovlev on 09.02.16.
//  Copyright © 2016 acme. All rights reserved.
//

#ifndef arch_h
#define arch_h

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief   Disable VM read only access protection
 */
void AsmEnableWriteProtection(void);

/**
 * \brief   Enable VM read only access protection
 */
void AsmDisableWriteProtection(void);
    
#ifdef __cplusplus
}
#endif

#endif /* arch_h */
