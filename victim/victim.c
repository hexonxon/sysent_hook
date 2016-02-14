//
//  victim.c
//  test
//
//  Created by eyakovlev on 11.02.16.
//  Copyright © 2016 acme. All rights reserved.
//

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <mach/mach.h>

//  2     88              mach_msg_trap:entry victim enters mach_msg_trap(7fff5fbffad8, 3, 24, 44, 607, 0, 0)

static int DoListen(void)
{
    printf("%d\n", getpid());
    
    volatile int f = 0;
    while(!f) {
        ;
    }
    
    return EXIT_SUCCESS;
}

int main(int argc, char** argv)
{
    kern_return_t rc = KERN_SUCCESS;
    task_t task;

    if (argc < 2) {
        return EXIT_FAILURE;
    }

    int listen = 0;
    if (0 == strcmp(argv[1], "listen")) {
        listen = 1;
    }
    
    if (listen) {
        return DoListen();
    }
    
    int pid = atoi(argv[1]);
    printf("Terminating pid %d\n", pid);
    
    rc = task_for_pid(mach_task_self(), pid, &task);//mach_task_self();
    if (rc != KERN_SUCCESS) {
        printf("task_for_pid failed: %d\n", rc);
        return rc;
    }
    
    rc = task_terminate(task);
    if (rc != KERN_SUCCESS) {
        printf("task_terminate failed: %d\n", rc);
        return rc;
    }

    
    return 0;
}