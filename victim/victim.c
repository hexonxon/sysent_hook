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
#include <mach/message.h>

//  2     88              mach_msg_trap:entry victim enters mach_msg_trap(7fff5fbffad8, 3, 24, 44, 607, 0, 0)

static int DoListen(void)
{
    mach_msg_return_t err;
    printf("%d\n", getpid());
    
    /* Allocate a port.  */
    mach_port_t port;
    err = mach_port_allocate (mach_task_self (),
                              MACH_PORT_RIGHT_RECEIVE, &port);
    if (err) {
        printf("mach_port_allocate failed with 0x%x\n", err);
        return err;
    }
    
    volatile int f = 0;
    while(!f) {
        uint8_t recv_buf[4096];
        mach_msg_header_t* hdr = (mach_msg_header_t*)recv_buf;
        mach_msg_return_t err = mach_msg(hdr, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof(recv_buf), port, 5000, MACH_PORT_NULL);
        if (err == MACH_RCV_TIMED_OUT) {
            continue;
        }
        
        if (err) {
            printf("mach_msg failed with 0x%x\n", err);
            continue;
        }
        
        printf("Recv message:\n");
        printf("size = %d\n", hdr->msgh_size);
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
    
    printf("%d\n", getpid());
    
    int pid = atoi(argv[1]);
    printf("Terminating pid %d\n", pid);
    
    rc = task_for_pid(mach_task_self(), pid, &task);//mach_task_self();
    if (rc != KERN_SUCCESS) {
        printf("task_for_pid failed: %d\n", rc);
        return rc;
    }
    
    do {
        printf("Terminating task at port %d\n", task);
        rc = task_terminate(task);
        if (rc != KERN_SUCCESS) {
            printf("task_terminate failed: %d\n", rc);
            //return rc;
        }
        
        sleep(5);
    } while (rc != KERN_SUCCESS);

    
    return 0;
}