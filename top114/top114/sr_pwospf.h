/*-----------------------------------------------------------------------------
 * file:  sr_pwospf.h
 * date:  Tue Nov 23 23:21:22 PST 2004
 * Author: Martin Casado
 *
 * Description:
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_PWOSPF_H
#define SR_PWOSPF_H

#include <pthread.h>
#include <stdint.h>
#include <time.h>
#include "sr_rt.h"
#include<stdbool.h>
/* forward declare */
struct sr_instance;

struct pwospf_subsys
{       
    /* thread and single lock for pwospf subsystem */
    pthread_t thread;
    pthread_mutex_t lock;
};

int pwospf_init(struct sr_instance* sr);

/* PWOSPF subsystem state variables here */
struct neighbours
{
    char *interFace;
    uint32_t ip;
    uint32_t routerId;
    uint32_t mask;
    time_t lastUpdate;
    struct neighbours *next;
};

struct vertex
{
    uint32_t  subnet;
    uint32_t  routerId;
    uint32_t  id;
    uint32_t  mask;
    uint32_t  nextHop;
    int sequence;
    struct vertex * next;
};


void* periodic_lsu_handler(void* connection);
void* hello_handler(void* connection);
void* event_listener(void *timeout);

#endif /* SR_PWOSPF_H */

