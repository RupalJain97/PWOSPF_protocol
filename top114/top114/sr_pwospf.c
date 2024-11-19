/*-----------------------------------------------------------------------------
 * file: sr_pwospf.c
 * date: Tue Nov 23 23:24:18 PST 2004
 * Author: Martin Casado
 *
 * Description:
 *
 *---------------------------------------------------------------------------*/

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "sr_helper.h"
#include "sr_pwospf.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_protocol.h"
#include "pwospf_protocol.h"
#include "sr_arpcache.h"

/* Declaration of threads for PWOSPF subsystem */
pthread_t *hello_thread;
pthread_t *periodic_lsu_thread;
pthread_t *listener_thread;
static void *pwospf_run_thread(void *arg);

static int sequenceNum = 0;

/* Declaration required for LSU Packet Header */
static int len = sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_hello_hdr);
static int lsu_packet_len = (sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_lsu_hdr) + (sizeof(struct ospfv2_lsu) * 3));

/*
 **************************************************************************
 * Method: hello_handler
 * A method for sending periodic HELLO messages to discover neighboring nodes
 ***************************************************************************
 */
void *hello_handler(void *connection)
{
    while (1)
    {
        struct sr_instance *sr = (struct sr_instance *)connection;

        /* Lock the PWOSPF thread before sending HELLO packet */
        pthread_mutex_lock(&(sr->ospf_subsys->lock));
        struct sr_if *interfaces = sr->if_list;

        while (interfaces)
        {
            uint8_t *packet = ((uint8_t *)(malloc(len)));
            initiate_LSU_packet(packet, interfaces, len, OSPF_TYPE_HELLO);
            struct ospfv2_hello_hdr *ospf_hello_hdr = (struct ospfv2_hello_hdr *)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct ospfv2_hdr));
            ospf_hello_hdr->helloint = htons(OSPF_DEFAULT_HELLOINT);
            ospf_hello_hdr->padding = 0;
            sr_send_packet(sr, packet, len, interfaces->name);
            free(packet);
            interfaces = interfaces->next;
        }

        pthread_mutex_unlock(&(sr->ospf_subsys->lock));
        sleep(OSPF_DEFAULT_HELLOINT);
    }
    return NULL;
}

/*
 **************************************************************************
 * Method: periodic_lsu_handler
 * A method for sending LSU along one of the router's interfaces
 ***************************************************************************
 */
void *periodic_lsu_handler(void *connection)
{
    while (1)
    {
        struct sr_instance *sr = (struct sr_instance *)connection;

        /* Lock the PWOPSF thread before sending LSU */
        pthread_mutex_lock(&(sr->ospf_subsys->lock));

        struct sr_if *interfaces = sr->if_list;

        while (interfaces)
        {
            uint8_t *packet = (uint8_t *)malloc(lsu_packet_len);
            initiate_LSU_packet(packet, interfaces, len, OSPF_TYPE_LSU);

            struct ospfv2_lsu_hdr *lsu_hdr = (struct ospfv2_lsu_hdr *)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct ospfv2_hdr) + (sizeof(struct ospfv2_lsu_hdr) * 3));

            lsu_hdr->unused = 0;
            lsu_hdr->ttl = 64;
            sequenceNum++;
            lsu_hdr->seq = sequenceNum;

            if (interfaces->neighborId != 1)
            {
                struct sr_if *inter = sr->if_list;
                struct ospfv2_lsu *lsu_array = ((struct ospfv2_lsu *)(malloc(3 * sizeof(struct ospfv2_lsu))));
                int itr = 0;

                while (inter)
                {
                    uint32_t nexthop_mask = inter->ip & inter->mask;
                    lsu_array[itr].subnet = nexthop_mask;
                    lsu_array[itr].mask = inter->mask;
                    lsu_array[itr].rid = inter->neighborId;

                    itr++;
                    inter = inter->next;
                }

                memcpy(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_lsu_hdr), lsu_array, 3 * sizeof(struct ospfv2_lsu));

                sr_send_packet(sr, packet, lsu_packet_len, interfaces->name);
            }

            free(packet);
            interfaces = interfaces->next;
        }

        /* Unlock the PWOSPF subsystem thread for next periodic LSU */
        pthread_mutex_unlock(&(sr->ospf_subsys->lock));
        sleep(30);
    }

    return NULL;
}

/*---------------------------------------------------------------------
 * Method: pwospf_init(..)
 *
 * Sets up the internal data structures for the pwospf subsystem
 *
 * You may assume that the interfaces have been created and initialized
 * by this point.
 *---------------------------------------------------------------------*/
int pwospf_init(struct sr_instance *sr)
{
    assert(sr);
    /* creating threads */
    hello_thread = (pthread_t *)malloc(sizeof(pthread_t));
    periodic_lsu_thread = (pthread_t *)malloc(sizeof(pthread_t));
    listener_thread = (pthread_t *)malloc(sizeof(pthread_t));

    sr->ospf_subsys = (struct pwospf_subsys *)malloc(sizeof(struct pwospf_subsys));

    assert(sr->ospf_subsys);

    /* lock PWOSPF thread before starting */
    pthread_mutex_init(&(sr->ospf_subsys->lock), 0);

    /* start PWOSPF thread - raise error upon failure */
    if (pthread_create(&sr->ospf_subsys->thread, 0, pwospf_run_thread, sr))
    {
        perror("pthread_create");
        assert(0);
    }
    /* send HELLO, STATUS and LSU messages to neighbors */ 
    if (pthread_create(hello_thread, NULL, &hello_handler, sr))
    {
        perror("Hello Handler Thread created");
        assert(0);
    }
    if (pthread_create(listener_thread, NULL, &event_listener, sr))
    {
        perror("Event Listener Thread created");
        assert(0);
    }
    if (pthread_create(periodic_lsu_thread, NULL, &periodic_lsu_handler, sr))
    {
        perror("PWOSPF Thread created");
        assert(0);
    }
    return 0;
}

/*---------------------------------------------------------------------
 * Method: pwospf_lock
 *
 * Lock mutex associated with pwospf_subsys
 *
 *---------------------------------------------------------------------*/

void pwospf_lock(struct pwospf_subsys *subsys)
{
    if (pthread_mutex_lock(&subsys->lock))
    {
        assert(0);
    }
} /* -- pwospf_subsys -- */

/*---------------------------------------------------------------------
 * Method: pwospf_unlock
 *
 * Unlock mutex associated with pwospf subsystem
 *
 *---------------------------------------------------------------------*/

void pwospf_unlock(struct pwospf_subsys *subsys)
{
    if (pthread_mutex_unlock(&subsys->lock))
    {
        assert(0);
    }
} /* -- pwospf_subsys -- */

/*---------------------------------------------------------------------
 * Method: pwospf_run_thread
 *
 * Main thread of pwospf subsystem.
 *
 *---------------------------------------------------------------------*/

static void *pwospf_run_thread(void *arg)
{
    // struct sr_instance *sr = (struct sr_instance *)arg;
    // while (1)
    // {
    //     /* -- PWOSPF subsystem functionality should start  here! -- */

    //     pwospf_lock(sr->ospf_subsys);
    //     // printf(" pwospf subsystem sleeping \n");
    //     pwospf_unlock(sr->ospf_subsys);
    //     sleep(2);
    //     // printf(" pwospf subsystem awake \n");
    // };
    return NULL;
} /* -- run_ospf_thread -- */
