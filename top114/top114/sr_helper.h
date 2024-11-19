/*-----------------------------------------------------------------------------
 * File: sr_helper.h
 * Date: 3rd Dec 2023
 * Authors: Rupal Jain, Sarah Hyunju Song
 * Contact: jainrupal@arizona.edu, hyunjusong@arizona.edu 
 *  
 * Description: This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 * 
 *---------------------------------------------------------------------------*/

#ifndef SR_HELPER_H
#define SR_HELPER_H

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>


/* Helper functions */
uint16_t checkSum(uint8_t* hdr, int len);



/* pwospf.c */

bool check_rtable(struct sr_instance *sr, char *intf);
struct sr_if *check_interface(struct sr_instance *sr, char *destination);
struct neighbours *match_router_ip(uint32_t IP_address, bool type);

void lsu_packet_handler(struct sr_instance *sr, uint8_t *packet, struct sr_if *iface);
void hello_packet_handler(struct sr_instance *sr, uint8_t *packet, struct sr_if *iface);
void remove_neighbor(struct sr_instance*,struct neighbours *target);
void initiate_LSU_packet(uint8_t *packet, struct sr_if *iface_list, int len, int type);

struct vertex * finding_vertex(uint32_t routerId ,uint32_t subnet);

struct sr_rt *check_routing_table(struct sr_instance *sr, uint32_t ipTarget, uint32_t nextHop);
void update_routing_table(struct sr_instance* sr);
void generate_rtable(struct sr_instance *sr,uint32_t destination ,uint32_t nextHop,uint32_t mask,char *interface);


#endif