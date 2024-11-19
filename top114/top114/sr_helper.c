/**********************************************************************
 * File: sr_helper.c
 * Date: 3rd Dec 2023
 * Authors: Rupal Jain, Sarah Hyunju Song
 * Contact: jainrupal@arizona.edu, hyunjusong@arizona.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 *
 **********************************************************************/
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_pwospf.h"
#include "sr_protocol.h"
#include "pwospf_protocol.h"

/* Global variable */
struct neighbours *neighborRouter = NULL;
struct vertex *vertices = NULL;
int numInterface = 3;

/* Helper functions */

/*
 **************************************************************************
 * Method: checkSum
 * Here we calculate the checksum of 16 bits for non-IP fields
 ***************************************************************************
 */
uint16_t checkSum(uint8_t *hdr, int len)
{
    long summation = 0;
    while (len > 1)
    {
        summation += *((unsigned short *)hdr);
        hdr = hdr + 2;
        if (summation & 0x80000000)
        {
            summation = (summation & 0xFFFF) + (summation >> 16);
        }
        len -= 2;
    }

    if (len)
    {
        summation += (unsigned short)*(unsigned char *)hdr;
    }
    while (summation >> 16)
    {
        summation = (summation & 0xFFFF) + (summation >> 16);
    }
    return ~summation;
} 


/* pwospf.c */

/*
 **************************************************************************
 * Method: event_listener
 * with this function, we check if we did not receive any routing update from
 * a neighboring router for more than a specific interval OSPF_NEIGHBOR_TIMEOUT.
 * If we did not, then we assume that router is down, and delete it from our
 * neighboring nodes list.
 ***************************************************************************
 */
void *event_listener(void *timeout)
{
    struct sr_instance *sr = (struct sr_instance *)timeout;
    while (1)
    {
        struct neighbours *neighbor_list = neighborRouter;
        // printf("\n Printing Neighbors...\n");
        // printf("---------------------------------------------\n");
        // printNeighbours(neighbor_list);
        // printf("---------------------------------------------\n");

        time_t currTime = time(NULL);
        while (neighbor_list)
        {
            time_t lastUpdate = neighbor_list->lastUpdate;
            double diff = difftime(currTime, lastUpdate);

            if (diff > OSPF_NEIGHBOR_TIMEOUT && neighbor_list->routerId != 0)
            {
                remove_neighbor(sr, neighbor_list);
            }
            neighbor_list = neighbor_list->next;
        }
        sleep(30);
    }
    return NULL;
}

/* **************************************************************************
 * Function:check_rtable
 * This method is used to check Routing table if there exists the interface or not
 *---------------------------------------------------------------------*/
bool check_rtable(struct sr_instance *sr, char *interf)
{
    struct sr_rt *temp = sr->routing_table;
    while (temp)
    {
        if (strcmp(temp->interface, interf) == 0)
        {
            return true;
        }
        temp = temp->next;
    }
    return false;
}

/**
 * Find interface using the router's interface list to find the next hop of the destination
 */
struct sr_if *check_interface(struct sr_instance *sr, char *destination)
{
    struct sr_if *inter = sr->if_list;
    while (inter)
    {
        if (strcmp(destination, inter->name) == 0)
        {
            return inter;
        }
        inter = inter->next;
    }
    return NULL;
}

/*
 **************************************************************************
 * Method: match_router_ip
 * A method that returns Router ID of adjacent routers and returns IP address of neighboring node based on the type of the ip to match
 ***************************************************************************
 */
struct neighbours *match_router_ip(uint32_t IP_address, bool type)
{
    struct neighbours *nextHop = neighborRouter;
    if (type)
    {
        while (nextHop)
        {
            if (nextHop->routerId == IP_address)
            {
                return nextHop;
            }
            nextHop = nextHop->next;
        }
    }
    else
    {
        while (nextHop)
        {
            if (nextHop->ip == IP_address)
            {
                return nextHop;
            }
            nextHop = nextHop->next;
        }
    }
    return NULL;
}

/*
 **************************************************************************
 * Method: lsu_packet_handler
 * A method that updates a routers routing table based on new LSU received.
 ***************************************************************************
 */
void lsu_packet_handler(struct sr_instance *sr, uint8_t *pkt, struct sr_if *interface)
{
    struct ip *ip = (struct ip *)(pkt + sizeof(struct sr_ethernet_hdr));
    struct ospfv2_hdr *ospf_hdr = (struct ospfv2_hdr *)(pkt + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
    struct ospfv2_lsu_hdr *lsu_hdr = (struct ospfv2_lsu_hdr *)(pkt + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct ospfv2_hdr));
    struct ospfv2_lsu *lsu_array = (struct ospfv2_lsu *)(pkt + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_lsu_hdr));

    for (int i = 0; i < numInterface; i++)
    {
        if (finding_vertex(ospf_hdr->rid, lsu_array[i].subnet) == NULL)
        {
            if (vertices == NULL)
            {
                vertices = malloc(sizeof(struct vertex));
                vertices->routerId = ospf_hdr->rid;
                vertices->subnet = lsu_array[i].subnet;
                vertices->mask = lsu_array[i].mask;
                vertices->id = lsu_array[i].rid;
                vertices->nextHop = ip->ip_src.s_addr;
                vertices->sequence = lsu_hdr->seq;
                vertices->next = NULL;
            }
            else
            {
                struct vertex *vert = vertices;
                while (vert->next)
                {
                    vert = vert->next;
                }
                vert->next = (malloc)(sizeof(struct vertex));
                vert->next->routerId = ospf_hdr->rid;
                vert->next->subnet = lsu_array[i].subnet;
                vert->next->mask = lsu_array[i].mask;
                vert->next->id = lsu_array[i].rid;
                vert->next->nextHop = ip->ip_src.s_addr;
                vert->next->sequence = lsu_hdr->seq;

                vert->next->next = NULL;
            }
        }
    }

    update_routing_table(sr);
}

/*
 **************************************************************************
 * Method: hello_packet_handler
 * A method that adds a new neighbor to router's rtable based on HELLO packet received from one of its interfaces.
 ***************************************************************************
 */
void hello_packet_handler(struct sr_instance *sr, uint8_t *pkt, struct sr_if *interface)
{
    struct ip *ip = ((struct ip *)(pkt + sizeof(struct sr_ethernet_hdr)));

    struct ospfv2_hdr *ospf_hdr = (struct ospfv2_hdr *)(pkt + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
    struct ospfv2_hello_hdr *ospf_hello_hdr = (struct ospfv2_hello_hdr *)(pkt + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct ospfv2_hdr));
    time_t curr_t = time(NULL);

    struct neighbours *nextHop = match_router_ip(ospf_hdr->rid, 1);
    if (neighborRouter == NULL)
    {
        neighborRouter = (struct neighbours *)malloc(sizeof(struct neighbours));
        neighborRouter->ip = ip->ip_src.s_addr;
        neighborRouter->mask = ospf_hello_hdr->nmask;
        neighborRouter->lastUpdate = curr_t;
        neighborRouter->interFace = interface->name;
        neighborRouter->routerId = ospf_hdr->rid;
        neighborRouter->next = NULL;

        struct sr_if *interf = check_interface(sr, interface->name);
        if (interf)
        {
            interf->neighborId = ospf_hdr->rid;
            interf->neighborIp = ip->ip_src.s_addr;
        }
    }
    else if (nextHop == NULL && neighborRouter != NULL)
    {
        nextHop = neighborRouter;
        while (nextHop->next)
        {
            nextHop = nextHop->next;
        }

        nextHop->next = (struct neighbours *)malloc(sizeof(struct neighbours));

        nextHop->next->ip = ip->ip_src.s_addr;
        nextHop->next->mask = ospf_hello_hdr->nmask;
        nextHop->next->lastUpdate = curr_t;
        nextHop->next->interFace = interface->name;
        nextHop->next->routerId = ospf_hdr->rid;
        nextHop->next->next = NULL;

        struct sr_if *interf = check_interface(sr, interface->name);

        if (interf)
        {
            interf->neighborId = ospf_hdr->rid;
            interf->neighborIp = ip->ip_src.s_addr;
        }
    }
    else
    {
        nextHop = match_router_ip(ip->ip_src.s_addr, 0);
        if (nextHop != NULL)
        {
            nextHop->lastUpdate = curr_t;
        }
    }
}

/*
 **************************************************************************
 * Method: remove_neighbor
 * A method for deleting neighbor that is down
 ***************************************************************************
 */
void remove_neighbor(struct sr_instance *sr, struct neighbours *nextHop)
{
    struct neighbours *curr_node = neighborRouter;
    struct neighbours *previous_node = NULL;
    struct sr_if *inter = check_interface(sr, nextHop->interFace);
    if (inter)
    {
        inter->neighborId = 1;
    }

    if (nextHop == neighborRouter)
    {
        neighborRouter = neighborRouter->next;
        free(nextHop);
        return;
    }
    else
    {
        while (curr_node)
        {
            if (curr_node->ip == nextHop->ip)
            {
                previous_node->next = nextHop->next;
                free(nextHop);
                return;
            }
            previous_node = curr_node;
            curr_node = curr_node->next;
        }
    }
}

/*
 **************************************************************************
 * Method: initiate_LSU_packet
 * A method for setting up contents of OSPF update packet's header field before trying to transmit it to neighboring routers
 ***************************************************************************
 */
void initiate_LSU_packet(uint8_t *packet, struct sr_if *iface_list, int len, int type)
{
    struct sr_ethernet_hdr *eth_hdr = (struct sr_ethernet_hdr *)packet;
    struct ip *ip = ((struct ip *)(packet + sizeof(struct sr_ethernet_hdr)));
    struct ospfv2_hdr *ospf_hdr = (struct ospfv2_hdr *)(packet + sizeof(struct ip) + sizeof(struct sr_ethernet_hdr));

    for (int i = 0; i < ETHER_ADDR_LEN; i++)
    {
        eth_hdr->ether_dhost[i] = htons(0xff);
        eth_hdr->ether_shost[i] = iface_list->addr[i];
    }

    eth_hdr->ether_type = htons(ETHERTYPE_IP);
    ip->ip_id = htons(rand());
    ip->ip_v = 4;
    ip->ip_hl = 5;
    ip->ip_tos = 0;
    ip->ip_off = htons(IP_DF);
    ip->ip_ttl = 64;
    ip->ip_sum = 0;
    ip->ip_sum = checkSum(((uint8_t *)(ip)), sizeof(struct ip));
    ip->ip_src.s_addr = iface_list->ip;
    ip->ip_dst.s_addr = htonl(OSPF_AllSPFRouters);
    ip->ip_p = 89;

    ospf_hdr->version = OSPF_V2;
    ospf_hdr->type = type;
    ospf_hdr->aid = htonl(0);
    ospf_hdr->csum = 0;
    ospf_hdr->csum = checkSum(((uint8_t *)(ospf_hdr)), sizeof(struct ospfv2_hdr));
    ospf_hdr->autype = 0;
    ospf_hdr->audata = 0;
    
    if (type == OSPF_TYPE_HELLO)
    {
        ip->ip_len = htons(sizeof(struct ip) + sizeof(struct ospfv2_hdr) + (sizeof(struct ospfv2_hello_hdr)));
        ospf_hdr->len = htons(len - sizeof(struct sr_ethernet_hdr) - sizeof(struct ip));
    }
    else
    {
        ip->ip_len = htons(sizeof(struct ip) + sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_lsu_hdr) + (sizeof(struct ospfv2_lsu) * 3));
        ospf_hdr->len = htons(sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_lsu_hdr) + (sizeof(struct ospfv2_lsu) * 3));
    }

    if (strcmp(iface_list->name, "eth0") == 0)
    {
        ospf_hdr->rid = iface_list->ip;
    }
}

/*
 **************************************************************************
 * Method: finding_vertex
 * A method for finding a Vertex in topology (graph datastructure)
 ***************************************************************************
 */
struct vertex *finding_vertex(uint32_t rid, uint32_t subn)
{
    struct vertex *vert = vertices;
    while (vert)
    {
        if (vert->routerId == rid && vert->subnet == subn)
        {
            return vert;
        }
        vert = vert->next;
    }
    return NULL;
}


/*
 **************************************************************************
 Function: check_routing_table
 This function helps look up in routing table
 ***************************************************************************
 */
struct sr_rt *check_routing_table(struct sr_instance *sr, uint32_t ip_target, uint32_t nextHop)
{
    printf("Checking Routing Table:\n");
    struct sr_rt *entry = sr->routing_table;
    while (entry != NULL)
    {
        /* if dest.adddress == target_IP, return the interface */
        if (entry->dest.s_addr == ip_target && entry->gw.s_addr == nextHop)
        {
            return entry;
        }
        entry = entry->next;
    }
    return entry;
}

/*
 **************************************************************************
 * Method: update_routing_table
 * A method for updating routing table - lookup and prefix matching
 ***************************************************************************
 */
void update_routing_table(struct sr_instance *sr)
{
    struct vertex *nextHops = vertices;
    while (nextHops)
    {
        char *iface;
        if (nextHops->nextHop == 0)
        {
            return NULL;
        }
        struct sr_if *nextHop = sr->if_list;
        uint32_t max = 0;
        while (nextHop)
        {
            uint32_t temp = nextHop->ip & nextHops->nextHop;
            if (temp > max)
            {
                max = temp;
                iface = nextHop->name;
            }
            nextHop = nextHop->next;
        }

        if (iface && check_routing_table(sr, nextHops->subnet, nextHops->nextHop) == NULL)
        {
            generate_rtable(sr, nextHops->subnet, nextHops->nextHop, nextHops->mask, iface);
            sr_print_routing_table(sr);
        }
        nextHops = nextHops->next;
    }
    struct sr_if *interf = sr->if_list;
    while (interf)
    {
        bool found = check_rtable(sr, interf->name);
        if (!found)
            break;
        interf = interf->next;
    }
    if (interf)
    {
        generate_rtable(sr, (interf->ip & interf->mask), 0, interf->mask, interf->name);
    }
    struct sr_rt *rotable = sr->routing_table;

    while (rotable)
    {
        if (rotable->dest.s_addr == 0)
        {
            return;
        }
        rotable = rotable->next;
    }
    struct sr_if *iface = check_interface(sr, "eth0");

    generate_rtable(sr, 0, iface->neighborIp, 0, iface->name);
}

void generate_rtable(struct sr_instance *sr, uint32_t dest, uint32_t nextHop, uint32_t mask, char *iface)
{
    printf("\nAdding into Routing Table... \n");
    struct in_addr dest_addr;
    struct in_addr gateway_addr;
    struct in_addr mask_addr;

    dest_addr.s_addr = dest;
    gateway_addr.s_addr = nextHop;
    mask_addr.s_addr = mask;

    sr_add_rt_entry(sr, dest_addr, gateway_addr, mask_addr, iface);
}
