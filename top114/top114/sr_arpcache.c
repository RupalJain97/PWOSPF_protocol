/************************
 * File: sr_arpcache.c
 * Date: 3rd Dec 2023
 * Authors: Rupal Jain, Sarah Hyunju Song
 * Contact: jainrupal@arizona.edu, hyunjusong@arizona.edu
 *
 * Description:
 *
 * This file contains the implementation of the ARP cache.
 * It includes the functionality to insert entries into the cache,
 * and periodically discard the content after 10 seconds using a thread.
 *
 *
 ************************/

#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include <sys/time.h>
#include <stdbool.h>

#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_helper.h"
#include "sr_pwospf.h"

/** GLOBAL VARIABLES */
struct arp_cache *curr_cache = NULL;
struct arp_cache_packets *curr_packets_head = NULL;
unsigned char MAC[ETHER_ADDR_LEN];

/**
 * Method: check_buffer
 * 
 * Check if ip exists in arp cache. 
*/
bool check_buffer(uint32_t ip)
{
    struct arp_cache *runner = curr_cache;

    /* if arp_cache->ip == ip, return the current pointer */
    while (runner)
    {
        if (runner->ip == ip)
        {
            memset(MAC, '\0', sizeof(MAC));
            memcpy(MAC, runner->mac, ETHER_ADDR_LEN);
            return true;
        }
        runner = runner->next;
    }
    return false;
}

/**
 * Method: find_entry_from_cache
 * 
 * Find the corresponding entry from cache.
*/
struct arp_cache *find_entry_from_cache(uint32_t ip)
{
    struct arp_cache *curr = curr_cache;
    while (curr)
    {
        if (curr->ip == ip)
        {
            return curr;
        }
        curr = curr->next;
    }
    return NULL;
}

/**
 * Method: insert_to_cache
 * 
 * Insert new entry to arp cache.
*/
void insert_to_cache(uint32_t ip, unsigned char mac[ETHER_ADDR_LEN])
{
    if (check_buffer(ip) == true)
    {
        return;
    }

    /* Creating entry in cache */
    struct arp_cache *entry = (struct arp_cache *)malloc(sizeof(struct arp_cache));
    entry->ip = ip;
    memcpy(entry->mac, mac, ETHER_ADDR_LEN);
    entry->next = NULL;

    /* Adding to current cache */
    if (curr_cache == NULL)
    {
        curr_cache = entry;
    }
    else
    {
        struct arp_cache *ptr = curr_cache;
        while (ptr->next != NULL)
        {
            ptr = ptr->next;
        }
        ptr->next = entry;
    }
}

/**
 * Method: insert_to_cached_packets
 *
 * Insert into cached ARP packets linked list.
 *
 */
void insert_to_cached_packets(uint8_t *packet, struct sr_ethernet_hdr *header, int len, struct sr_instance *sr, char *inter)
{
    struct arp_cache_packets *entry = (struct arp_cache_packets *)malloc(sizeof(struct arp_cache_packets));

    entry->sr = sr;
    entry->packet = packet;
    entry->length = len;
    entry->inter = inter;
    entry->next = NULL;

    /* creating list of cached packet */
    if (curr_packets_head == NULL)
    {
        curr_packets_head = entry;
    }
    else
    {
        struct arp_cache_packets *tail = curr_packets_head;
        while (tail->next != NULL)
        {
            tail = tail->next;
        }
        tail->next = entry;
    }
}

/**
 * Method: send_arp_cached_packets
 * 
 * Send the cached packets existing in ARP Cache
*/
void send_arp_cached_packets(uint32_t ip_addr, char *src_interface, char *dest_interface)
{
    struct arp_cache_packets *curr = curr_packets_head;

    while (curr)
    {
        struct sr_ethernet_hdr *etheader = (struct sr_ethernet_hdr *)(curr->packet);

        if (strcmp(curr->inter, dest_interface) == 0)
        {
            struct sr_if *neighbor_iface = is_interface_available(curr->sr, dest_interface);
            if (neighbor_iface == NULL)
            {
                struct sr_rt *routtable = get_interface(ip_addr, curr->sr, src_interface);
                if (routtable == NULL)
                {
                    neighbor_iface = check_interface(curr->sr, "eth0");
                }
            }
            struct arp_cache *temp = NULL;
            struct arp_cache *arp_entry = curr_cache;
            while (arp_entry)
            {
                if (arp_entry->ip == ip_addr)
                {
                    temp = arp_entry;
                    break;
                }
                arp_entry = arp_entry->next;
            }
            if (temp != NULL)
            {
                memcpy(etheader->ether_shost, neighbor_iface->addr, ETHER_ADDR_LEN);
                memcpy(etheader->ether_dhost, temp->mac, ETHER_ADDR_LEN);
                sr_send_packet(curr->sr, curr->packet, curr->length, neighbor_iface->name);
            }
        }
        curr = curr->next;
    }
}

/**
 * Method : is_interface_available
 * 
 * Check if interface is up and neighboring.
*/
struct sr_if *is_interface_available(struct sr_instance *sr, char *interface)
{
    /* Check if the interface up and not neighborId=1 */
    struct sr_if *current_interface = sr->if_list;

    while (current_interface)
    {
        if (strcmp(current_interface->name, interface) == 0 && current_interface->neighborId != 1)
        {
            return current_interface;
        }
        current_interface = current_interface->next;
    }
    return NULL;
}

/**
 * Method: get_interface
 * 
 * Find matching interface and return it
*/
struct sr_rt *get_interface(uint32_t dest, struct sr_instance *sr, char *src_iface)
{
    bool interface_matched = false;
    struct sr_rt *routing_table = sr->routing_table;

    while (routing_table)
    {
        struct sr_if *iface = is_interface_available(sr, routing_table->interface);

        if ((dest & routing_table->mask.s_addr) == ((routing_table->dest.s_addr) & (routing_table->mask.s_addr)) && routing_table->dest.s_addr != 0)
        {
            if (iface)
            {
                return routing_table;
            }
        }
        if (!iface)
        {
            interface_matched = true;
        }
        routing_table = routing_table->next;
    }

    if (!interface_matched)
    {
        return NULL;
    }
    routing_table = sr->routing_table;
    while (routing_table)
    {
        if (routing_table->dest.s_addr != 0 && is_interface_available(sr, routing_table->interface))
        {
            if (routing_table->gw.s_addr != 0 && strcmp(src_iface, routing_table->interface) != 0)
            {
                return routing_table;
            }
        }
        routing_table = routing_table->next;
    }
    return NULL;
}

/*
 **************************************************************************
 Function: baseFlow
 With the help of this function we set a default route
 ***************************************************************************
 */
void baseFlow(uint8_t *packet, struct sr_instance *sr, int len)
{
    struct sr_rt *rtable = sr->routing_table;
    struct sr_ethernet_hdr *eth_hdr = (struct sr_ethernet_hdr *)packet;
    struct ip *ip = (struct ip *)(packet + sizeof(struct sr_ethernet_hdr));
    char interface[5];
    if (ip->ip_v != 4)
    {
        return;
    }

    while (rtable)
    {
        if (strcmp(inet_ntoa(rtable->dest), "0.0.0.0") == 0)
        {
            int i;
            for (i = 0; i < 4; i++)
            {
                interface[i] = rtable->interface[i];
            }
            interface[4] = '\0';
            break;
        }
        rtable = rtable->next;
    }
    if (rtable == NULL)
    {
        return;
    }

    if (check_buffer(rtable->gw.s_addr) == true)
    {
        struct arp_cache *arp_entry = find_entry_from_cache(rtable->gw.s_addr);
        if (arp_entry)
        {
            memcpy(eth_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
        }
    }
    else
    {
        insert_to_cached_packets(packet, eth_hdr, len, sr, interface);
        send_arp_request(sr, rtable->gw.s_addr, interface, len);
    }

    struct sr_if *interf = check_interface(sr, interface);
    memcpy(eth_hdr->ether_shost, interf->addr, ETHER_ADDR_LEN);

    if (ip->ip_ttl == 0)
        return;
    else
        ip->ip_ttl = ip->ip_ttl - 1;
    ip->ip_sum = 0;
    ip->ip_sum = checkSum(((uint8_t *)(ip)), sizeof(struct ip));
    sr_send_packet(sr, packet, len, interface);
}

/*
 **************************************************************************
 Function: send_ip_packet
 With the help of this function we send IP
 ***************************************************************************
 */
void send_ip_packet(uint8_t *packet, uint32_t address, char *interface, int len, struct sr_instance *sr)
{
    struct sr_ethernet_hdr *eth_hdr = (struct sr_ethernet_hdr *)packet;
    struct ip *ip = (struct ip *)(packet + sizeof(struct sr_ethernet_hdr));
    unsigned char mac[ETHER_ADDR_LEN];

    if (ip->ip_v != 4)
        return;

    struct arp_cache *arp_entry = find_entry_from_cache(address);
    if (arp_entry)
    {
        memcpy(mac, arp_entry->mac, ETHER_ADDR_LEN);
    }

    struct sr_if *sr_interfc = NULL;
    if (interface)
    {
        sr_interfc = check_interface(sr, interface);
    }
    memcpy(eth_hdr->ether_dhost, mac, ETHER_ADDR_LEN);

    if (sr_interfc == NULL)
    {
        return;
    }
    memcpy(eth_hdr->ether_shost, sr_interfc->addr, ETHER_ADDR_LEN);

    if (ip->ip_ttl == 0)
    {
        return;
    }
    else
    {
        ip->ip_ttl = ip->ip_ttl - 1;
    }

    ip->ip_sum = 0;
    ip->ip_sum = checkSum(((uint8_t *)(ip)), sizeof(struct ip));

    sr_send_packet(sr, packet, len, interface);
}

/*
 **************************************************************************
 Function: handle_IP_packet
 With the help of this function we handle the IP packet
 ***************************************************************************
 */
void handle_IP_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface, char *src_interface)
{
    struct ip *ip = ((struct ip *)(packet + sizeof(struct sr_ethernet_hdr)));
    struct sr_rt *rtable = get_interface(ip->ip_dst.s_addr, sr, src_interface);

    if (check_buffer(ip->ip_dst.s_addr) == true)
    {
        send_ip_packet(packet, ip->ip_dst.s_addr, interface, len, sr);
    }
    else if (rtable && rtable->dest.s_addr != 0 && check_buffer(rtable->gw.s_addr) == true)
    {
        send_ip_packet(packet, rtable->gw.s_addr, interface, len, sr);
    }
    else
    {
        struct sr_ethernet_hdr *ethHeaddr = (struct sr_ethernet_hdr *)packet;
        insert_to_cached_packets(packet, ethHeaddr, len, sr, interface);
        struct sr_rt *routable = get_interface(ip->ip_dst.s_addr, sr, src_interface);
        if (routable->gw.s_addr != 0)
        {
            send_arp_request(sr, routable->gw.s_addr, routable->interface, len);
        }
        else
        {
            send_arp_request(sr, ip->ip_dst.s_addr, routable->interface, len);
        }
    }
}

/**
 * Method: send_arp_request
 * Scope:  Global
 *
 * This function is responsible for sending an ARP request packet on the specified
 * network interface to resolve the MAC address corresponding to a given target IP address.
 * It constructs an ARP request packet with the appropriate fields filled in, such as Ethernet
 * and ARP headers. The Ethernet header contains the source MAC address of the sending interface
 * and a broadcast destination MAC address. The ARP header specifies the ARP operation as a request,
 * the sender's IP and MAC addresses, and the target IP address with an unknown target MAC address.
 * The constructed ARP request packet is then broadcasted on the network to request the MAC address
 * associated with the target IP.
 */
void send_arp_request(struct sr_instance *sr, uint32_t dest, char *interface, int len)
{
    uint8_t *packet = malloc(len);
    struct sr_if *sr_interfc = sr->if_list;
    struct sr_arphdr *arp_hdr = (struct sr_arphdr *)(packet + sizeof(struct sr_ethernet_hdr));

    if (check_buffer(dest))
    {
        return;
    }

    arp_hdr->ar_hrd = ntohs(1);
    arp_hdr->ar_op = ntohs(ARP_REQUEST);
    arp_hdr->ar_pro = ntohs(ETHERTYPE_IP);
    arp_hdr->ar_pln = IP_ADDR_LEN;
    arp_hdr->ar_hln = ETHER_ADDR_LEN;
    arp_hdr->ar_tip = dest;

    struct sr_ethernet_hdr *eth_hdr = (struct sr_ethernet_hdr *)packet;

    eth_hdr->ether_type = htons(ETHERTYPE_ARP);

    uint8_t broadcast[ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    memcpy(eth_hdr->ether_dhost, broadcast, ETHER_ADDR_LEN);

    struct sr_if *interf_entry = sr_interfc;
    while (interf_entry)
    {
        if (strcmp(interf_entry->name, interface) == 0)
        {
            memcpy(arp_hdr->ar_sha, interf_entry->addr, ETHER_ADDR_LEN);
            memcpy(eth_hdr->ether_shost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
            arp_hdr->ar_sip = interf_entry->ip;
            sr_send_packet(sr, (uint8_t *)eth_hdr, len, interf_entry->name);
            return;
        }
        interf_entry = interf_entry->next;
    }
}

/**
 * Method: handle_arp_reply
 * Scope:  Global
 *
 * Handle received ARP reply packet.
 *
 * When an ARP reply packet is received in response to an ARP request, this function
 * parses the ARP reply packet and updates the ARP cache with the sender's MAC address.
 * It then checks if there are any pending packets waiting for this ARP reply and sends them.
 *
 */
void handle_arp_reply(struct sr_instance *sr, uint8_t *packet, char *interface)
{
    struct sr_if *iface = sr_get_interface(sr, interface);
    struct sr_arphdr *headerarp = ((struct sr_arphdr *)(packet + sizeof(struct sr_ethernet_hdr)));

    insert_to_cache(headerarp->ar_sip, headerarp->ar_sha);

    send_arp_cached_packets(headerarp->ar_sip, iface->name, interface);
}

/**
 * Method: handle_arp_request(struct sr_instance *sr, struct sr_arphdr *hdr, char *interface, int ips_same)
 * Scope:  Global
 *
 * This function is responsible for processing ARP request packets. It first checks if
 * the IP address in the received ARP request packet matches the IP address of the router's
 * interface. If they match, it constructs an ARP reply packet with the appropriate fields
 * filled in (including MAC addresses, ARP op code, and IP addresses) and sends the reply.
 * If the IP addresses do not match, the packet is dropped.
 *
 */
void handle_arp_request(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *inter, struct sr_ethernet_hdr *header)
{
    struct sr_arphdr *arp_hdr = ((struct sr_arphdr *)(packet + sizeof(struct sr_ethernet_hdr)));

    insert_to_cache(arp_hdr->ar_sip, arp_hdr->ar_sha);

    memcpy(header->ether_dhost, header->ether_shost, ETHER_ADDR_LEN);
    memcpy(header->ether_shost, inter->addr, ETHER_ADDR_LEN);
    memcpy(arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
    memcpy(arp_hdr->ar_sha, inter->addr, ETHER_ADDR_LEN);

    arp_hdr->ar_op = htons(ARP_REPLY);
    arp_hdr->ar_hrd = htons(ARPHDR_ETHER);
    arp_hdr->ar_pro = htons(ETHERTYPE_IP);
    arp_hdr->ar_hln = ETHER_ADDR_LEN;
    arp_hdr->ar_pln = IP_ADDR_LEN;

    uint32_t tmp = arp_hdr->ar_sip;
    arp_hdr->ar_sip = arp_hdr->ar_tip;
    arp_hdr->ar_tip = tmp;

    sr_send_packet(sr, ((uint8_t *)(packet)), len, inter->name);
}

/**
 * Method: handle_arp_packet
 * Scope:  Global
 *
 * Handle incoming ARP request/reply packet.
 *
 * Handle incoming ARP request/reply packet. This function receives an ARP packet, determines its
 * operation type (Request or Reply), and invokes the appropriate handler (handle_arp_request or handle_arp_reply)
 * based on the type. It plays a central role in processing ARP packets within the router.
 *
 */
void handle_arp_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *inter, struct sr_ethernet_hdr *header, char *interface)
{
    struct sr_arphdr *headerarp = ((struct sr_arphdr *)(packet + sizeof(struct sr_ethernet_hdr)));

    if (htons(headerarp->ar_op) == ARP_REQUEST)
    {
        printf("Received ARP Request.\n");
        handle_arp_request(sr, packet, len, inter, header);
    }

    else if (htons(headerarp->ar_op) == ARP_REPLY)
    {
        printf("Received ARP Reply.\n");
        handle_arp_reply(sr, packet, interface);
    }
}