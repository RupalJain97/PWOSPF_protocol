/************************
 * File: sr_arpcache.h
 * Date: 3rd Dec 2023
 * Authors: Rupal Jain, Sarah Hyunju Song
 * Contact: jainrupal@arizona.edu, hyunjusong@arizona.edu
 *
 * Description:
 *
 * This header file contains the constants and the functions used to implement the ARP cache.
 * It declares the data type that represents the ARP cache and its content, which is
 * the queue of ARP requests that are buffered and the entry of IP and MAC address pair that
 * has been learned from incoming ARP reply.
 * It also includes the functionality to insert entries into the cache, and periodically discards the content after 10 seconds using a thread.
 *
 *
 ************************/

#ifndef SR_ARPCACHE_H
#define SR_ARPCACHE_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdbool.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_pwospf.h"
#include "sr_protocol.h"
#include "pwospf_protocol.h"

struct arp_cache
{
    uint32_t ip;
    unsigned char mac[ETHER_ADDR_LEN];
    struct arp_cache *next;
};

struct arp_cache_packets
{
    uint8_t *packet;
    int length;
    struct sr_instance *sr;
    char *inter;
    struct arp_cache_packets *next;
} arp_cache_packets;

bool check_buffer(uint32_t ip);
struct arp_cache *find_entry_from_cache(uint32_t ip);
void insert_to_cache(uint32_t ip, unsigned char mac[ETHER_ADDR_LEN]);

void insert_to_cached_packets(uint8_t *packet, struct sr_ethernet_hdr *header, int len, struct sr_instance *sr, char *inter);
void send_arp_cached_packets(uint32_t ip_addr, char *interfaceD, char *interfaceS);

void baseFlow(uint8_t *packet, struct sr_instance *sr, int len);
struct sr_if *is_interface_available(struct sr_instance *sr, char *interface);
struct sr_rt *get_interface(uint32_t destination, struct sr_instance *sr, char *srcInterface);

void send_ip_packet(uint8_t *packet, uint32_t address, char *interface, int len, struct sr_instance *sr); 
void handle_IP_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface, char *srcInterface);

void handle_arp_request(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *inter, struct sr_ethernet_hdr *header);
void handle_arp_reply(struct sr_instance *sr, uint8_t *packet, char *interface);
void handle_arp_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *inter, struct sr_ethernet_hdr *header, char *interface);
void send_arp_request(struct sr_instance *sr, uint32_t dest, char *interface, int len);

#endif