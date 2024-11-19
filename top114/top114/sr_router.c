/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing. 11
 * 90904102
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_pwospf.h"
#include "sr_protocol.h"
#include "pwospf_protocol.h"
#include "sr_arpcache.h"
#include "sr_helper.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/
void sr_init(struct sr_instance *sr)
{
  /* REQUIRES */
  assert(sr);

  /* Add initialization code here! */
  // pthread_attr_init(&(sr->attr));
  // pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
  // pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
  // pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
  // pthread_t thread;

  /* moved to sr_vns_comm.c, after HWINFO has been received and processed */
  /* pwospf_init(sr); */
} /* -- sr_init -- */

uint16_t ethertype(uint8_t *buf)
{
  struct sr_ethernet_hdr *ehdr = (struct sr_ethernet_hdr *)buf;
  return ntohs(ehdr->ether_type);
}

uint8_t ip_protocol(uint8_t *buf)
{
  struct ip *iphdr = (struct ip *)(buf);
  return iphdr->ip_p;
}

/* Prints out formatted Ethernet address, e.g. 00:11:22:33:44:55 */
void print_addr_eth(uint8_t *addr)
{
  int pos = 0;
  uint8_t cur;
  for (; pos < ETHER_ADDR_LEN; pos++)
  {
    cur = addr[pos];
    if (pos > 0)
      fprintf(stderr, ":");
    fprintf(stderr, "%02X", cur);
  }
  fprintf(stderr, "\n");
}

/* Prints out IP address as a string from in_addr */
void print_addr_ip(struct in_addr address)
{
  char buf[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &address, buf, 100) == NULL)
    fprintf(stderr, "inet_ntop error on address conversion\n");
  else
    fprintf(stderr, "%s\n", buf);
}

/* Prints out IP address from integer value */
void print_addr_ip_int(uint32_t ip)
{
  uint32_t curOctet = ip >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 8) >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 16) >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 24) >> 24;
  fprintf(stderr, "%d\n", curOctet);
}

/* Prints out fields in Ethernet header. */
void print_hdr_eth(uint8_t *buf)
{
  struct sr_ethernet_hdr *ehdr = (struct sr_ethernet_hdr *)buf;
  fprintf(stderr, "ETHERNET header:\n");
  fprintf(stderr, "\tdestination: ");
  print_addr_eth(ehdr->ether_dhost);
  fprintf(stderr, "\tsource: ");
  print_addr_eth(ehdr->ether_shost);
  fprintf(stderr, "\ttype: %d\n", ntohs(ehdr->ether_type));
}

/* Prints out fields in IP header. */
void print_hdr_ip(uint8_t *buf)
{
  struct ip *iphdr = (struct ip *)(buf);
  fprintf(stderr, "IP header:\n");
  fprintf(stderr, "\tversion: %d\n", iphdr->ip_v);
  fprintf(stderr, "\theader length: %d\n", iphdr->ip_hl);
  fprintf(stderr, "\ttype of service: %d\n", iphdr->ip_tos);
  fprintf(stderr, "\tlength: %d\n", ntohs(iphdr->ip_len));
  fprintf(stderr, "\tid: %d\n", ntohs(iphdr->ip_id));

  if (ntohs(iphdr->ip_off) & IP_DF)
    fprintf(stderr, "\tfragment flag: DF\n");
  else if (ntohs(iphdr->ip_off) & IP_MF)
    fprintf(stderr, "\tfragment flag: MF\n");
  else if (ntohs(iphdr->ip_off) & IP_RF)
    fprintf(stderr, "\tfragment flag: R\n");

  fprintf(stderr, "\tfragment offset: %d\n", ntohs(iphdr->ip_off) & IP_OFFMASK);
  fprintf(stderr, "\tTTL: %d\n", iphdr->ip_ttl);
  fprintf(stderr, "\tprotocol: %d\n", iphdr->ip_p);

  /*Keep checksum in NBO*/
  fprintf(stderr, "\tchecksum: %d\n", iphdr->ip_sum);

  fprintf(stderr, "\tsource: ");
  print_addr_ip_int(ntohl(iphdr->ip_src.s_addr));

  fprintf(stderr, "\tdestination: ");
  print_addr_ip_int(ntohl(iphdr->ip_dst.s_addr));
}

/* Prints out sr_icmp_hdr header fields */
void print_hdr_icmp(uint8_t *buf)
{
  struct sr_icmp_hdr *icmp_hdr = (struct sr_icmp_hdr *)(buf);
  fprintf(stderr, "ICMP header:\n");
  fprintf(stderr, "\ttype: %d\n", icmp_hdr->icmp_type);
  fprintf(stderr, "\tcode: %d\n", icmp_hdr->icmp_code);
  /* Keep checksum in NBO */
  fprintf(stderr, "\tchecksum: %d\n", icmp_hdr->icmp_sum);
}

/* Prints out fields in ARP header */
void print_hdr_arp(uint8_t *buf)
{
  struct sr_arphdr *arp_hdr = (struct sr_arphdr *)(buf);
  fprintf(stderr, "ARP header\n");
  fprintf(stderr, "\thardware type: %d\n", ntohs(arp_hdr->ar_hrd));
  fprintf(stderr, "\tprotocol type: %d\n", ntohs(arp_hdr->ar_pro));
  fprintf(stderr, "\thardware address length: %d\n", arp_hdr->ar_hln);
  fprintf(stderr, "\tprotocol address length: %d\n", arp_hdr->ar_pln);
  fprintf(stderr, "\topcode: %d\n", ntohs(arp_hdr->ar_op));

  fprintf(stderr, "\tsender hardware address: ");
  print_addr_eth(arp_hdr->ar_sha);
  fprintf(stderr, "\tsender ip address: ");
  print_addr_ip_int(ntohl(arp_hdr->ar_sip));

  fprintf(stderr, "\ttarget hardware address: ");
  print_addr_eth(arp_hdr->ar_tha);
  fprintf(stderr, "\ttarget ip address: ");
  print_addr_ip_int(ntohl(arp_hdr->ar_tip));
}

void print_hdr_ospf(uint8_t *buf)
{
  struct ospfv2_hdr *ospf_hdr = (struct ospfv2_hdr *)(buf);
  fprintf(stderr, "OSPF header:\n");
  fprintf(stderr, "\tversion: %d\n", ospf_hdr->version);
  fprintf(stderr, "\ttype: %d\n", ospf_hdr->type);
  fprintf(stderr, "\tlength: %d\n", ntohs(ospf_hdr->len));
  fprintf(stderr, "\trouter ID: ");
  print_addr_ip_int(ntohl(ospf_hdr->rid));
  fprintf(stderr, "\tarea ID: ");
  print_addr_ip_int(ntohl(ospf_hdr->aid));
  fprintf(stderr, "\tchecksum: %d\n", ntohs(ospf_hdr->csum));
  fprintf(stderr, "\tauthentication type: %d\n", ntohs(ospf_hdr->autype));
  fprintf(stderr, "\tauthentication data: %llu\n", ospf_hdr->audata);

  if (ospf_hdr->type == OSPF_TYPE_HELLO)
  {
    struct ospfv2_hello_hdr *hello_hdr = (struct ospfv2_hello_hdr *)(buf + sizeof(struct ospfv2_hdr));
    fprintf(stderr, "OSPF Hello header:\n");
    fprintf(stderr, "\tnetmask: ");
    print_addr_ip_int(ntohl(hello_hdr->nmask));
    fprintf(stderr, "\thello interval: %d\n", ntohs(hello_hdr->helloint));
  }
  else
  {
    struct ospfv2_lsu_hdr *lsu_hdr = (struct ospfv2_lsu_hdr *)(buf + sizeof(struct ospfv2_hdr));
    fprintf(stderr, "OSPF LSU header:\n");
    fprintf(stderr, "\tsequence number: %d\n", ntohs(lsu_hdr->seq));
    fprintf(stderr, "\tunused: %d\n", lsu_hdr->unused);
    fprintf(stderr, "\tttl: %d\n", lsu_hdr->ttl);
    fprintf(stderr, "\tnumber of advertisements: %d\n", ntohl(lsu_hdr->num_adv));

    struct ospfv2_lsu *lsu = (struct ospfv2_lsu *)(buf + sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_lsu_hdr));
    int i;
    for (i = 0; i < ntohl(lsu_hdr->num_adv); i++)
    {
      fprintf(stderr, "\tAdvertisement %d:\n", i + 1);
      fprintf(stderr, "\t\tsubnet: ");
      print_addr_ip_int(ntohl(lsu[i].subnet));
      fprintf(stderr, "\t\tmask: ");
      print_addr_ip_int(ntohl(lsu[i].mask));
      fprintf(stderr, "\t\trouter ID: ");
      print_addr_ip_int(ntohl(lsu[i].rid));
    }
  }
}

/* Prints out all possible headers, starting from Ethernet */
void print_hdrs(uint8_t *buf, uint32_t length)
{
  /* Ethernet */
  int minlength = sizeof(struct sr_ethernet_hdr);
  if (length < minlength)
  {
    fprintf(stderr, "Failed to print ETHERNET header, insufficient length\n");
    return;
  }

  uint16_t ethtype = ethertype(buf);
  print_hdr_eth(buf);

  if (ethtype == 0x0800)
  { /* IP */
    minlength += sizeof(struct ip);
    if (length < minlength)
    {
      fprintf(stderr, "Failed to print IP header, insufficient length\n");
      return;
    }

    print_hdr_ip(buf + sizeof(struct sr_ethernet_hdr));
    uint8_t ip_proto = ip_protocol(buf + sizeof(struct sr_ethernet_hdr));

    if (ip_proto == 0x0001)
    { /* sr_icmp_hdr */
      minlength += sizeof(struct sr_icmp_hdr);
      if (length < minlength)
        fprintf(stderr, "Failed to print ICMP header, insufficient length\n");
      else
        print_hdr_icmp(buf + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
    }
    else if (ip_proto == 0x59)
    { /* OSPF */
      minlength += sizeof(struct ospfv2_hdr);
      if (length < minlength)
      {
        fprintf(stderr, "Failed to print OSPF header, insufficient length\n");
      }
      else
      {
        print_hdr_ospf(buf + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
      }
    }
  }
  else if (ethtype == 0x0806)
  { /* ARP */
    minlength += sizeof(struct sr_arphdr);
    if (length < minlength)
      fprintf(stderr, "Failed to print ARP header, insufficient length\n");
    else
      print_hdr_arp(buf + sizeof(struct sr_ethernet_hdr));
  }
  else
  {
    fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
  }
}

/*---------------------------------------------------------------------
 * Method: sr_handle_OSPF_packet
 * In this method we handle the PWOSPF packet
 *---------------------------------------------------------------------*/
void sr_handle_OSPF_packet(struct sr_instance *sr, uint8_t *packet, char *interface)
{
  struct sr_if *interfc = sr_get_interface(sr, interface);
  struct ospfv2_hdr *ospf_hdr = (struct ospfv2_hdr *)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));

  /* if header type is of hello, then we handle it as a hello packet */
  if (ospf_hdr->type == OSPF_TYPE_HELLO)
  {
    printf("\n Hello Packet Receieved....\n");
    print_hdrs(packet, sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_hello_hdr));
    hello_packet_handler(sr, packet, interfc);
    return;
  }
  /* if header type is of lsu, then we handle it as a lsu packet */
  else if (ospf_hdr->type == OSPF_TYPE_LSU)
  {
    printf("\n LSU Packet receieved....\n");
    print_hdrs(packet, sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_lsu_hdr));
    lsu_packet_handler(sr, packet, interfc);
    return;
  }
}

/*---------------------------------------------------------------------
 * Method: sr_handle_icmp_packet
 *
 * Handle received ICMP packet.
 *---------------------------------------------------------------------*/
void sr_handle_icmp_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *inter, struct sr_ethernet_hdr *header, char *interface)
{
  struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct sr_ethernet_hdr));
  struct sr_icmp_hdr *icmp_hdr = (struct sr_icmp_hdr *)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
  uint32_t ip_src = ip_hdr->ip_src.s_addr;
  uint32_t ip_dst = ip_hdr->ip_dst.s_addr;

  int length = len - sizeof(struct sr_ethernet_hdr) - sizeof(struct ip);
  if (!(icmp_hdr->icmp_type == 8 && ip_hdr->ip_ttl > 1))
  {
    return;
  }
  else
  {
    header->ether_type = htons(ETHERTYPE_IP);
    ip_hdr->ip_src.s_addr = ip_dst;
    ip_hdr->ip_dst.s_addr = ip_src;
    icmp_hdr->icmp_type = 0;

    uint8_t temp[ETHER_ADDR_LEN];
    memcpy(temp, header->ether_dhost, ETHER_ADDR_LEN);
    memcpy(header->ether_dhost, header->ether_shost, ETHER_ADDR_LEN);
    memcpy(header->ether_shost, temp, ETHER_ADDR_LEN);

    icmp_hdr->icmp_sum = 0;
    icmp_hdr->icmp_sum = checkSum((uint8_t *)packet + sizeof(struct sr_ethernet_hdr) + ip_hdr->ip_hl * 4, len - sizeof(struct sr_ethernet_hdr) - sizeof(struct ip));
    sr_send_packet(sr, packet, len, interface);
  }
}

/**
 * Method: sr_handle_IP_packet(struct sr_instance *sr, uint8_t *packet, char *interface, unsigned int length)
 * Scope:  Global
 *
 * Handle incoming IP packet, performing forwarding or processing based on the destination IP address.
 *
 * This function processes incoming IP packets, either forwarding them to the appropriate next hop or handling them
 * locally if the destination IP matches one of the router's interfaces. It decrements the Time-to-Live (TTL) field,
 * checks and updates the checksum, and makes forwarding decisions based on the routing table and ARP cache.
 *
 */
void sr_handle_IP_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface)
{
  struct sr_ethernet_hdr *header = (struct sr_ethernet_hdr *)packet;

  struct sr_if *inter = sr_get_interface(sr, interface);
  struct ip *ip_header = ((struct ip *)(packet + sizeof(struct sr_ethernet_hdr)));
  if (ip_header->ip_p == IP_PROTO_OSPFv2)
  {
    printf("\nProcessing OSPF Packet.... \n");
    sr_handle_OSPF_packet(sr, packet, interface);
    return;
  }
  if (ip_header->ip_p == 1)
  {
    struct sr_icmp_hdr *icmp_hdr = (struct sr_icmp_hdr *)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
    struct sr_if *iface = sr->if_list;
    if ((icmp_hdr->icmp_type == 3) && (icmp_hdr->icmp_code == 3))
    {
      baseFlow(packet, sr, len);
      return;
    }
    uint32_t dest_ipaddress = ip_header->ip_dst.s_addr;

    while (iface)
    {
      if (iface->ip == dest_ipaddress)
      {
        printf("\n Processing ICMP packet....\n");
        sr_handle_icmp_packet(sr, packet, len, inter, header, interface);
        return;
      }
      iface = iface->next;
    }
  }

  struct sr_rt *interfc = get_interface(ip_header->ip_dst.s_addr, sr, interface);
  if (interfc == NULL)
  {
    baseFlow(packet, sr, len);
  }
  else
  {
    handle_IP_packet(sr, packet, len, interfc->interface, interface);
  }
}

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/
void sr_handlepacket(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n", len);

  struct sr_if *inter = sr_get_interface(sr, interface);
  struct sr_ethernet_hdr *eth_hdr = (struct sr_ethernet_hdr *)packet;

  if (htons(eth_hdr->ether_type) == ETHERTYPE_ARP)
  {
    // handle ARP request or ARP reply packet
    printf("ARP packet received...\n");
    handle_arp_packet(sr, packet, len, inter, eth_hdr, interface);
  }
  else if (htons(eth_hdr->ether_type) == ETHERTYPE_IP)
  {
    printf("\nProcessing IP Packet....\n");
    sr_handle_IP_packet(sr, packet, len, interface);
  }
}