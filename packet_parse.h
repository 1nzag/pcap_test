#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdint.h>



#ifndef __parse_ethernet_h__
#define __parse_ethernet_h__

void parse_ethernet(struct ether_header* eth_header);
#endif

#ifndef __parse_ip_h__
#define __parse_ip_h__

void parse_ip(struct ip* ip_header);

#endif

#ifndef __parse_tcp_h__
#define __parse_ecp_h__

void parse_tcp(struct tcphdr *tcp_header);
#endif
