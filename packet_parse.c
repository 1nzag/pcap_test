#include <stdio.h>
#include "packet_parse.h"

void parse_ethernet(struct ether_header* eth_header)
{
	int i;
	uint8_t addr;
	printf("* ETHERNET INFOMATION\n");
	printf("SOURCE MAC: ");
	for(i = 0; i < 6; i++)
	{
		addr = (char)(eth_header->ether_shost[i]);
		printf("%02x",addr);
		if(i == 5)
		{
			printf("\n");
			break;
		}
		printf(":");
	}
	printf("DESTINATION: ");
	for(i = 0; i<6; i++)
	{
		addr = (char)(eth_header->ether_dhost[i]);
		printf("%02x",addr);
		if(i == 5)
		{
			printf("\n");
			break;
		}
		printf(":");
	}
}

void parse_ip(struct ip* ip_header)
{
	int i;
	uint32_t addr;
	char src_addr[INET_ADDRSTRLEN] = {0,};
	char dest_addr[INET_ADDRSTRLEN] = {0,};

	printf("* IP INFOMATION\n");
	addr = (int)(ip_header->ip_src).s_addr;
	inet_ntop(AF_INET,&(ip_header->ip_src).s_addr,src_addr,sizeof(src_addr));
	inet_ntop(AF_INET,&(ip_header->ip_dst).s_addr,dest_addr,sizeof(dest_addr));
	printf("SOURCE IP: %s\n",src_addr);
	printf("DESTINATION IP: %s\n",dest_addr);
}

void parse_tcp(struct tcphdr *tcp_header)
{
	printf("* TCP INFOMATION\n");
	printf("SOURCE PORT: %d\n",ntohs(tcp_header->source));
	printf("DESTINATION PORT: %d\n",ntohs(tcp_header->dest));
}
