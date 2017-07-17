#include <stdio.h>
#include "packet_parse.h"


void parse_ethernet(struct ether_header* eth_header)
{
	int i;
	unsigned char addr;
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
	unsigned int addr;
	printf("* IP INFOMATION\n");
	printf("SOURCE IP: ");
	addr = (int)(ip_header->ip_src).s_addr;
	for(i=0;i<4;i++)
	{
		printf("%d", (addr >> (8 * (3 - i))) & 0xff);
		if(i == 3) {printf("\n"); break;}
		printf(".");
	}
	printf("DESTINATION IP: ");
	addr = (int)(ip_header->ip_dst).s_addr;
	for(i=0;i<4;i++)
	{
		printf("%d", (addr >> (8 * (3 - i))) & 0xff);
		if(i == 3){printf("\n");break;}
		printf(".");
	}
}

void parse_tcp(struct tcphdr *tcp_header)
{
	printf("* TCP INFOMATION\n");
	printf("SOURCE PORT: %d\n",ntohs(tcp_header->source));
	printf("DESTINATION PORT: %d\n",ntohs(tcp_header->dest));
}
