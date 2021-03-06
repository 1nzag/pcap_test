#include "packet_parse.h"
#include <ctype.h>
void parse_packet(const u_char *packet,int length)
{
	struct ether_header *eth_header; // ethernet header
	struct ip *ip_header; //ip header
	struct tcphdr *tcp_header;//tcp header
	const u_char *crit = packet;
	int i;
	uint16_t datalen = 0;
	eth_header = (struct ether_header*)packet;
	if(ntohs(eth_header->ether_type) != 0x0800)
	{
		return;
	}//IP filter
	parse_ethernet(eth_header);
	packet += 14; // ethernet header size
	
	ip_header = (struct ip*)packet;
	if(ip_header->ip_p != 6)
	{
		return ;
	}//TCP filter
	datalen = ntohs(ip_header->ip_len) - (ntohl(ip_header->ip_hl) * 4);
	parse_ip(ip_header);
	packet += ((ip_header -> ip_hl) * 4); // ip header size
	
	tcp_header = (struct tcphdr*)packet;
	datalen -= (tcp_header -> th_off * 4);
	parse_tcp(tcp_header);
	packet += ((tcp_header -> th_off) * 4); // tcp header size
	

	printf("DATA:\n");
	printf("DATA LENGTH: %d\n",datalen);
	for(i=0;i<datalen;i++)
	{
		if(isprint((char)*(packet+i)))
		{
			printf("%c",(char)*(packet+i));
		}
		else
		{
			printf(".");
		}
	}
	printf("\n");

}




int main(int argc, char *argv[])
{
	pcap_t *handle;
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "port 80";
	bpf_u_int32 mask;
	bpf_u_int32 net;
	struct pcap_pkthdr *header;
	const u_char *packet;
	const u_char *p_data;
	int count = 0;

	if(argc != 2)
	{
		printf("Usage: ./pcap_test [device]\n");
		return 0;
	}
	
	handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000,errbuf);
	pcap_compile(handle, &fp, filter_exp, 0, net);
	pcap_setfilter(handle, &fp);
	
	while(1)
	{
		count++;
		pcap_next_ex(handle, &header, &p_data);
		printf("===============================================\n");
		printf("[%d]ST PACKET INFOMATION\n",count);
		parse_packet(p_data,header->len);
		printf("===============================================\n");
	}
	pcap_close(handle);
	return 0;
}
