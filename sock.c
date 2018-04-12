#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#define BUFFER_MAX 2048

typedef struct
{
	unsigned short src_port;
	unsigned short dst_port;
	unsigned int seq;
	unsigned int ack;
	unsigned char re:4, hl:4;
	unsigned char flags;
	unsigned short win_size;
	unsigned short checksum;
	unsigned short urp;
}tcpheader;

typedef struct
{
	unsigned short src_port;
	unsigned short dst_port;
	unsigned short len;
	unsigned short checksum;
}udpheader;

typedef struct
{
	unsigned char type;
	unsigned char code;
	unsigned short checksum;
	unsigned short id;
	unsigned short seq;
}icmpheader;





typedef struct
{
	unsigned char hl:4, v:4;
	//hl为一个字节中的低4个bits，v为一个字节中的高4个bits
	unsigned char tos;
	unsigned short len;
	unsigned short id;
	unsigned short off:13, flags:3;
	unsigned char ttl;
	unsigned char pro;
	unsigned short checksum;
	unsigned char src[4];
	unsigned char dst[4];
}ipheader;

typedef struct
{
	unsigned short hard_type;
	unsigned short pro_type;
	unsigned char hard_size;
	unsigned char pro_size;
	unsigned short op;
	unsigned char src_mac[6];
	unsigned char src_ip[4];
	unsigned char dst_mac[6];
	unsigned char dst_ip[4];
}arpheader;






typedef struct
{
	unsigned char dst_src[12];
	ipheader* ip; 
}eth_ip;

typedef struct
{
	unsigned char dst_src[12];
	arpheader* arp;
}eth_arp;








void fill_tcp(tcpheader* tcphdr, unsigned char* tcp_header)
{
	tcphdr->src_port = *((unsigned short *)(tcp_header));
	tcphdr->src_port = (tcphdr->src_port >> 8) + (tcphdr->src_port << 8);
	tcp_header += 2;
	tcphdr->dst_port = *((unsigned short *)(tcp_header));
	tcphdr->dst_port = (tcphdr->dst_port >> 8) + (tcphdr->dst_port << 8);
	tcp_header += 2;
	tcphdr->seq = *((unsigned int *)(tcp_header));
	tcphdr->seq = (tcphdr->seq << 24) + ((tcphdr->seq << 8) & 0xff0000) + ((tcphdr->seq >> 8) & 0xff00) + ((tcphdr->seq >> 24)& 0xff);
	tcp_header += 4;
	tcphdr->ack = *((unsigned int *)(tcp_header));
	tcphdr->ack = (tcphdr->ack << 24) + ((tcphdr->ack << 8) & 0xff0000) + ((tcphdr->ack >> 8) & 0xff00) + ((tcphdr->ack >> 24)& 0xff);
	tcp_header += 4;
	tcphdr->hl = *(tcp_header) >> 4;
	tcphdr->re = *(tcp_header) & 0xf;
	tcp_header += 1;
	tcphdr->flags = *(tcp_header);
	tcp_header += 1;
	tcphdr->win_size = *((unsigned short *)(tcp_header));
	tcphdr->win_size = (tcphdr->win_size >> 8) + (tcphdr->win_size << 8);
	tcp_header += 2;
	tcphdr->checksum = *((unsigned short *)(tcp_header));
	tcphdr->checksum = (tcphdr->checksum >> 8) + (tcphdr->checksum << 8);
	tcp_header += 2;
	tcphdr->urp = *((unsigned short *)(tcp_header));
	tcphdr->urp = (tcphdr->urp >> 8) + (tcphdr->urp << 8);
}

void fill_udp(udpheader* udphdr, unsigned char* udp_header)
{
	udphdr->src_port = *((unsigned short *)(udp_header));
	udphdr->src_port = (udphdr->src_port >> 8) + (udphdr->src_port << 8);
	udp_header += 2;
	udphdr->dst_port = *((unsigned short *)(udp_header));
	udphdr->dst_port = (udphdr->dst_port >> 8) + (udphdr->dst_port << 8);
	udp_header += 2;
	udphdr->len = *((unsigned short *)(udp_header));
	udphdr->len = (udphdr->len >> 8) + (udphdr->len << 8);
	udp_header += 2;
	udphdr->checksum = *((unsigned short *)(udp_header));
	udphdr->checksum = (udphdr->checksum >> 8) + (udphdr->checksum << 8);
}

void fill_icmp(icmpheader* icmphdr, unsigned char* icmp_header)
{
	icmphdr->type = *(icmp_header);
	icmp_header += 1;
	icmphdr->code = *(icmp_header);
	icmp_header += 1;
	icmphdr->checksum = *((unsigned short *)(icmp_header));
	icmphdr->checksum = (icmphdr->checksum >> 8) + (icmphdr->checksum << 8);
	icmp_header += 2;
	icmphdr->id = *((unsigned short *)(icmp_header));
	icmphdr->id = (icmphdr->id >> 8) + (icmphdr->id << 8);
	icmp_header += 2;
	icmphdr->seq = *((unsigned short *)(icmp_header));
	icmphdr->seq = (icmphdr->seq >> 8) + (icmphdr->seq << 8);
}






void fill_ip(ipheader* iphdr, unsigned char* ip_header)
{
	iphdr->v = *(ip_header) >> 4;
	iphdr->hl = *(ip_header) & 0xf;
	ip_header += 1;
	iphdr->tos = *(ip_header);
	ip_header += 1;
	iphdr->len = *((unsigned short *)(ip_header));
	iphdr->len = (iphdr->len >> 8) + (iphdr->len << 8);
	ip_header += 2;
	iphdr->id = *((unsigned short *)(ip_header));
	iphdr->id = (iphdr->id >> 8) + (iphdr->id << 8);
	ip_header += 2;
	iphdr->flags = *(ip_header) >> 5;
	iphdr->off = ((*(unsigned short *)(ip_header) & 0x1f) << 8) + *(ip_header + 1); 
	ip_header += 2;
	iphdr->ttl = *(ip_header);
	ip_header += 1;
	iphdr->pro = *(ip_header);
	ip_header += 1;
	iphdr->checksum = *((unsigned short *)(ip_header));
	iphdr->checksum = (iphdr->checksum >> 8) + (iphdr->checksum << 8);
	ip_header += 2;
	iphdr->src[0] = ip_head[0];
	iphdr->src[1] = ip_header[1];
	iphdr->src[2] = ip_header[2];
	iphdr->src[3] = ip_header[3];
	iphdr->dst[0] = ip_header[4];
	iphdr->dst[1] = ip_header[5];
	iphdr->dst[2] = ip_header[6];
	iphdr->dst[3] = ip_header[7];
}

void fill_arp(arpheader* arphdr, unsigned char* arp_header)
{
	arphdr->hard_type = *((unsigned short *)(arp_header));
	arphdr->hard_type = (arphdr->hard_type >> 8) + (arphdr->hard_type << 8);
	arp_header += 2;
	arphdr->pro_type = *((unsigned short *)(arp_header));
	arphdr->pro_type = (arphdr->pro_type >> 8) + (arphdr->pro_type << 8);
	arp_header += 2;
	arphdr->hard_size = *(arp_header);
	arp_header += 1;
	arphdr->pro_size = *(arp_header);
	arp_header += 1;
	arphdr->op = *((unsigned short *)(arp_header));
	arp_header += 2;
	arphdr->op = (arphdr->op << 8) + (arphdr->op >> 8);
	arphdr->src_mac[0] = arp_header[0];
	arphdr->src_mac[1] = arp_header[1];
	arphdr->src_mac[2] = arp_header[2];
	arphdr->src_mac[3] = arp_header[3];
	arphdr->src_mac[4] = arp_header[4];
	arphdr->src_mac[5] = arp_header[5];
	arp_header += 6;
	arphdr->src_ip[0] = arp_header[0];
	arphdr->src_ip[1] = arp_header[1];
	arphdr->src_ip[2] = arp_header[2];
	arphdr->src_ip[3] = arp_header[3];
	arp_header += 4;
	arphdr->dst_mac[0] = arp_header[0];
	arphdr->dst_mac[1] = arp_header[1];
	arphdr->dst_mac[2] = arp_header[2];
	arphdr->dst_mac[3] = arp_header[3];
	arphdr->dst_mac[4] = arp_header[4];
	arphdr->dst_mac[5] = arp_header[5];
	arp_header += 6;
	arphdr->dst_ip[0] = arp_header[0];
	arphdr->dst_ip[1] = arp_header[1];
	arphdr->dst_ip[2] = arp_header[2];
	arphdr->dst_ip[3] = arp_header[3];
}






void fill_eth_ip(eth_ip* ethip, unsigned char* eth_header)
{
	ethip->dst_src[0] = eth_header[0];
	ethip->dst_src[1] = eth_header[1];
	ethip->dst_src[2] = eth_header[2];
	ethip->dst_src[3] = eth_header[3];
	ethip->dst_src[4] = eth_header[4];
	ethip->dst_src[5] = eth_header[5];
	
	ethip->dst_src[6] = eth_header[6];
	ethip->dst_src[7] = eth_header[7];
	ethip->dst_src[8] = eth_header[8];
	ethip->dst_src[9] = eth_header[9];
	ethip->dst_src[10] = eth_header[10];
	ethip->dst_src[11] = eth_header[11];
	
	unsigned char* ip_header = eth_header + 14;
	
	ethip->ip = malloc(sizeof(ipheader));
	fill_ip(ethip->ip, ip_header);
}

void fill_eth_arp(eth_arp* etharp, unsigned char* eth_header)
{
	etharp->dst_src[0] = eth_header[0];
	etharp->dst_src[1] = eth_header[1];
	etharp->dst_src[2] = eth_header[2];
	etharp->dst_src[3] = eth_header[3];
	etharp->dst_src[4] = eth_header[4];
	etharp->dst_src[5] = eth_header[5];
	
	etharp->dst_src[6] = eth_header[6];
	etharp->dst_src[7] = eth_header[7];
	etharp->dst_src[8] = eth_header[8];
	etharp->dst_src[9] = eth_header[9];
	etharp->dst_src[10] = eth_header[10];
	etharp->dst_src[11] = eth_header[11];
	
	unsigned char* arp_head = eth_header + 14;
	
	etharp->arp = malloc(sizeof(arpheader));
	fill_arp(etharp->arp, arp_head);
}







void print_tcp(tcpheader* tcphdr)
{
	printf("TCP HEADER\n");
	printf("Source port: %u\n", tcphdr->src_port);
	printf("Destination port: %u\n", tcphdr->dst_port);
	printf("Sequence number: %u\n", tcphdr->seq);
	printf("ack: %u\n", tcphdr->ack);
	printf("Header length: %u\n", tcphdr->hl);
	printf("Flags: %c%c%c%c%c%c%c%c%c%c%c%c\n", (tcphdr->re >> 3) + '0', ((tcphdr->re << 1) >> 3) + '0', ((tcphdr->re << 2) >> 3) + '0', ((tcphdr->re << 3) >> 3) + '0', (tcphdr->flags >> 3) + '0', ((tcphdr->flags << 1) >> 3) + '0', ((tcphdr->flags << 2) >> 3) + '0', ((tcphdr->flags << 3) >> 3) + '0');
	printf("Window size: %u\n", tcphdr->win_size);
	printf("Check sum: %u\n", tcphdr->checksum);
	printf("Urp: %u\n", tcphdr->urp);
	printf("\n\n");
}

void print_udp(udpheader* udphdr)
{
	printf("UDP HEADER\n");
	printf("Source port: %u\n", udphdr->src_port);
	printf("Destination port: %u\n", udphdr->dst_port);
	printf("Length: %u\n", udphdr->len);
	printf("Check sum: %u\n", udphdr->checksum);
	printf("\n\n");
}

void print_icmp(icmpheader* icmphdr)
{
	printf("ICMP HEADER\n");
	printf("Type: ");
	switch(icmphdr->type)
	{
		case 0:
		printf("0 (Echo (ping) reply)\n"); break;
		case 8：
		printf("8 (Echo (ping) request)\n"); break;
		default:
		printf("%u (something else)\n", icmphdr->type);
	}
	printf("Code: %u\n", icmphdr->code);
	printf("Check sum: 0x%4x\n", icmphdr->checksum);
	printf("Identifier (BE): %u (0x%4x)\n", icmphdr->id, icmphdr->id);
	printf("Identifier (LE): %u (0x%4x)\n", (icmphdr->id >> 8) + (icmphdr->id << 8), (icmphdr->id >> 8) + (icmphdr->id << 8));
	printf("Sequence number (BE): %u (0x%4x)\n", icmphdr->seq, icmphdr->seq);
	printf("Sequence number (LE): %u (0x%4x)\n", (icmphdr->seq >> 8) + (icmphdr->seq << 8), (icmphdr->id >> 8) + (icmphdr->seq << 8));
	//need response time
	printf("\n\n");
}







void print_ip(ipheader* iphdr)
{
	printf("IP HEADER\n");
	printf("Version: %u\n", iphdr->v);
	printf("Header length: %u bytes\n", (iphdr->hl) * 4);
	printf("Type of service: ");
	switch(iphdr->tos)
	{
		case 0:
		printf("Routine (0)\n"); break;
		case 1:
		printf("Priority (1)\n"); break;
		case 2:
		printf("Immediate (2)\n"); break;
		case 3:
		printf("Flash (3)\n"); break;
		case 4:
		printf("Flash Override (4)\n"); break;
		case 5:
		printf("CRI/TIC/ECP (5)\n"); break;
		case 6:
		printf("Internetwork Control (6)\n"); break;
		case 7:
		printf("Network Control (7)\n"); break;
		default:
		printf("Something else (%u)\n", iphdr->tos);
	}
	printf("Total Length: %u\n", iphdr->len);
	printf("Identification: 0x%04x (%u)\n", iphdr->id, iphdr->id);
	printf("Flags: 0x%02x\n", iphdr->flags);
	printf("Fragment offset: %u\n", iphdr->off);
	printf("Time to live: %u\n", iphdr->ttl);
	printf("Protocol: ");
	switch(iphdr->pro)
	{
		case IPPROTO_ICMP:
		printf("ICMP (1)\n"); break;
		case IPPROTO_IGMP:
		printf("IGMP (2)\n"); break;
		case IPPROTO_TCP:
		printf("TCP (6)\n"); break;
		case IPPROTO_UDP:
		printf("UDP (17)\n"); break;
		case IPPROTO_IGRP:
		printf("IGRP (88)\n"); break;
		case IPPROTO_OSFP:
		printf("OSPF (89)\n"); break;
		default:
		printf("something else (%u)\n", iphdr->pro);
	}
	printf("Header checksum: 0x%4x\n", iphdr->checksum);   //need complefy
	printf("Source: %.2u:%02u:%02u:%02u\n", iphdr->src[0], iphdr->src[1], iphdr->src[2], iphdr->src[3]);
	printf("Destination: %.2u:%02u:%02u:%02u\n", iphdr->dst[0], iphdr->dst[1], iphdr->dst[2], iphdr->dst[3]);
	printf("\n\n");
}

void print_arp(arpheader* arphdr)
{
	printf("ARP HEADER\n");
	printf("Hardware type: ");
	switch(arphdr->hard_type)
	{
		case 1: 
		printf("Ethernet (1)\n"); break;
		case 6:
		printf("Toke ring network (6)\n"); break;
		default:
		printf("Something else (%u)\n", arphdr->hard_type);
	}
	printf("Protocol type: ");
	switch(arphdr->pro_type)
	{
		case 0x0800: 
		printf("IP (0x0800)\n"); break;
		case 0x0806:
		printf("ARP (0x0806)\n"); break;
		case 0x8035:
		printf("RARP (0x8035)\n"); break;
		default:
		printf("Something else (0x%x)\n", arphdr->pro_type);
	}
	printf("Hardware size: %u\n", arphdr->hard_size);
	printf("Protocol size: %u\n", arphdr->pro_size);
	printf("Opcode: ");
	switch(arphdr->op)
	{
		case 1:
		printf("request (1)\n"); break;
		case 2:
		printf("response (2)\n"); break;
		case 3:
		printf("RARP request (3)\n"); break;
		case 4:
		printf("RARP response (4)\n"); break;
		default:
		printf("something else (%u)\n", arphdr->op);
	}
	printf("Sender MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n", arphdr->src_mac[0], arphdr->src_mac[1], arphdr->src_mac[2], arphdr->src_mac[3], arphdr->src_mac[4], arphdr->src_mac[5]);
	printf("Sender IP address: %u.%u.%u.%u\n", arphdr->src_ip[0], arphdr->src_ip[1], arphdr->src_ip[2], arphdr->src_ip[3]);
	printf("Target MAC address: %.2x:%02x:%02x:%02x:%02x:%02x\n", arphdr->dst_mac[0], arphdr->dst_mac[1], arphdr->dst_mac[2], arphdr->dst_mac[3], arphdr->dst_mac[4], arphdr->dst_mac[5]);
	printf("Target IP address: %u.%u.%u.%u\n", arphdr->dst_ip[0], arphdr->dst_ip[1], arphdr->dst_ip[2], arphdr->dst_ip[3]);
	printf("\n\n");
}









void printeth(unsigned char* eth_header)
{	
	printf("ETHERNET HEADER\n");
	unsigned short* ip_arp_type;
	ip_arp_type = *(unsigned short *)(eth_header + 12);
	ip_arp_type = (ip_arp_type >> 8) + (ip_arp_type << 8);
	eth_ip* ethip = NULL;
	eth_arp* etharp = NULL;
	switch(ip_arp_type)
	{
		case 0x0800:
		ethip = malloc(sizeof(eth_ip));
		fill_eth_ip(ethip, eth_header); break;
		case 0x0806:
		etharp = malloc((sizeof(eth_arp));
		fill_eth_arp(etharp, eth_header); break;
		default:
		printf("Something else %u\n", ip_arp_type);
		return;
	}
	printf("Destination: %02x:%02x:%02x:%02x:%02x:%02x\n",eth_header[0], eth_header[1], eth_header[2], eth_header[3], eth_header[4], eth_header[5]);
	printf("Source: %02x:%02x:%02x:%02x:%02x:%02x\n",eth_header[6], eth_header[7], eth_header[8], eth_header[9], eth_header[10], eth_header[11]);
	printf("\n\n");
	if(ethip != NULL)
	{
		ipheader* iphdr = ethip->ip;
		print_ip(iphdr);
		eth_header += 14;
		eth_header += (iphdr->hl) * 4;
		switch(iphdr->pro)
		{
			case IPPROTO_ICMP:
			icmpheader* icmphdr = malloc(sizeof(icmpheader));
			fill_icmp(icmphdr,eth_header); print_icmp(icmphdr);
			free(icmphdr); break;
			case IPPROTO_TCP:
			tcpheader* tcphdr = malloc(sizeof(tcpheader));
			fill_tcp(tcphdr, eth_header); print_tcp(tcphdr);
			free(tcphdr); break;
			case IPPROTO_UDP:
			udpheader* udphdr = malloc(sizeof(udpheader));
			fill_udp(udphdr); print_udp(udphdr);
			free(udphdr); break;
			case IPPROTO_IGMP:
			printf("To fill up IGMP\n\n\n");
			break;
			case IPPROTO_IPIP:
			printf("To fill up TPTP\n\n\n");
			break;
			default:
			printf("To fill up %u\n\n\n", *eth_header); break;
		}
		free(iphdr);
		free(ethip);
	}
	else
	{
		arpheader* arphdr = etharp->arp;
		print_arp(arphdr);
		free(arphdr);
		free(etharp);
	}
	printf("\n\n\n");
}






unsigned short checksum(unsigned short* buffer, int n)
{
	unsigned int sum = 0;
	while(n > 1)
	{
		sum += *buffer;
		buffer++;
		n -= 2;
	}
	if(n == 1)
		sum += *((unsigned char *)buffer);
	sum = (sum >> 16) + (sum && 0xffff);
	sum = (sum >> 16) + (sum && 0xffff);
	sum = ~sum;
	return sum;
}




void sendicmp(int sock_fd, sockaddr* sa)
{
	static int id = 1;
	static int seq = 1;
	icmpheader icmp_header;
	icmp_header.type = 8;
	icmp_header.code = 0;
	icmp_header.checksum = 0;
	icmp_header.checksum = checksum((unsigned short *)&icmp_header, sizeof(icmp_header));
	icmp_header.id = id++;
	icmp_header.seq = seq++;
	int re = sendto(sock_fd, (char *)&icmp_header, sizeof(icmp_header), 0, sa, sizeof(sockaddr));
    if (re == SOCKET_ERROR)
        printf("Send error \n ");
    
}





int main(int argc, char* argv[])
{
	int sock_fd;
	int protocol;
	int n_read;
	A:printf("请选择操作类型: 1.收包; 2.发送icmp包\n");
	int type;
	scanf("%d", &type);
	if(type == 1)
	{
		unsigned char* eth_head;
		unsigned char buffer[BUFFER_MAX];
		if((sock_fd = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_IP|ETH_P_ARP|ETH_P_ALL)))<0)
		{
			printf("error while creating raw socket\n");
			return -1;
		}
		while(1)
		{
			n_read = recvfrom(sock_fd,buffer,BUFFER_MAX,0,NULL,NULL);
			if(n_read < 42)
			{
				printf("error while recieving message\n");
				return -1;
			}
			eth_head = buffer;
			printeth(eth_head);
		}
	}
	else if(type == 2)
	{
		printf("请输入ip地址:  ");
		unsigned char ipaddr[21];
		scanf("%s", &ipaddr);
		unsigned char ip[4];
		unsigned char tmp = 0;
		int i = 0;
		while(*ipaddr)
		{
			if(*ipaddr != '.')
				tmp = tmp * 10 + *ipaddr - '0';
			else
			{
				ip[i] = tmp;
				i++;
				tmp = 0;
			}
			ipaddr++;
		}
		int sock;
		if((sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
		{
			printf("error while creating raw socket\n");
			return -1;
		}
		sockaddr* sa = new sockaddr;
		sa->sin_family = AF_INET;
		sa->sa_data[2] = ip[0];
		sa->sa_data[3] = ip[1];
		sa->sa_data[4] = ip[2];
		sa->sa_data[5] = ip[3];
		sa->sa_data[0] = sa->sa_data[1] = sa->sa_data[6] = sa->sa_data[7] = sa->sa_data[8] = sa->sa_data[9] = sa->sa_data[10] = sa->sa_data[11] = sa->sa_data[12] = sa->sa_data[13] = 0;
		while(1)
			sendicmp(sock, sa);
	}
	else
		goto A;
}

		