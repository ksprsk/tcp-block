#include <iostream>
#include <unistd.h> 
#include "frame.h"

char errbuf[PCAP_ERRBUF_SIZE];

void usage()
{
	std::cout<<"syntax : tcp-block <interface> <pattern>"<<std::endl;
	std::cout<<"sample : tcp-block wlan0 \"Host: test.gilgil.net\""<<std::endl;
}

size_t is_forbidden(const uint8_t* packet_data,const uint8_t *pattern,size_t patternlen)
{
	size_t idx=0;
	//is IPv4?
	if(((EthHdr*)packet_data)->type()!=EthHdr::Ip4)return 0;
	idx+=sizeof(EthHdr);
	//is TCP?
	if(((IPv4Hdr*)(packet_data+idx))->protocol()!=IPv4Hdr::TCP)return 0;
	size_t datalen=sizeof(EthHdr)+((IPv4Hdr*)(packet_data+idx))->packet_len();
	idx+=((IPv4Hdr*)(packet_data+idx))->IHL();
	if(idx==datalen)return 0;
	//get port and check
	uint16_t src_port=((TCPHdr*)(packet_data+idx))->src_port();
	uint16_t dst_port=((TCPHdr*)(packet_data+idx))->dst_port();
	bool isforbidden;
	idx+=((TCPHdr*)(packet_data+idx))->hdr_len();
	if(idx==datalen)return 0;
	//check port
	if(dst_port==TCPHdr::HTTP)
	{
		size_t httphdr_len=0;
		while((idx+httphdr_len+4<=datalen)&&memcmp(packet_data+idx+httphdr_len,"\r\n\r\n",4))httphdr_len++;
		isforbidden=check_pattern(packet_data+idx,httphdr_len,pattern,patternlen);
	}
	else if(dst_port==TCPHdr::HTTPS)
	{
		isforbidden=check_pattern(packet_data+idx,datalen-idx,pattern,patternlen);
	}
	else
	{
		isforbidden=false;
	}
	if(isforbidden)return datalen;
	return 0;
}

void send_rst(int sock,const uint8_t* data,size_t datalen)
{
	uint8_t* packet_data=new uint8_t[datalen-sizeof(EthHdr)];
	memcpy(packet_data,data+sizeof(EthHdr),datalen-sizeof(EthHdr));
	IPv4_TCPHdr *ipv4_tcphdr=(IPv4_TCPHdr*)packet_data;
	
	struct sockaddr_in server_addr;
	server_addr.sin_family = AF_INET;
	server_addr.sin_port =htons(ipv4_tcphdr->tcphdr.dst_port());
	server_addr.sin_addr.s_addr= ipv4_tcphdr->ipv4hdr.dip();
	ipv4_tcphdr->ipv4hdr.total_len_=htons(sizeof(IPv4_TCPHdr));
	ipv4_tcphdr->tcphdr.flags_=0x14;
	
	
	ipv4_tcphdr->ipv4hdr.checksum_=calc_ipv4_checksum((uint8_t*)&ipv4_tcphdr->ipv4hdr);
	ipv4_tcphdr->tcphdr.checksum_=calc_tcp_checksum(&ipv4_tcphdr->ipv4hdr,(uint8_t*)&ipv4_tcphdr->tcphdr);
	
	sendto(sock,packet_data,sizeof(IPv4_TCPHdr),0,(sockaddr*)&server_addr,sizeof(server_addr));
	delete [] packet_data;
}
void send_fin(int sock,const uint8_t* data,size_t datalen)
{
	char payload[]="HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n\r\n";
	uint8_t* packet_data=new uint8_t[datalen-sizeof(EthHdr)+sizeof(payload)];
	memcpy(packet_data,data+sizeof(EthHdr),datalen-sizeof(EthHdr));
	IPv4_TCPHdr *ipv4_tcphdr=(IPv4_TCPHdr*)packet_data;
	
	struct sockaddr_in server_addr;
	server_addr.sin_family = AF_INET;
	server_addr.sin_port =htons(ipv4_tcphdr->tcphdr.src_port());
	server_addr.sin_addr.s_addr= ipv4_tcphdr->ipv4hdr.sip();
	
	ipv4_tcphdr->ipv4hdr.total_len_=htons(sizeof(IPv4_TCPHdr)+sizeof(payload));
	
	Ip tempip=ipv4_tcphdr->ipv4hdr.sip_;
	ipv4_tcphdr->ipv4hdr.sip_=ipv4_tcphdr->ipv4hdr.dip_;
	ipv4_tcphdr->ipv4hdr.dip_=tempip;
	
	uint16_t tempport=ipv4_tcphdr->tcphdr.src_port_;
	ipv4_tcphdr->tcphdr.src_port_=ipv4_tcphdr->tcphdr.dst_port_;
	ipv4_tcphdr->tcphdr.dst_port_=tempport;
	
	uint32_t tempnum=ipv4_tcphdr->tcphdr.seq_num_;
	ipv4_tcphdr->tcphdr.seq_num_=ipv4_tcphdr->tcphdr.ack_num_;
	ipv4_tcphdr->tcphdr.ack_num_=htonl(ntohl(tempnum)+datalen-sizeof(EthHdr)-sizeof(IPv4_TCPHdr));
	
	ipv4_tcphdr->tcphdr.flags_=0x11;
	memcpy(packet_data+sizeof(IPv4_TCPHdr),payload,sizeof(payload));
	
	ipv4_tcphdr->ipv4hdr.checksum_=calc_ipv4_checksum((uint8_t*)&ipv4_tcphdr->ipv4hdr);
	ipv4_tcphdr->tcphdr.checksum_=calc_tcp_checksum(&ipv4_tcphdr->ipv4hdr,(uint8_t*)&ipv4_tcphdr->tcphdr);
	
	
	sendto(sock,packet_data,sizeof(IPv4_TCPHdr)+sizeof(payload),0,(sockaddr*)&server_addr,sizeof(server_addr));
	delete [] packet_data;
}
void tcp_block(pcap_t* handle,const uint8_t* data,size_t datalen)
{
	printf("detected!\n");
	//https://www.sysnet.pe.kr/2/0/13151?pageno=9
	//actually i didn't understand yet..
	int enable = 1;
    // Step 1: Create a raw network socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0)
    {
        fprintf(stderr,"raw socket error\n");
		exit(-1);
	}
    // Step 2: Set socket option.
    int result = setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (const char*)&enable, sizeof(enable));
    if (sock < 0)
    {
        fprintf(stderr,"setsockopt error\n");
		exit(-1);
    }
	send_fin(sock,data,datalen);
	send_rst(sock,data,datalen);
	close(sock);
}

int main(int argc,const char* const argv[])
{
	if(argc!=3)
	{
		usage();
		return -1;
	}
	const char *interface=argv[1];
	const uint8_t *pattern=(const uint8_t*)argv[2];
	size_t patternlen=0;while(pattern[patternlen]){patternlen++;};
	
	pcap_t* handle=pcap_open_live(interface, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", interface, errbuf);
		return -1;
	}
	pcap_pkthdr* header;
	const uint8_t* packet_data;
	while(1)
	{
		int res = pcap_next_ex(handle, &header, (const u_char**)&packet_data);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			fprintf(stderr,"pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			exit(-1);
		}
		size_t datalen=is_forbidden(packet_data,pattern,patternlen);
		if(datalen)tcp_block(handle,packet_data,datalen);
	}
	
	
}
