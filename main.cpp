#include <iostream>
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
	printf("%d %d %d\n",idx,src_port,dst_port);
	if(dst_port==TCPHdr::HTTP)
	{
		printf("http\n");
		size_t httphdr_len=0;
		while((idx+httphdr_len+4<=datalen)&&memcmp(packet_data+idx+httphdr_len,"\r\n\r\n",4))httphdr_len++;
		isforbidden=check_pattern(packet_data+idx,httphdr_len,pattern,patternlen);
	}
	else if(dst_port==TCPHdr::HTTPS)
	{
		printf("https\n");
		isforbidden=check_pattern(packet_data+idx,datalen-idx,pattern,patternlen);
	}
	else
	{
		isforbidden=false;
	}
	if(isforbidden)return datalen;
	return 0;
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
		if(datalen)printf("%d\n",datalen);
	}
	
	
}
