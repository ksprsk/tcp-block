#include "frame.h"

uint32_t calc_checksum(const uint8_t *data,size_t datalen)
{
	uint32_t checksum=0;
	for(int i=0;i<datalen-1;i+=2)
	{
		checksum+=ntohs(*(uint16_t*)(data+i));
	}
	
	if(datalen&1)
	{
		uint16_t last=0;
		memcpy(&last,data+datalen-1,1);
		checksum+=ntohs(last);
	}
	
	return checksum;
}
uint16_t calc_ipv4_checksum(const uint8_t *data)
{
	IPv4Hdr *ipv4hdr=(IPv4Hdr*)data;
	uint32_t checksum=calc_checksum(data,ipv4hdr->IHL());
	checksum-=htons(ipv4hdr->checksum_);
	checksum=(checksum>>16)+checksum&0xFFFF;
	return ~htons((uint16_t)checksum);
}
uint16_t calc_tcp_checksum(IPv4Hdr *ipv4hdr,const uint8_t *data)
{
	uint32_t checksum=0;
	PseudoHdr phdr;
	phdr.sip=ipv4hdr->sip();
	phdr.dip=ipv4hdr->dip();
	phdr.reserved=0;
	phdr.proto=ipv4hdr->protocol();
	phdr.len=htons(ipv4hdr->packet_len()-ipv4hdr->IHL());
	checksum+=calc_checksum((uint8_t*)&phdr,sizeof(phdr));
	checksum+=calc_checksum(data,ntohs(phdr.len));
	TCPHdr *tcphdr=(TCPHdr*)data;
	checksum-=htons(tcphdr->checksum_);
	checksum=(checksum>>16)+checksum&0xFFFF;
	return ~ntohs((uint16_t)checksum);
}

bool check_pattern(const uint8_t *data,size_t datalen,const uint8_t *pattern,size_t patternlen)
{
	if(datalen<patternlen)return false;
	for(int i=0;i<=datalen-patternlen;i++)
	{
		if(!memcmp(data+i,pattern,patternlen))return true;
	}
	return false;
}
