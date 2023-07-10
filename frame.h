#pragma once

#include "addr.h"

#pragma pack(push, 1)

struct EthHdr final {
	Mac dmac_;
	Mac smac_;
	uint16_t type_;

	Mac dmac() { return dmac_; }
	Mac smac() { return smac_; }
	uint16_t type() { return ntohs(type_); }

	// Type(type_)
	enum: uint16_t {
		Ip4 = 0x0800,
		Arp = 0x0806,
		Ip6 = 0x86DD
	};
};

struct IPv4Hdr final {
	uint8_t ver_IHL_;
	uint8_t DSCP_ECN_;
	uint16_t total_len_;
	uint16_t identification_;
	uint16_t flags_fragoffset_;
	uint8_t TTL_;
	uint8_t protocol_;
	uint16_t checksum_;
	Ip sip_;
	Ip dip_;

	Ip sip() { return sip_; }
	Ip dip() { return dip_; }
	uint8_t protocol() { return protocol_; }
	uint8_t IHL() { return (ver_IHL_&0xf)<<2; }
	uint16_t packet_len(){ return ntohs(total_len_); }
	// protocol(protocol_)
	enum: uint8_t {
		TCP = 0x06
	};	
};

struct TCPHdr final {
	uint16_t src_port_;
	uint16_t dst_port_;
	uint32_t seq_num_;
	uint32_t ack_num_;
	uint8_t data_offset_reserved_;
	uint8_t flags_;
	uint16_t win_size_;
	uint16_t checksum_;
	uint16_t urg_ptr_;
	
	uint16_t src_port() { return ntohs(src_port_); }
	uint16_t dst_port() { return ntohs(dst_port_); }
	uint32_t seq_num() { return ntohl(seq_num_); }
	uint32_t ack_num() { return ntohl(ack_num_); }
	uint8_t hdr_len() { return (data_offset_reserved_>>4)<<2; }
	enum: uint16_t {
		HTTP = 80,
		HTTPS = 443
	};
};

#pragma pack(pop)

bool check_pattern(const uint8_t *data,size_t datalen,const uint8_t *pattern,size_t patternlen);
