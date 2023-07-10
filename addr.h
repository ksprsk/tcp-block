#pragma once

#include <pcap.h>
#include <cstring>
#include <cstdint>

struct Ip final {
	static const int SIZE = 4;
	Ip(){}
	Ip(const uint32_t r) : ip_(r) {}
	
	operator uint32_t() const { return ip_; }

	Ip& operator = (const Ip& r) { this->ip_=r.ip_; return *this; }	
	bool operator == (const Ip& r) const { return ip_ == r.ip_; }
	bool operator != (const Ip& r) const { return ip_ != r.ip_; }
	
	void clear() {
		this->ip_=0;
	}
	
	bool isLocalHost() const { // 127.*.*.*
		uint8_t prefix = (ip_ & 0xFF000000) >> 24;
		return prefix == 0x7F;
	}

	bool isBroadcast() const { // 255.255.255.255
		return ip_ == 0xFFFFFFFF;
	}

	bool isMulticast() const { // 224.0.0.0 ~ 239.255.255.255
		uint8_t prefix = (ip_ & 0xFF000000) >> 24;
		return prefix >= 0xE0 && prefix < 0xF0;
	}
protected:
	uint32_t ip_;
};


struct Mac final {
	static constexpr int SIZE = 6;

	// constructor
	Mac() {}
	Mac(const uint8_t* r) { memcpy(this->mac_, r, SIZE); }
	
	Mac& operator = (const Mac& r) { memcpy(this->mac_, r.mac_, SIZE); return *this; }
	explicit operator uint8_t*() const { return const_cast<uint8_t*>(mac_); }
	bool operator == (const Mac& r) const { return memcmp(mac_, r.mac_, SIZE) == 0; }
	bool operator != (const Mac& r) const { return memcmp(mac_, r.mac_, SIZE) != 0; }
	
	void clear() {
		*this = nullMac();
	}

	bool isNull() const {
		return *this == nullMac();
	}

	bool isBroadcast() const { // FF:FF:FF:FF:FF:FF
		return *this == broadcastMac();
	}

	bool isMulticast() const { // 01:00:5E:0*
		return mac_[0] == 0x01 && mac_[1] == 0x00 && mac_[2] == 0x5E && (mac_[3] & 0x80) == 0x00;
	}
	
	static Mac& nullMac();
	static Mac& broadcastMac();

protected:
	uint8_t mac_[SIZE];
};

