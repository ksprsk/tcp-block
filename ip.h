#pragma once

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
