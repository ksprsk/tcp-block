#pragma once

#include <cstring>
#include <cstdint>

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
