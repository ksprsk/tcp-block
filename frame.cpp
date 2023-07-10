#include "frame.h"

bool check_pattern(const uint8_t *data,size_t datalen,const uint8_t *pattern,size_t patternlen)
{
	for(int i=0;i<=datalen-patternlen;i++)
	{
		if(!memcmp(data+i,pattern,patternlen))return true;
	}
	return false;
}
