#include <iostream>
#include "frame.h"

void usage()
{
	std::cout<<"syntax : tcp-block <interface> <pattern>"<<std::endl;
	std::cout<<"sample : tcp-block wlan0 \"Host: test.gilgil.net\""<<std::endl;
}

int main(int argc,char* argv[])
{
	if(argc!=3)
	{
		usage();
		return -1;
	}
	char *interface=argv[1];
	char *pattern=argv[2];
	
}
