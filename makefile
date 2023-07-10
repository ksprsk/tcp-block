LDLIBS=-lpcap

all: tcp-block

main.o: main.cpp ip.h #mac.h ethhdr.h arphdr.h 

ip.o: ip.h ip.cpp

mac.o : mac.h mac.cpp

#arphdr.o: mac.h ip.h arphdr.h arphdr.cpp

#ethhdr.o: mac.h ethhdr.h ethhdr.cpp

tcp-block: main.o ip.o mac.o #arphdr.o ethhdr.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f tcp-block *.o
