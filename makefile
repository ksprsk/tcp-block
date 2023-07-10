LDLIBS=-lpcap

all: tcp-block

main.o: main.cpp frame.h

addr.o: addr.cpp addr.h

frame.o: frame.cpp frame.h addr.h

tcp-block: main.o addr.o frame.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f tcp-block *.o
