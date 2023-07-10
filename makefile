LDLIBS=-lpcap

all: tcp-block

main.o: main.cpp frame.h

frame.o: frame.cpp frame.h addr.h

addr.o: addr.cpp addr.h

tcp-block: main.o frame.o addr.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f tcp-block *.o
