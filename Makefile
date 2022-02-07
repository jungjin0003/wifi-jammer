#Makefile
all: wifi-jammer

wifi-jammer:
				gcc -c iw/iwlib.c -o iwlib.o -lm
				g++ main.cpp wifi-jammer.cpp iwlib.o -o wifi-jammer -lpcap -lpthread

clean:
		rm -f iwlib.o
		rm -f wifi-jammer