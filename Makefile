CC=gcc 
CFLAGS+=-lpcap 

all: portscanner

clean:
	-rm -rf portscanner

tar: portscanner.tar.gz

portscanner: portScanner.c
	gcc -pthread portScanner.c -lpcap -o portScanner 

portscanner.tar.gz: Makefile portScanner.c report.txt
	tar -zcvf $@ $^
