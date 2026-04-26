CC = gcc
CFLAGS = -O2 -g -Wall

all: main bpf.o

main: main.c tiny_ebpf.o
	$(CC) $(CFLAGS) -o $@ $^

tiny_ebpf.o: tiny_ebpf.c tiny_ebpf.h
	$(CC) $(CFLAGS) -c $<

bpf.o: bpf.c
	clang -O0 -Wall --target=bpf  -c bpf.c -o $@

clean:
	rm -v tiny_ebpf.o main
