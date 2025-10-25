# Makefile for packet-monitor

CLANG ?= clang
LLC ?= llc
BPFTOOL ?= bpftool
CC = gcc

BPF_SRC = src/bpf/packet_monitor.bpf.c
BPF_OBJ = packet_monitor.bpf.o
USER_SRC = src/packet_monitor.c
USER_BIN = packet_monitor

CFLAGS = -g -Wall
BPF_CFLAGS = -g -O2 -target bpf -D__TARGET_ARCH_x86
LIBS = -lbpf -lelf -lz

.PHONY: all clean bpf user install

all: bpf user

bpf: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

user: $(USER_BIN)

$(USER_BIN): $(USER_SRC)
	$(CC) $(CFLAGS) $< -o $@ $(LIBS)

generate-vmlinux:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h

install: all
	sudo cp $(USER_BIN) /usr/local/bin/
	sudo cp $(BPF_OBJ) /usr/local/lib/bpf/

clean:
	rm -f $(BPF_OBJ) $(USER_BIN)
	@echo "Cleaned build artifacts"

help:
	@echo "Available targets:"
	@echo "  all              - Build eBPF program and userspace binary"
	@echo "  bpf              - Build eBPF program only"
	@echo "  user             - Build userspace binary only"
	@echo "  generate-vmlinux - Generate vmlinux.h from kernel BTF"
	@echo "  install          - Install binaries to system"
	@echo "  clean            - Remove build artifacts"
