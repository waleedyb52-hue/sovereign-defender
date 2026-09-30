# Sovereign Defender eBPF XDP Build Automation
# Target: Ubuntu 20.04 / 22.04 / 24.04 LTS, Debian 11/12
# Kernel: 5.4+

CLANG ?= clang
LLC ?= llc
CC ?= gcc
BPFTOOL ?= bpftool

# Linux Kernel headers and libbpf
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
CFLAGS := -O2 -g -Wall -Werror \
          -target bpf \
          -D__TARGET_ARCH_$(ARCH) \
          -I/usr/include/$(shell uname -m)-linux-gnu \
          -I/usr/include

all: xdp_drop.o

xdp_drop.o: xdp_drop.c
	@echo "[+] Compiling eBPF XDP C program to bytecode using $(CLANG)..."
	$(CLANG) $(CFLAGS) -c $< -o $@
	@echo "[✓] eBPF Object successfully compiled: $@"

clean:
	rm -f xdp_drop.o

# Attach to default interface (e.g. eth0 or enp1s0)
IFACE ?= eth0

# load / unload: what the server needs. bpftool pins the LIBBPF_PIN_BY_NAME maps at
# /sys/fs/bpf/blacklist_map and /sys/fs/bpf/stats_map, which is where the platform reads
# and writes them. (`ip link ... obj` pins under /sys/fs/bpf/xdp/globals instead, and
# `bpftool prog load ... pinmaps /sys/fs/bpf/` fails: libbpf has already pinned them.)
# MODE=xdpgeneric works on any interface; MODE=xdpdrv needs driver support.
MODE ?= xdpgeneric

load: xdp_drop.o
	@mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
	@rm -f /sys/fs/bpf/xdp_drop
	$(BPFTOOL) prog load xdp_drop.o /sys/fs/bpf/xdp_drop type xdp
	$(BPFTOOL) net attach $(MODE) pinned /sys/fs/bpf/xdp_drop dev $(IFACE) overwrite
	@$(BPFTOOL) net show dev $(IFACE)

unload:
	-$(BPFTOOL) net detach $(MODE) dev $(IFACE)
	rm -f /sys/fs/bpf/xdp_drop /sys/fs/bpf/blacklist_map /sys/fs/bpf/stats_map

# Standalone attach without the platform (maps pinned under /sys/fs/bpf/xdp/globals).
attach-generic: xdp_drop.o
	@echo "[+] Attaching xdp_drop.o to $(IFACE) in XDP Generic (SKB) mode..."
	ip link set dev $(IFACE) xdpgeneric obj xdp_drop.o sec xdp
	@echo "[✓] Attached in Generic mode."

attach-native: xdp_drop.o
	@echo "[+] Attaching xdp_drop.o to $(IFACE) in XDP Native (Driver Zero-Copy) mode..."
	ip link set dev $(IFACE) xdpdrv obj xdp_drop.o sec xdp
	@echo "[✓] Attached in Native Driver mode."

detach:
	@echo "[-] Detaching XDP programs from $(IFACE)..."
	ip link set dev $(IFACE) xdp off
	@echo "[✓] Detached."

status:
	@echo "[*] Listing active XDP hooks on network interfaces:"
	ip link show | grep -E "xdp|eth|enp"
	@echo "[*] Listing active eBPF maps:"
	$(BPFTOOL) map list 2>/dev/null || true
