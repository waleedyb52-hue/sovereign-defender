# Send N UDP datagrams to the Linux host as fast as this process can, and time it.
# Used for the XDP drop test: read /sys/fs/bpf/stats_map before and after, once with the
# sender's address contained and once without.
#   python audit/udp_flood.py <linux-host-ip> 300000
# The offered rate is bounded by this sender, so it is not a measure of XDP capacity.
import socket, sys, time

target, count = sys.argv[1], int(sys.argv[2])
payload = b"\x00" * 64
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
sent = 0
t = time.perf_counter()
for _ in range(count):
    try:
        s.sendto(payload, (target, 9))
        sent += 1
    except OSError:
        pass
dt = time.perf_counter() - t
print(f"sent={sent} seconds={dt:.2f} offered_pps={sent / dt:,.0f}")
