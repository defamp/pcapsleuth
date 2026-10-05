#!/usr/bin/env python3
"""Generate samples/sample.pcap — a synthetic capture that contains one clean
example of each pattern pcapsleuth detects. Deterministic, so tests can assert.

    python3 scripts/make_sample.py
"""
import os
import socket
import dpkt

OUT = os.path.join(os.path.dirname(__file__), "..", "samples", "sample.pcap")
MAC_A = b"\x00\x0c\x29\x11\x11\x11"
MAC_B = b"\x00\x0c\x29\x22\x22\x22"
T0 = 1700000000.0


def eth_ip(src, dst, l4, proto):
    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst), p=proto, data=l4)
    ip.len = len(bytes(ip))
    return bytes(dpkt.ethernet.Ethernet(src=MAC_A, dst=MAC_B, type=dpkt.ethernet.ETH_TYPE_IP, data=ip))


def tcp(src, dst, sport, dport, flags=dpkt.tcp.TH_SYN, payload=b""):
    t = dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags, seq=1000, data=payload)
    return eth_ip(src, dst, t, dpkt.ip.IP_PROTO_TCP)


def udp_dns(src, dst, qname, qtype=dpkt.dns.DNS_A):
    q = dpkt.dns.DNS.Q(name=qname, type=qtype, cls=dpkt.dns.DNS_IN)
    dns = dpkt.dns.DNS(id=1234, qd=[q])
    u = dpkt.udp.UDP(sport=40000, dport=53, data=bytes(dns))
    u.ulen = len(bytes(u))
    return eth_ip(src, dst, u, dpkt.ip.IP_PROTO_UDP)


def client_hello(sni):
    host = sni.encode()
    sn = b"\x00" + len(host).to_bytes(2, "big") + host           # name entry
    snlist = len(sn).to_bytes(2, "big") + sn
    ext = b"\x00\x00" + len(snlist).to_bytes(2, "big") + snlist   # server_name extension
    exts = len(ext).to_bytes(2, "big") + ext
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\x00\x02\x00\x2f" + b"\x01\x00" + exts
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


def main():
    pkts = []  # (ts, bytes)

    # --- normal DNS + HTTP + TLS -----------------------------------------
    for i, d in enumerate(["google.com", "github.com", "cloudflare.com"]):
        pkts.append((T0 + i, udp_dns("10.0.0.5", "10.0.0.1", d)))
    pkts.append((T0 + 5, tcp("10.0.0.5", "140.82.112.3", 50001, 443,
                             dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK, client_hello("github.com"))))
    pkts.append((T0 + 6, tcp("10.0.0.5", "93.184.216.34", 50002, 80, dpkt.tcp.TH_PUSH,
                             b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n")))

    # --- cleartext HTTP Basic creds (admin:hunter2) ----------------------
    pkts.append((T0 + 7, tcp("10.0.0.5", "203.0.113.10", 50003, 80, dpkt.tcp.TH_PUSH,
                             b"GET /admin HTTP/1.1\r\nHost: legacy.internal\r\n"
                             b"Authorization: Basic YWRtaW46aHVudGVyMg==\r\nUser-Agent: curl/8\r\n\r\n")))

    # --- vertical port scan: 10.0.0.9 -> 25 ports ------------------------
    for i, port in enumerate(range(20, 45)):
        pkts.append((T0 + 10 + i * 0.01, tcp("10.0.0.9", "10.0.0.50", 40000 + i, port)))

    # --- C2 beaconing: every 30s x6 to 198.51.100.7:8080 -----------------
    for i in range(6):
        pkts.append((T0 + 60 + i * 30, tcp("10.0.0.5", "198.51.100.7", 51000 + i, 8080)))

    # --- DNS tunneling: 25 long high-entropy TXT queries -----------------
    import base64
    for i in range(25):
        label = base64.b32encode(os.urandom(28)).decode().rstrip("=").lower()
        pkts.append((T0 + 90 + i, udp_dns("10.0.0.5", "10.0.0.1", f"{label}.tunnel.evil-exfil.com",
                                          dpkt.dns.DNS_TXT)))

    # --- suspicious port 4444 --------------------------------------------
    pkts.append((T0 + 200, tcp("10.0.0.5", "45.77.0.9", 52000, 4444, dpkt.tcp.TH_SYN)))

    pkts.sort(key=lambda x: x[0])
    with open(os.path.abspath(OUT), "wb") as f:
        w = dpkt.pcap.Writer(f)
        for ts, buf in pkts:
            w.writepkt(buf, ts=ts)
    print(f"wrote {len(pkts)} packets -> {os.path.abspath(OUT)}")


if __name__ == "__main__":
    main()
