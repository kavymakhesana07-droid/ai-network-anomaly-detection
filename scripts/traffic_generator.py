#!/usr/bin/env python3
"""
Traffic Generator - Generates synthetic network traffic for testing ingestors.
Supports PCAP generation, live replay, and direct Kafka injection.

Usage:
  python traffic_generator.py pcap --output test.pcap --packets 10000
  python traffic_generator.py replay --pcap test.pcap --speed 10.0
  python traffic_generator.py kafka --topic raw.packets --rate 1000
"""

# ruff: noqa: S311 - random used for traffic generation, not crypto
# ruff: noqa: S104 - 0.0.0.0 used as fallback IP, not bind address
# ruff: noqa: E731 - lambda in struct.unpack format string
# ruff: noqa: TRY003 - RuntimeError with message is appropriate for missing deps
# ruff: noqa: UP031 - percent format in struct.unpack is standard idiom
# ruff: noqa: F401 - scapy imports for availability check only
# ruff: noqa: ARG001 - timestamp reserved for future use

import argparse
import asyncio
import json
import random
import struct
import time
from dataclasses import dataclass
from pathlib import Path

try:
    from aiokafka import AIOKafkaProducer

    KAFKA_AVAILABLE = True
except ImportError:
    KAFKA_AVAILABLE = False

try:
    from scapy.all import ICMP, IP, TCP, UDP, Ether, Raw, rdpcap, sendp, wrpcap

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# Common ports for realistic traffic
COMMON_PORTS = {
    "tcp": [80, 443, 22, 21, 25, 53, 110, 143, 993, 995, 3306, 5432, 6379, 8080, 8443, 27017],
    "udp": [53, 67, 68, 69, 123, 161, 162, 514, 1194, 5353],
}

# Private IP ranges
PRIVATE_RANGES = [
    ("10.0.0.0", "10.255.255.255"),
    ("172.16.0.0", "172.31.255.255"),
    ("192.168.0.0", "192.168.255.255"),
]

PUBLIC_RANGES = [
    ("1.0.0.0", "126.255.255.255"),
    ("128.0.0.0", "191.255.255.255"),
    ("192.0.0.0", "223.255.255.255"),
]


@dataclass
class TrafficConfig:
    packet_count: int = 1000
    pps: float = 1000.0  # Packets per second
    protocols: list[str] = None
    src_ip_range: str = "private"
    dst_ip_range: str = "mixed"
    min_packet_size: int = 64
    max_packet_size: int = 1500
    tcp_syn_ratio: float = 0.1
    payload_entropy: float = 0.5

    def __post_init__(self):
        if self.protocols is None:
            self.protocols = ["tcp", "udp", "icmp"]


def ip_to_int(ip: str) -> int:
    return struct.unpack("!I", struct.pack("!4s", bytes(int(x) for x in ip.split("."))))[0]


def int_to_ip(n: int) -> str:
    return ".".join(str((n >> (8 * i)) & 0xFF) for i in reversed(range(4)))


def random_ip(range_name: str) -> str:
    """Generate random IP from named range."""
    if range_name == "private":
        start, end = random.choice(PRIVATE_RANGES)
    elif range_name == "public":
        start, end = random.choice(PUBLIC_RANGES)
    else:  # mixed
        if random.random() < 0.7:
            start, end = random.choice(PRIVATE_RANGES)
        else:
            start, end = random.choice(PUBLIC_RANGES)
    return int_to_ip(random.randint(ip_to_int(start), ip_to_int(end)))


def random_port(protocol: str) -> int:
    """Generate random port weighted toward common ports."""
    common = COMMON_PORTS.get(protocol, [53])
    if random.random() < 0.7:
        return random.choice(common)
    return random.randint(1024, 65535)


def random_payload(size: int, entropy: float) -> bytes:
    """Generate payload with controlled entropy."""
    if entropy <= 0:
        return b"A" * size
    elif entropy >= 1:
        return random.randbytes(size)
    else:
        # Mix of pattern and random
        pattern = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        result = bytearray()
        while len(result) < size:
            if random.random() < entropy:
                result.extend(random.randbytes(min(100, size - len(result))))
            else:
                result.extend(pattern[: min(len(pattern), size - len(result))])
        return bytes(result[:size])


def generate_packet(config: TrafficConfig, timestamp: float) -> bytes:
    """Generate a single synthetic packet as raw bytes (Ethernet + IP + Transport)."""
    protocol = random.choice(config.protocols)
    src_ip = random_ip(config.src_ip_range)
    dst_ip = random_ip(config.dst_ip_range)

    # Ethernet header (simplified - just use fixed MACs)
    eth_dst = b"\x00\x0c\x29\x12\x34\x56"
    eth_src = b"\x00\x0c\x29\x65\x43\x21"
    eth_type = b"\x08\x00"  # IPv4

    # IP header
    ip_version_ihl = 0x45
    ip_tos = 0
    ip_id = random.randint(0, 65535)
    ip_flags_frag = 0x4000  # Don't fragment
    ip_ttl = 64
    ip_checksum = 0  # Will calculate

    if protocol == "tcp":
        ip_proto = 6
        src_port = random_port("tcp")
        dst_port = random_port("tcp")

        # TCP header
        tcp_seq = random.randint(0, 0xFFFFFFFF)
        tcp_ack = 0
        tcp_offset = 0x50  # 5 * 4 = 20 bytes
        tcp_flags = 0x02 if random.random() < config.tcp_syn_ratio else 0x10  # SYN or ACK
        tcp_window = 65535
        tcp_checksum = 0
        tcp_urgent = 0

        # Payload
        payload_size = random.randint(config.min_packet_size - 54, config.max_packet_size - 54)
        payload = random_payload(max(0, payload_size), config.payload_entropy)

        # Build TCP pseudo-header for checksum
        tcp_header = struct.pack(
            "!HHIIBBHHH",
            src_port,
            dst_port,
            tcp_seq,
            tcp_ack,
            tcp_offset,
            tcp_flags,
            tcp_window,
            tcp_checksum,
            tcp_urgent,
        )
        pseudo_header = struct.pack(
            "!4s4sBBH",
            struct.pack("!I", ip_to_int(src_ip)),
            struct.pack("!I", ip_to_int(dst_ip)),
            0,
            ip_proto,
            len(tcp_header) + len(payload),
        )
        tcp_checksum = checksum(pseudo_header + tcp_header + payload)
        tcp_header = struct.pack(
            "!HHIIBBHHH",
            src_port,
            dst_port,
            tcp_seq,
            tcp_ack,
            tcp_offset,
            tcp_flags,
            tcp_window,
            tcp_checksum,
            tcp_urgent,
        )

        transport_header = tcp_header

    elif protocol == "udp":
        ip_proto = 17
        src_port = random_port("udp")
        dst_port = random_port("udp")

        payload_size = random.randint(config.min_packet_size - 42, config.max_packet_size - 42)
        payload = random_payload(max(0, payload_size), config.payload_entropy)

        udp_length = 8 + len(payload)
        udp_checksum = 0

        udp_header = struct.pack("!HHHH", src_port, dst_port, udp_length, udp_checksum)

        pseudo_header = struct.pack(
            "!4s4sBBH",
            struct.pack("!I", ip_to_int(src_ip)),
            struct.pack("!I", ip_to_int(dst_ip)),
            0,
            ip_proto,
            udp_length,
        )
        udp_checksum = checksum(pseudo_header + udp_header + payload)
        udp_header = struct.pack("!HHHH", src_port, dst_port, udp_length, udp_checksum)

        transport_header = udp_header

    else:  # ICMP
        ip_proto = 1
        src_port = 0
        dst_port = 0

        icmp_type = 8  # Echo request
        icmp_code = 0
        icmp_checksum = 0
        icmp_id = random.randint(0, 65535)
        icmp_seq = random.randint(0, 65535)

        payload_size = random.randint(config.min_packet_size - 42, config.max_packet_size - 42)
        payload = random_payload(max(0, payload_size), config.payload_entropy)

        icmp_header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
        icmp_checksum = checksum(icmp_header + payload)
        icmp_header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)

        transport_header = icmp_header

    # IP total length
    ip_total_len = 20 + len(transport_header) + len(payload)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        ip_version_ihl,
        ip_tos,
        ip_total_len,
        ip_id,
        ip_flags_frag,
        ip_ttl,
        ip_proto,
        ip_checksum,
        struct.pack("!I", ip_to_int(src_ip)),
        struct.pack("!I", ip_to_int(dst_ip)),
    )
    ip_checksum = checksum(ip_header)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        ip_version_ihl,
        ip_tos,
        ip_total_len,
        ip_id,
        ip_flags_frag,
        ip_ttl,
        ip_proto,
        ip_checksum,
        struct.pack("!I", ip_to_int(src_ip)),
        struct.pack("!I", ip_to_int(dst_ip)),
    )

    frame = eth_dst + eth_src + eth_type + ip_header + transport_header + payload
    return frame


def checksum(data: bytes) -> int:
    """Internet checksum (RFC 1071)."""
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def generate_pcap(config: TrafficConfig, output_path: Path) -> None:
    """Generate a PCAP file with synthetic packets."""
    if not SCAPY_AVAILABLE:
        raise RuntimeError("scapy is required for PCAP generation. Install with: pip install scapy")

    packets = []
    for i in range(config.packet_count):
        ts = time.time() + i / config.pps
        frame = generate_packet(config, ts)

        # Parse with scapy to create proper packet object
        pkt = Ether(frame)
        pkt.time = ts
        packets.append(pkt)

    # Write PCAP
    if str(output_path).endswith(".gz"):
        import gzip

        with gzip.open(output_path, "wb") as f:
            wrpcap(f, packets)
    else:
        wrpcap(output_path, packets)

    print(f"Generated {len(packets)} packets to {output_path}")


async def replay_pcap(pcap_path: Path, speed: float, interface: str) -> None:
    """Replay a PCAP file on an interface at given speed multiplier."""
    if not SCAPY_AVAILABLE:
        raise RuntimeError("scapy is required for PCAP replay. Install with: pip install scapy")

    packets = rdpcap(str(pcap_path))
    print(f"Replaying {len(packets)} packets from {pcap_path} at {speed}x speed on {interface}")

    if speed <= 0:
        # As fast as possible
        sendp(packets, iface=interface, verbose=1)
    else:
        # Rate-limited
        interval = 1.0 / (speed * 1000)  # Approximate
        sendp(packets, iface=interface, inter=interval, verbose=1)


async def inject_kafka(
    config: TrafficConfig, topic: str, brokers: str, rate: float, duration: float | None
) -> None:
    """Inject synthetic packets directly into Kafka."""
    if not KAFKA_AVAILABLE:
        raise RuntimeError(
            "aiokafka is required for Kafka injection. Install with: pip install aiokafka"
        )

    producer = AIOKafkaProducer(
        bootstrap_servers=brokers,
        value_serializer=lambda v: v.encode() if isinstance(v, str) else str(v).encode(),
        acks="all",
        enable_idempotence=True,
    )
    await producer.start()

    print(f"Injecting packets into Kafka topic '{topic}' at {rate} pps")
    start_time = time.time()
    sent = 0

    try:
        while config.packet_count == 0 or sent < config.packet_count:
            if duration and (time.time() - start_time) >= duration:
                break

            frame = generate_packet(config, time.time())
            # Encode as base64 for JSON transport
            import base64

            record = {
                "timestamp": time.time(),
                "frame": base64.b64encode(frame).decode(),
                "length": len(frame),
            }
            await producer.send_and_wait(topic, json.dumps(record).encode())
            sent += 1

            if rate > 0:
                await asyncio.sleep(1.0 / rate)

            if sent % 1000 == 0:
                print(f"  Sent {sent} packets...")

    finally:
        await producer.stop()
        print(f"Total sent: {sent}")


def main():
    parser = argparse.ArgumentParser(description="Traffic Generator for Network Anomaly Detection")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Common arguments
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--packets", type=int, default=10000, help="Number of packets (0 = infinite)"
    )
    common.add_argument("--pps", type=float, default=1000.0, help="Packets per second")
    common.add_argument(
        "--protocols", nargs="+", default=["tcp", "udp", "icmp"], choices=["tcp", "udp", "icmp"]
    )
    common.add_argument("--src-range", choices=["private", "public", "mixed"], default="private")
    common.add_argument("--dst-range", choices=["private", "public", "mixed"], default="mixed")
    common.add_argument("--min-size", type=int, default=64)
    common.add_argument("--max-size", type=int, default=1500)
    common.add_argument("--syn-ratio", type=float, default=0.1)
    common.add_argument("--entropy", type=float, default=0.5)

    # PCAP generation
    pcap_parser = subparsers.add_parser("pcap", parents=[common], help="Generate PCAP file")
    pcap_parser.add_argument("--output", "-o", required=True, help="Output PCAP file path")

    # PCAP replay
    replay_parser = subparsers.add_parser("replay", help="Replay PCAP on interface")
    replay_parser.add_argument("--pcap", required=True, help="Input PCAP file")
    replay_parser.add_argument(
        "--speed", type=float, default=1.0, help="Replay speed multiplier (0 = max)"
    )
    replay_parser.add_argument("--interface", "-i", required=True, help="Network interface")

    # Kafka injection
    kafka_parser = subparsers.add_parser("kafka", parents=[common], help="Inject into Kafka")
    kafka_parser.add_argument("--topic", required=True, help="Kafka topic")
    kafka_parser.add_argument("--brokers", default="localhost:9092", help="Kafka brokers")
    kafka_parser.add_argument("--rate", type=float, default=1000, help="Packets per second")
    kafka_parser.add_argument(
        "--duration", type=float, help="Duration in seconds (overrides --packets)"
    )

    args = parser.parse_args()

    config = TrafficConfig(
        packet_count=args.packets,
        pps=args.pps,
        protocols=args.protocols,
        src_ip_range=args.src_range,
        dst_ip_range=args.dst_range,
        min_packet_size=args.min_size,
        max_packet_size=args.max_size,
        tcp_syn_ratio=args.syn_ratio,
        payload_entropy=args.entropy,
    )

    if args.command == "pcap":
        generate_pcap(config, Path(args.output))
    elif args.command == "replay":
        asyncio.run(replay_pcap(Path(args.pcap), args.speed, args.interface))
    elif args.command == "kafka":
        if args.duration:
            config.packet_count = 0  # Infinite until duration
        asyncio.run(inject_kafka(config, args.topic, args.brokers, args.rate, args.duration))


if __name__ == "__main__":
    main()
