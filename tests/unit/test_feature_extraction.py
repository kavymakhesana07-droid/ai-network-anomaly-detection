"""Unit tests for flow feature extraction logic."""

from datetime import datetime

import pytest

from feature_extraction.models import (
    FlowFeatures,
    FlowKey,
    FlowState,
    RawPacket,
    compute_entropy,
    summarize_flow,
)


def _pkt(
    src="10.0.0.1", dst="10.0.0.2", sport=1234, dport=80, proto=6, length=100, payload=b""
) -> RawPacket:
    return RawPacket(
        timestamp=datetime(2026, 1, 1, 12, 0, 0).timestamp(),
        src_ip=src,
        dst_ip=dst,
        src_port=sport,
        dst_port=dport,
        protocol=proto,
        length=length,
        payload=payload,
        pcap_file="test.pcap",
        packet_number=1,
    )


class TestFlowKey:
    def test_normalizes_direction(self):
        """Same 5-tuple in reverse order must produce an identical key."""
        a = FlowKey.from_packet(_pkt(src="10.0.0.1", dst="10.0.0.2", sport=1111, dport=80))
        b = FlowKey.from_packet(_pkt(src="10.0.0.2", dst="10.0.0.1", sport=80, dport=1111))
        assert a == b

    def test_distinguishes_protocols(self):
        a = FlowKey.from_packet(_pkt(proto=6))
        b = FlowKey.from_packet(_pkt(proto=17))
        assert a != b

    def test_distinguishes_ports(self):
        a = FlowKey.from_packet(_pkt(sport=1111, dport=80))
        b = FlowKey.from_packet(_pkt(sport=2222, dport=80))
        assert a != b

    def test_distinguishes_hosts(self):
        a = FlowKey.from_packet(_pkt(src="10.0.0.1", dst="10.0.0.2"))
        b = FlowKey.from_packet(_pkt(src="10.0.0.3", dst="10.0.0.4"))
        assert a != b


class TestFlowState:
    def test_not_expired_within_timeout(self):
        state = FlowState(
            key=FlowKey.from_packet(_pkt()),
            start_time=1000.0,
            last_time=1010.0,
        )
        assert state.is_expired(now=1050.0, timeout=300) is False

    def test_expired_past_timeout(self):
        state = FlowState(
            key=FlowKey.from_packet(_pkt()),
            start_time=1000.0,
            last_time=1010.0,
        )
        assert state.is_expired(now=1400.0, timeout=300) is True

    def test_expiry_boundary(self):
        state = FlowState(
            key=FlowKey.from_packet(_pkt()),
            start_time=1000.0,
            last_time=1000.0,
        )
        # elapsed exactly == timeout is not expired (strict >)
        assert state.is_expired(now=1300.0, timeout=300) is False
        assert state.is_expired(now=1300.1, timeout=300) is True


class TestFlowFeatures:
    def test_schema_roundtrip(self):
        features = FlowFeatures(
            flow_id="10.0.0.1:1234-10.0.0.2:80-6",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=1234,
            dst_port=80,
            protocol=6,
            start_time=1000.0,
            duration=5.0,
            packets_total=10,
            bytes_total=1000,
            packets_fwd=6,
            packets_rev=4,
            bytes_fwd=700,
            bytes_rev=300,
            packets_per_sec=2.0,
            bytes_per_sec=200.0,
            avg_pkt_size=100.0,
            min_pkt_size=50,
            max_pkt_size=150,
            pkt_size_std=12.5,
            fwd_rev_packet_ratio=1.5,
            fwd_rev_byte_ratio=2.33,
        )
        restored = FlowFeatures.model_validate_json(features.model_dump_json())
        assert restored.flow_id == features.flow_id
        assert restored.bytes_total == 1000

    def test_optional_fields_default(self):
        features = FlowFeatures(
            flow_id="f",
            src_ip="1.1.1.1",
            dst_ip="2.2.2.2",
            src_port=1,
            dst_port=2,
            protocol=6,
            start_time=0.0,
            duration=1.0,
            packets_total=1,
            bytes_total=1,
            packets_fwd=1,
            packets_rev=0,
            bytes_fwd=1,
            bytes_rev=0,
            packets_per_sec=1.0,
            bytes_per_sec=1.0,
            avg_pkt_size=1.0,
            min_pkt_size=1,
            max_pkt_size=1,
            pkt_size_std=0.0,
            fwd_rev_packet_ratio=1.0,
            fwd_rev_byte_ratio=1.0,
        )
        assert features.tcp_syn_count == 0
        assert features.dns_query_count == 0
        assert features.payload_entropy == 0.0


@pytest.mark.parametrize(
    "payload,expected_positive",
    [
        (b"\x00" * 256, False),  # single repeated byte -> zero entropy
        (bytes(range(256)), True),  # all distinct -> high entropy
    ],
)
def test_entropy_bounds(payload: bytes, expected_positive: bool):
    entropy = compute_entropy(payload)
    assert 0.0 <= entropy <= 8.0
    if expected_positive:
        assert entropy > 6.0
    else:
        assert entropy == pytest.approx(0.0, abs=1e-9)


def test_entropy_empty_payload():
    assert compute_entropy(b"") == 0.0


class TestSummarizeFlow:
    def test_bidirectional_accounting(self):
        state = FlowState(
            key=FlowKey.from_packet(_pkt()),
            start_time=1000.0,
            last_time=1005.0,
            packets_fwd=6,
            packets_rev=4,
            bytes_fwd=700,
            bytes_rev=300,
            pkt_sizes=[100] * 10,
        )
        f = summarize_flow(state, pcap_source="demo.pcap")
        assert f.packets_total == 10
        assert f.bytes_total == 1000
        assert f.duration == pytest.approx(5.0)
        assert f.packets_per_sec == pytest.approx(2.0)
        assert f.bytes_per_sec == pytest.approx(200.0)
        assert f.avg_pkt_size == pytest.approx(100.0)
        assert f.fwd_rev_packet_ratio == pytest.approx(1.5)
        assert f.pcap_source == "demo.pcap"

    def test_zero_duration_does_not_divide_by_zero(self):
        state = FlowState(
            key=FlowKey.from_packet(_pkt()),
            start_time=1000.0,
            last_time=1000.0,
            packets_fwd=1,
            packets_rev=0,
            bytes_fwd=100,
            bytes_rev=0,
            pkt_sizes=[100],
        )
        f = summarize_flow(state)
        assert f.duration == pytest.approx(0.001)
        assert f.packets_per_sec == pytest.approx(1000.0)

    def test_flow_id_matches_key_string(self):
        pkt = _pkt()
        key = FlowKey.from_packet(pkt)
        state = FlowState(key=key, start_time=0.0, last_time=1.0, pkt_sizes=[10])
        f = summarize_flow(state)
        assert f.flow_id == str(key)
        assert f.src_ip == key.ip1
        assert f.dst_ip == key.ip2

    def test_tcp_flag_counts(self):
        state = FlowState(
            key=FlowKey.from_packet(_pkt()),
            start_time=0.0,
            last_time=1.0,
            pkt_sizes=[10],
            tcp_flags={"SYN": 3, "ACK": 7, "RST": 1},
        )
        f = summarize_flow(state)
        assert f.tcp_syn_count == 3
        assert f.tcp_ack_count == 7
        assert f.tcp_rst_count == 1
        assert f.tcp_fin_count == 0
