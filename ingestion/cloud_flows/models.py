"""
Cloud Flow Logs Ingestor - Domain logic for parsing cloud provider flow logs.
No external dependencies so unit tests run fast.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class CloudProvider(Enum):
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"


class AWSFlowAction(Enum):
    ACCEPT = "ACCEPT"
    REJECT = "REJECT"


class AWSTrafficDirection(Enum):
    INGRESS = "ingress"
    EGRESS = "egress"


@dataclass(slots=True)
class CloudFlowConfig:
    """Configuration for cloud flow log ingestion."""

    provider: CloudProvider
    # AWS
    s3_bucket: str | None = None
    s3_prefix: str = ""
    sqs_queue_url: str | None = None
    # GCP
    gcs_bucket: str | None = None
    pubsub_subscription: str | None = None
    # Azure
    storage_account: str | None = None
    storage_container: str = "insights-logs-networksecuritygroupflowevent"
    event_hub_namespace: str | None = None
    event_hub_name: str | None = None
    # Common
    batch_size: int = 1000
    poll_interval: float = 5.0
    checkpoint_interval: int = 10000


# --- AWS VPC Flow Logs ---

AWS_FLOW_LOG_VERSION = 2
AWS_FLOW_LOG_FIELDS = (
    "version",
    "account_id",
    "interface_id",
    "src_addr",
    "dst_addr",
    "src_port",
    "dst_port",
    "protocol",
    "packets",
    "bytes",
    "start_time",
    "end_time",
    "action",
    "log_status",
)

# VPC Flow Logs v3+ additional fields
AWS_FLOW_LOG_FIELDS_V3 = AWS_FLOW_LOG_FIELDS + (
    "pkt_src_addr",
    "pkt_dst_addr",
    "pkt_src_port",
    "pkt_dst_port",
    "tcp_flags",
    "type",
    "region",
    "az_id",
    "subnet_id",
    "vpc_id",
)

# VPC Flow Logs v4+ (includes VPC flow logs for Transit Gateway)
AWS_FLOW_LOG_FIELDS_V4 = AWS_FLOW_LOG_FIELDS_V3 + (
    "instance_id",
    "src_vpc_id",
    "dst_vpc_id",
    "direction",
)


@dataclass(slots=True)
class AWSFlowRecord:
    """Parsed AWS VPC Flow Log record."""

    version: int
    account_id: str
    interface_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    packets: int
    bytes: int
    start_time: int  # Unix epoch
    end_time: int  # Unix epoch
    action: str  # ACCEPT / REJECT
    log_status: str  # OK / NODATA / SKIPDATA
    # v3+
    pkt_src_ip: str | None = None
    pkt_dst_ip: str | None = None
    pkt_src_port: int | None = None
    pkt_dst_port: int | None = None
    tcp_flags: int | None = None
    flow_type: str | None = None
    region: str | None = None
    az_id: str | None = None
    subnet_id: str | None = None
    vpc_id: str | None = None
    # v4+
    instance_id: str | None = None
    src_vpc_id: str | None = None
    dst_vpc_id: str | None = None
    direction: str | None = None

    @property
    def flow_key(self) -> str:
        return f"{self.src_ip}:{self.src_port}->{self.dst_ip}:{self.dst_port}/{self.protocol}"

    @property
    def duration_seconds(self) -> int:
        return max(0, self.end_time - self.start_time)

    @property
    def is_rejected(self) -> bool:
        return self.action == "REJECT"


def parse_aws_flow_log_line(line: str) -> AWSFlowRecord | None:
    """
    Parse a single AWS VPC Flow Log line (space-separated).
    Handles v2, v3, v4 formats.
    """
    line = line.strip()
    if not line:
        return None

    parts = line.split()
    if len(parts) < len(AWS_FLOW_LOG_FIELDS):
        return None

    try:
        version = int(parts[0])
        if version < 2:
            return None

        # Base fields (v2+)
        (
            _,
            account_id,
            interface_id,
            src_addr,
            dst_addr,
            src_port,
            dst_port,
            protocol,
            packets,
            bytes_,
            start_time,
            end_time,
            action,
            log_status,
        ) = parts[:14]

        record = AWSFlowRecord(
            version=version,
            account_id=account_id,
            interface_id=interface_id,
            src_ip=src_addr,
            dst_ip=dst_addr,
            src_port=int(src_port),
            dst_port=int(dst_port),
            protocol=int(protocol),
            packets=int(packets),
            bytes=int(bytes_),
            start_time=int(start_time),
            end_time=int(end_time),
            action=action,
            log_status=log_status,
        )

        # v3 fields (14+)
        if version >= 3 and len(parts) >= 24:
            record.pkt_src_ip = parts[14]
            record.pkt_dst_ip = parts[15]
            record.pkt_src_port = int(parts[16]) if parts[16] != "-" else None
            record.pkt_dst_port = int(parts[17]) if parts[17] != "-" else None
            record.tcp_flags = int(parts[18]) if parts[18] != "-" else None
            record.flow_type = parts[19]
            record.region = parts[20]
            record.az_id = parts[21]
            record.subnet_id = parts[22]
            record.vpc_id = parts[23]

        # v4 fields (24+)
        if version >= 4 and len(parts) >= 28:
            record.instance_id = parts[24]
            record.src_vpc_id = parts[25]
            record.dst_vpc_id = parts[26]
            record.direction = parts[27]

    except (ValueError, IndexError):
        return None
    else:
        return record


# --- GCP VPC Flow Logs ---


@dataclass(slots=True)
class GCPFlowRecord:
    """Parsed GCP VPC Flow Log record (JSON format)."""

    # Required fields
    start_time: str  # RFC3339
    end_time: str  # RFC3339
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    packets: int
    bytes: int
    # Optional / metadata
    src_vpc_project_id: str | None = None
    dst_vpc_project_id: str | None = None
    src_vpc_network: str | None = None
    dst_vpc_network: str | None = None
    src_vpc_subnetwork: str | None = None
    dst_vpc_subnetwork: str | None = None
    direction: str | None = None  # INGRESS / EGRESS
    reporter: str | None = None  # SRC / DEST / BOTH
    # TCP flags
    tcp_flags_ack: bool = False
    tcp_flags_syn: bool = False
    tcp_flags_fin: bool = False
    tcp_flags_rst: bool = False
    tcp_flags_push: bool = False
    tcp_flags_urg: bool = False
    tcp_flags_ece: bool = False
    tcp_flags_cwr: bool = False

    @property
    def flow_key(self) -> str:
        return f"{self.src_ip}:{self.src_port}->{self.dst_ip}:{self.dst_port}/{self.protocol}"


def parse_gcp_flow_log_json(json_str: str) -> GCPFlowRecord | None:
    """Parse a GCP VPC Flow Log JSON record."""
    try:
        data = json.loads(json_str)
        # GCP wraps flow logs in a 'jsonPayload' field when exported to Cloud Logging
        if "jsonPayload" in data:
            data = data["jsonPayload"]

        return GCPFlowRecord(
            start_time=data.get("start_time", ""),
            end_time=data.get("end_time", ""),
            src_ip=data.get("src_ip", ""),
            dst_ip=data.get("dst_ip", ""),
            src_port=int(data.get("src_port", 0)),
            dst_port=int(data.get("dst_port", 0)),
            protocol=int(data.get("protocol", 0)),
            packets=int(data.get("packets", 0)),
            bytes=int(data.get("bytes", 0)),
            src_vpc_project_id=data.get("src_vpc_project_id"),
            dst_vpc_project_id=data.get("dst_vpc_project_id"),
            src_vpc_network=data.get("src_vpc_network"),
            dst_vpc_network=data.get("dst_vpc_network"),
            src_vpc_subnetwork=data.get("src_vpc_subnetwork"),
            dst_vpc_subnetwork=data.get("dst_vpc_subnetwork"),
            direction=data.get("direction"),
            reporter=data.get("reporter"),
            tcp_flags_ack=data.get("tcp_flags_ack", False),
            tcp_flags_syn=data.get("tcp_flags_syn", False),
            tcp_flags_fin=data.get("tcp_flags_fin", False),
            tcp_flags_rst=data.get("tcp_flags_rst", False),
            tcp_flags_push=data.get("tcp_flags_push", False),
            tcp_flags_urg=data.get("tcp_flags_urg", False),
            tcp_flags_ece=data.get("tcp_flags_ece", False),
            tcp_flags_cwr=data.get("tcp_flags_cwr", False),
        )
    except (json.JSONDecodeError, KeyError, ValueError):
        return None


# --- Azure NSG Flow Logs ---


@dataclass(slots=True)
class AzureFlowRecord:
    """Parsed Azure NSG Flow Log record (JSON format)."""

    time: str  # ISO8601
    system_id: str
    category: str
    resource_id: str
    operation_name: str
    properties: dict[str, object]

    # Flattened from properties.flow (list of flows)
    rule: str | None = None
    mac: str | None = None
    flow_tuples: list[str] | None = (
        None  # Comma-separated: "timestamp,src_ip,dst_ip,src_port,dst_port,protocol,action,flow_direction"
    )

    @property
    def flow_key(self) -> str | None:
        if not self.flow_tuples:
            return None
        # Parse first flow tuple
        try:
            parts = self.flow_tuples[0].split(",")
            if len(parts) >= 7:
                _, src_ip, dst_ip, src_port, dst_port, protocol, action, direction = parts[:8]
                return f"{src_ip}:{src_port}->{dst_ip}:{dst_port}/{protocol}"
        except Exception:  # noqa: S110 - intentionally ignore parse errors
            pass
        return None


# Azure flow tuple format: "timestamp,src_ip,dst_ip,src_port,dst_port,protocol,action,flow_direction"
AZURE_FLOW_TUPLE_RE = re.compile(r"^(\d+),([^,]+),([^,]+),(\d+),(\d+),(\d+),([^,]+),([^,]+)$")


def parse_azure_flow_log_json(json_str: str) -> list[AzureFlowRecord] | None:
    """Parse Azure NSG Flow Log JSON - returns list of records (one per rule)."""
    try:
        data = json.loads(json_str)
        records = data.get("records", [])
        result = []
        for rec in records:
            props = rec.get("properties", {})
            flows = props.get("flows", [])
            for flow in flows:
                rule = flow.get("rule")
                flow_tuples = flow.get("flows", [])  # Nested 'flows' array
                for ft in flow_tuples:
                    tuples = ft.get("flowTuples", [])
                    if tuples:
                        result.append(
                            AzureFlowRecord(
                                time=rec.get("time", ""),
                                system_id=rec.get("systemId", ""),
                                category=rec.get("category", ""),
                                resource_id=rec.get("resourceId", ""),
                                operation_name=rec.get("operationName", ""),
                                properties=props,
                                rule=rule,
                                flow_tuples=tuples,
                            )
                        )
    except (json.JSONDecodeError, KeyError):
        return None
    else:
        return result if result else None


def parse_azure_flow_tuple(tuple_str: str) -> tuple[int, str, str, int, int, int, str, str] | None:
    """Parse a single Azure flow tuple string."""
    match = AZURE_FLOW_TUPLE_RE.match(tuple_str)
    if not match:
        return None
    timestamp, src_ip, dst_ip, src_port, dst_port, protocol, action, direction = match.groups()
    return (
        int(timestamp),
        src_ip,
        dst_ip,
        int(src_port),
        int(dst_port),
        int(protocol),
        action,
        direction,
    )


# --- Unified normalized record for Kafka ---


@dataclass(slots=True)
class CloudFlowRecord:
    """Normalized flow record from any cloud provider."""

    provider: str  # aws / gcp / azure
    timestamp: float  # Flow start time (Unix epoch)
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    packets: int
    bytes: int
    action: str | None  # ACCEPT / REJECT / ALLOW / DENY
    direction: str | None  # INGRESS / EGRESS
    # Provider-specific metadata
    metadata: dict[str, str]

    @property
    def flow_key(self) -> str:
        return f"{self.src_ip}:{self.src_port}->{self.dst_ip}:{self.dst_port}/{self.protocol}"


def normalize_aws(record: AWSFlowRecord) -> CloudFlowRecord:
    return CloudFlowRecord(
        provider="aws",
        timestamp=float(record.start_time),
        src_ip=record.src_ip,
        dst_ip=record.dst_ip,
        src_port=record.src_port,
        dst_port=record.dst_port,
        protocol=record.protocol,
        packets=record.packets,
        bytes=record.bytes,
        action=record.action,
        direction=record.direction,
        metadata={
            "account_id": record.account_id,
            "interface_id": record.interface_id,
            "log_status": record.log_status,
            "vpc_id": record.vpc_id or "",
            "subnet_id": record.subnet_id or "",
            "instance_id": record.instance_id or "",
        },
    )


def normalize_gcp(record: GCPFlowRecord) -> CloudFlowRecord:
    # Parse RFC3339 timestamps
    def parse_rfc3339(ts: str) -> float:
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
        except Exception:
            return 0.0

    action = "ALLOW"  # GCP doesn't have explicit action, infer from reporter
    if record.reporter == "SRC":
        action = "EGRESS"
    elif record.reporter == "DEST":
        action = "INGRESS"

    return CloudFlowRecord(
        provider="gcp",
        timestamp=parse_rfc3339(record.start_time),
        src_ip=record.src_ip,
        dst_ip=record.dst_ip,
        src_port=record.src_port,
        dst_port=record.dst_port,
        protocol=record.protocol,
        packets=record.packets,
        bytes=record.bytes,
        action=action,
        direction=record.direction,
        metadata={
            "src_vpc_project_id": record.src_vpc_project_id or "",
            "dst_vpc_project_id": record.dst_vpc_project_id or "",
            "src_vpc_network": record.src_vpc_network or "",
            "dst_vpc_network": record.dst_vpc_network or "",
            "reporter": record.reporter or "",
        },
    )


def normalize_azure(record: AzureFlowRecord) -> list[CloudFlowRecord]:
    """One Azure record can contain multiple flow tuples."""
    results: list[CloudFlowRecord] = []
    if not record.flow_tuples:
        return results

    for ft in record.flow_tuples:
        parsed = parse_azure_flow_tuple(ft)
        if not parsed:
            continue
        timestamp, src_ip, dst_ip, src_port, dst_port, protocol, action, direction = parsed

        results.append(
            CloudFlowRecord(
                provider="azure",
                timestamp=float(timestamp),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                packets=1,  # Azure doesn't provide packet count per tuple
                bytes=0,  # Azure doesn't provide byte count per tuple
                action=action,
                direction=direction,
                metadata={
                    "rule": record.rule or "",
                    "resource_id": record.resource_id,
                    "system_id": record.system_id,
                },
            )
        )
    return results
