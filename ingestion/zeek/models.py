"""
Zeek Log Ingestor - Domain logic for parsing Zeek (formerly Bro) log files.
No external dependencies so unit tests run fast.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ZeekLogType(Enum):
    """Known Zeek log types we can parse."""

    CONN = "conn"
    DNS = "dns"
    HTTP = "http"
    SSL = "ssl"
    X509 = "x509"
    NOTICE = "notice"
    WEIRD = "weird"
    FILES = "files"
    KERBEROS = "kerberos"
    RDP = "rdp"
    SMB_MAPPING = "smb_mapping"
    SMB_FILES = "smb_files"
    SSH = "ssh"
    FTP = "ftp"
    MYSQL = "mysql"
    PE = "pe"
    RADIUS = "radius"
    SYSLOG = "syslog"
    TUNNEL = "tunnel"
    UNKNOWN = "unknown"


@dataclass(slots=True)
class ZeekConfig:
    """Configuration for Zeek log ingestion."""

    log_dir: str = "./data/zeek_logs"
    file_pattern: str = "*.log"
    batch_size: int = 1000
    checkpoint_interval: int = 10000
    tail_files: bool = True
    poll_interval: float = 1.0
    # Field selection
    include_types: set[ZeekLogType] | None = None  # None = all
    exclude_fields: frozenset[str] = frozenset()


# Common field names across Zeek log types
COMMON_FIELDS = frozenset({
    "ts",
    "uid",
    "id.orig_h",
    "id.orig_p",
    "id.resp_h",
    "id.resp_p",
    "proto",
    "service",
    "duration",
    "orig_bytes",
    "resp_bytes",
    "conn_state",
    "local_orig",
    "local_resp",
    "missed_bytes",
    "history",
    "orig_pkts",
    "orig_ip_bytes",
    "resp_pkts",
    "resp_ip_bytes",
})

# Per-log-type field sets (subset for brevity; real implementation would be complete)
CONN_FIELDS = COMMON_FIELDS | frozenset({
    "tunnel_parents",
})

DNS_FIELDS = frozenset({
    "ts",
    "uid",
    "id.orig_h",
    "id.orig_p",
    "id.resp_h",
    "id.resp_p",
    "proto",
    "trans_id",
    "rtt",
    "query",
    "qclass",
    "qclass_name",
    "qtype",
    "qtype_name",
    "rcode",
    "rcode_name",
    "AA",
    "TC",
    "RD",
    "RA",
    "Z",
    "answers",
    "TTLs",
    "rejected",
})

HTTP_FIELDS = frozenset({
    "ts",
    "uid",
    "id.orig_h",
    "id.orig_p",
    "id.resp_h",
    "id.resp_p",
    "proto",
    "trans_depth",
    "method",
    "host",
    "uri",
    "referrer",
    "version",
    "user_agent",
    "request_body_len",
    "response_body_len",
    "status_code",
    "status_msg",
    "info_code",
    "info_msg",
    "filename",
    "tags",
    "username",
    "password",
    "proxied",
    "orig_fuids",
    "orig_mime_types",
    "resp_fuids",
    "resp_mime_types",
})

SSL_FIELDS = frozenset({
    "ts",
    "uid",
    "id.orig_h",
    "id.orig_p",
    "id.resp_h",
    "id.resp_p",
    "proto",
    "version",
    "cipher",
    "curve",
    "server_name",
    "resumed",
    "established",
    "cert_chain_fuids",
    "client_cert_chain_fuids",
    "subject",
    "issuer",
    "validation_status",
    "ja3",
    "ja3s",
})

NOTICE_FIELDS = frozenset({
    "ts",
    "uid",
    "id.orig_h",
    "id.orig_p",
    "id.resp_h",
    "id.resp_p",
    "proto",
    "note",
    "msg",
    "sub",
    "src",
    "dst",
    "p",
    "n",
    "peer_descr",
    "actions",
    "suppress_for",
    "dropped",
    "remote_location.country_code",
    "remote_location.region",
    "remote_location.city",
    "remote_location.latitude",
    "remote_location.longitude",
})

LOG_TYPE_FIELDS = {
    ZeekLogType.CONN: CONN_FIELDS,
    ZeekLogType.DNS: DNS_FIELDS,
    ZeekLogType.HTTP: HTTP_FIELDS,
    ZeekLogType.SSL: SSL_FIELDS,
    ZeekLogType.NOTICE: NOTICE_FIELDS,
}


@dataclass(slots=True)
class ZeekRecord:
    """A parsed Zeek log record."""

    log_type: ZeekLogType
    timestamp: float
    fields: dict[str, str | int | float | bool | None | list[str]]
    raw_line: str
    file_path: str
    line_number: int

    @property
    def flow_key(self) -> str | None:
        """Extract flow key if connection fields present."""
        try:
            orig_h = self.fields["id.orig_h"]
            orig_p = self.fields["id.orig_p"]
            resp_h = self.fields["id.resp_h"]
            resp_p = self.fields["id.resp_p"]
            proto = self.fields["proto"]
            # Ensure all are strings (not lists)
            if all(isinstance(v, str) for v in (orig_h, orig_p, resp_h, resp_p, proto)):
                return f"{orig_h}:{orig_p}->{resp_h}:{resp_p}/{proto}"
        except KeyError:
            pass
        return None

    @property
    def uid(self) -> str | None:
        """Connection UID if present."""
        val = self.fields.get("uid")
        return val if isinstance(val, str) else None


def detect_log_type(file_path: str, header_line: str) -> ZeekLogType:
    """
    Detect Zeek log type from file path and header.
    Header format: #fields\tfield1\tfield2\t...
    """
    # Try file name first
    stem = file_path.split("/")[-1].replace(".log", "").replace(".gz", "")
    for log_type in ZeekLogType:
        if log_type != ZeekLogType.UNKNOWN and log_type.value in stem.lower():
            return log_type

    # Fall back to field inspection
    if not header_line.startswith("#fields"):
        return ZeekLogType.UNKNOWN

    fields = header_line.strip().split("\t")[1:]
    field_set = set(fields)

    # Heuristic: which known type has the most field overlap?
    best_type = ZeekLogType.UNKNOWN
    best_score = 0
    for log_type, known_fields in LOG_TYPE_FIELDS.items():
        score = len(field_set & known_fields)
        if score > best_score:
            best_score = score
            best_type = log_type

    return best_type if best_score >= 3 else ZeekLogType.UNKNOWN


def parse_zeek_header(header_line: str) -> list[str]:
    """Parse #fields header line into field names."""
    if not header_line.startswith("#fields"):
        return []
    return header_line.strip().split("\t")[1:]


def parse_zeek_line(line: str, fields: list[str]) -> dict[str, str] | None:
    """Parse a Zeek log line (tab-separated) into a field dict."""
    if not line or line.startswith("#"):
        return None
    values = line.rstrip("\n").split("\t")
    if len(values) != len(fields):
        # Malformed line - could be escaped tabs in fields
        # Fall back: pad or truncate
        if len(values) < len(fields):
            values.extend([""] * (len(fields) - len(values)))
        else:
            values = values[: len(fields)]
    return dict(zip(fields, values, strict=False))


def parse_zeek_timestamp(ts_str: str) -> float:
    """Parse Zeek timestamp (UNIX epoch with fractional seconds) to float."""
    try:
        return float(ts_str)
    except ValueError:
        return 0.0


def normalize_zeek_value(
    value: str, field_name: str
) -> str | int | float | bool | None | list[str]:
    """
    Convert Zeek's string representation to native Python types.
    Zeek uses: - for empty, T/F for bool, comma-separated for sets/vectors.
    """
    if value == "-" or value == "":
        return None

    # Boolean
    if value == "T":
        return True
    if value == "F":
        return False

    if "," in value and field_name not in ("ts",):
        return [v.strip() for v in value.split(",")]

    # Numeric
    try:
        if "." in value:
            return float(value)
        return int(value)
    except ValueError:
        return value


def normalize_record(record: ZeekRecord) -> ZeekRecord:
    """Return a new record with normalized field values."""
    normalized = {k: normalize_zeek_value(v, k) for k, v in record.fields.items()}
    ts_val = normalized.get("ts")
    if isinstance(ts_val, (int, float)):
        ts_float = float(ts_val)
    elif isinstance(ts_val, str):
        ts_float = parse_zeek_timestamp(ts_val)
    else:
        ts_float = 0.0
    return ZeekRecord(
        log_type=record.log_type,
        timestamp=ts_float,
        fields=normalized,
        raw_line=record.raw_line,
        file_path=record.file_path,
        line_number=record.line_number,
    )
