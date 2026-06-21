"""Shared test fixtures and mock tshark JSON data."""

from datetime import UTC, datetime
from ipaddress import IPv4Address
from uuid import UUID, uuid4

from backend.contracts.enums import Protocol
from backend.contracts.parser_output import (
    ParsedDNS,
    ParsedFTP,
    ParsedHTTP,
    ParsedPacket,
    ParsedSMTP,
)

DNS_QUERY_PACKET = {
    "_source": {
        "layers": {
            "frame": {
                "frame.number": "1",
                "frame.time_epoch": "1700000000.123456",
                "frame.len": "80",
            },
            "ip": {
                "ip.src": "192.168.1.100",
                "ip.dst": "8.8.8.8",
            },
            "udp": {
                "udp.srcport": "5353",
                "udp.dstport": "53",
            },
            "dns": {
                "dns.qry.name": "example.com",
                "dns.qry.type": "A",
                "dns.flags.rcode": "0",
                "dns.resp.name": "example.com",
                "dns.a": "93.184.216.34",
            },
            "_ws.col.Protocol": "DNS",
            "_ws.col.Info": "Standard query 0x1234 A example.com",
        }
    }
}

DNS_RESPONSE_PACKET = {
    "_source": {
        "layers": {
            "frame": {
                "frame.number": "2",
                "frame.time_epoch": "1700000000.234567",
                "frame.len": "150",
            },
            "ip": {
                "ip.src": "8.8.8.8",
                "ip.dst": "192.168.1.100",
            },
            "udp": {
                "udp.srcport": "53",
                "udp.dstport": "5353",
            },
            "dns": {
                "dns.qry.name": "example.com",
                "dns.qry.type": "A",
                "dns.flags.rcode": "0",
                "dns.a": "93.184.216.34",
            },
            "_ws.col.Protocol": "DNS",
            "_ws.col.Info": "Standard query response 0x1234 A example.com",
        }
    }
}

HTTP_REQUEST_PACKET = {
    "_source": {
        "layers": {
            "frame": {
                "frame.number": "10",
                "frame.time_epoch": "1700000001.000000",
                "frame.len": "450",
            },
            "ip": {
                "ip.src": "192.168.1.100",
                "ip.dst": "93.184.216.34",
            },
            "tcp": {
                "tcp.srcport": "54321",
                "tcp.dstport": "80",
            },
            "http": {
                "http.request.method": "GET",
                "http.host": "example.com",
                "http.request.uri": "/index.html",
                "http.user_agent": "TestAgent/1.0",
                "http.content_type": "text/html",
            },
            "_ws.col.Protocol": "HTTP",
            "_ws.col.Info": "GET /index.html HTTP/1.1",
        }
    }
}

HTTP_RESPONSE_PACKET = {
    "_source": {
        "layers": {
            "frame": {
                "frame.number": "11",
                "frame.time_epoch": "1700000001.050000",
                "frame.len": "1200",
            },
            "ip": {
                "ip.src": "93.184.216.34",
                "ip.dst": "192.168.1.100",
            },
            "tcp": {
                "tcp.srcport": "80",
                "tcp.dstport": "54321",
            },
            "http": {
                "http.response.code": "200",
                "http.content_type": "text/html",
            },
            "_ws.col.Protocol": "HTTP",
            "_ws.col.Info": "HTTP/1.1 200 OK",
        }
    }
}

FTP_COMMAND_PACKET = {
    "_source": {
        "layers": {
            "frame": {
                "frame.number": "20",
                "frame.time_epoch": "1700000002.000000",
                "frame.len": "60",
            },
            "ip": {
                "ip.src": "192.168.1.100",
                "ip.dst": "10.0.0.1",
            },
            "tcp": {
                "tcp.srcport": "50000",
                "tcp.dstport": "21",
            },
            "ftp": {
                "ftp.request.command": "USER",
                "ftp.request.arg": "anonymous",
            },
            "_ws.col.Protocol": "FTP",
            "_ws.col.Info": "Request: USER anonymous",
        }
    }
}

FTP_RESPONSE_PACKET = {
    "_source": {
        "layers": {
            "frame": {
                "frame.number": "21",
                "frame.time_epoch": "1700000002.100000",
                "frame.len": "70",
            },
            "ip": {
                "ip.src": "10.0.0.1",
                "ip.dst": "192.168.1.100",
            },
            "tcp": {
                "tcp.srcport": "21",
                "tcp.dstport": "50000",
            },
            "ftp": {
                "ftp.response.code": "230",
                "ftp.response.arg": "Login successful",
            },
            "_ws.col.Protocol": "FTP",
            "_ws.col.Info": "Response: 230 Login successful",
        }
    }
}

SMTP_COMMAND_PACKET = {
    "_source": {
        "layers": {
            "frame": {
                "frame.number": "30",
                "frame.time_epoch": "1700000003.000000",
                "frame.len": "100",
            },
            "ip": {
                "ip.src": "192.168.1.100",
                "ip.dst": "10.0.0.2",
            },
            "tcp": {
                "tcp.srcport": "40000",
                "tcp.dstport": "25",
            },
            "smtp": {
                "smtp.command": "MAIL",
                "smtp.parameter": "FROM:<test@example.com>",
                "smtp.mail_from": "test@example.com",
            },
            "_ws.col.Protocol": "SMTP",
            "_ws.col.Info": "MAIL FROM:<test@example.com>",
        }
    }
}

SMTP_RESPONSE_PACKET = {
    "_source": {
        "layers": {
            "frame": {
                "frame.number": "31",
                "frame.time_epoch": "1700000003.050000",
                "frame.len": "60",
            },
            "ip": {
                "ip.src": "10.0.0.2",
                "ip.dst": "192.168.1.100",
            },
            "tcp": {
                "tcp.srcport": "25",
                "tcp.dstport": "40000",
            },
            "smtp": {
                "smtp.response.code": "250",
                "smtp.response.parameter": "OK",
            },
            "_ws.col.Protocol": "SMTP",
            "_ws.col.Info": "Response: 250 OK",
        }
    }
}

TCP_PACKET = {
    "_source": {
        "layers": {
            "frame": {
                "frame.number": "40",
                "frame.time_epoch": "1700000004.000000",
                "frame.len": "200",
            },
            "ip": {
                "ip.src": "10.0.0.1",
                "ip.dst": "10.0.0.2",
            },
            "tcp": {
                "tcp.srcport": "12345",
                "tcp.dstport": "443",
                "tcp.flags": "0x010",
            },
            "_ws.col.Protocol": "TCP",
            "_ws.col.Info": "443 → 12345 [ACK] Seq=1 Ack=1 Win=65535",
        }
    }
}

UDP_PACKET = {
    "_source": {
        "layers": {
            "frame": {
                "frame.number": "50",
                "frame.time_epoch": "1700000005.000000",
                "frame.len": "100",
            },
            "ip": {
                "ip.src": "10.0.0.1",
                "ip.dst": "10.0.0.2",
            },
            "udp": {
                "udp.srcport": "12345",
                "udp.dstport": "53",
            },
            "_ws.col.Protocol": "UDP",
            "_ws.col.Info": "12345 → 53 Len=58",
        }
    }
}

ICMP_PACKET = {
    "_source": {
        "layers": {
            "frame": {
                "frame.number": "60",
                "frame.time_epoch": "1700000006.000000",
                "frame.len": "84",
            },
            "ip": {
                "ip.src": "192.168.1.100",
                "ip.dst": "8.8.8.8",
            },
            "icmp": {
                "icmp.type": "8",
                "icmp.code": "0",
            },
            "_ws.col.Protocol": "ICMP",
            "_ws.col.Info": "Echo (ping) request id=0x1234 seq=1/256 ttl=64",
        }
    }
}

ICMP_RESPONSE_PACKET = {
    "_source": {
        "layers": {
            "frame": {
                "frame.number": "61",
                "frame.time_epoch": "1700000006.050000",
                "frame.len": "84",
            },
            "ip": {
                "ip.src": "8.8.8.8",
                "ip.dst": "192.168.1.100",
            },
            "icmp": {
                "icmp.type": "0",
                "icmp.code": "0",
            },
            "_ws.col.Protocol": "ICMP",
            "_ws.col.Info": "Echo (ping) reply id=0x1234 seq=1/256 ttl=118",
        }
    }
}


def make_expected_timestamp(epoch_str: str) -> datetime:
    """Convert tshark epoch string to datetime."""
    return datetime.fromtimestamp(float(epoch_str), tz=UTC)


# ── ParsedProtocols builder helpers ──────────────────────────────────────────

def make_parsed_packet(
    *,
    pcap_id: UUID | None = None,
    packet_number: int = 1,
    src_ip: str = "10.0.0.1",
    dst_ip: str = "10.0.0.2",
    src_port: int | None = 12345,
    dst_port: int | None = 80,
    protocol: Protocol = Protocol.TCP,
    length: int = 100,
    timestamp: str = "2024-01-01T00:00:00+00:00",
    tcp_flags: str | None = None,
) -> ParsedPacket:
    ts = datetime.fromisoformat(timestamp) if timestamp else None
    return ParsedPacket(
        pcap_id=pcap_id or uuid4(),
        packet_number=packet_number,
        timestamp=ts,
        src_ip=IPv4Address(src_ip),
        dst_ip=IPv4Address(dst_ip),
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        length=length,
        tcp_flags=tcp_flags,
    )


def make_parsed_dns(
    *,
    pcap_id: UUID | None = None,
    qname: str = "example.com",
    qtype: str = "A",
    src_ip: str = "10.0.0.1",
    dst_ip: str = "8.8.8.8",
    response_code: str | None = "0",
    query_size_bytes: int | None = None,
    timestamp: str = "2024-01-01T00:00:00+00:00",
) -> ParsedDNS:
    ts = datetime.fromisoformat(timestamp) if timestamp else None
    return ParsedDNS(
        pcap_id=pcap_id or uuid4(),
        timestamp=ts,
        src_ip=IPv4Address(src_ip),
        dst_ip=IPv4Address(dst_ip),
        qname=qname,
        qtype=qtype,
        response_code=response_code,
        query_size_bytes=query_size_bytes,
    )


def make_parsed_http(
    *,
    pcap_id: UUID | None = None,
    method: str = "GET",
    host: str = "example.com",
    uri: str = "/index.html",
    status_code: int | None = None,
    user_agent: str | None = None,
    src_ip: str = "10.0.0.1",
    dst_ip: str = "93.184.216.34",
    timestamp: str = "2024-01-01T00:00:00+00:00",
) -> ParsedHTTP:
    ts = datetime.fromisoformat(timestamp) if timestamp else None
    return ParsedHTTP(
        pcap_id=pcap_id or uuid4(),
        timestamp=ts,
        src_ip=IPv4Address(src_ip),
        dst_ip=IPv4Address(dst_ip),
        method=method,
        host=host,
        uri=uri,
        status_code=status_code,
        user_agent=user_agent,
    )


def make_parsed_ftp(
    *,
    src_ip: str = "10.0.0.1",
    dst_ip: str = "10.0.0.2",
    command: str = "USER",
    argument: str | None = "anonymous",
    response_code: int | None = None,
    response_message: str | None = None,
    timestamp: str = "2024-01-01T00:00:00+00:00",
) -> ParsedFTP:
    ts = datetime.fromisoformat(timestamp) if timestamp else None
    return ParsedFTP(
        pcap_id=uuid4(),
        timestamp=ts,
        src_ip=IPv4Address(src_ip),
        dst_ip=IPv4Address(dst_ip),
        command=command,
        argument=argument,
        response_code=response_code,
        response_message=response_message,
    )


def make_parsed_smtp(
    *,
    src_ip: str = "10.0.0.1",
    dst_ip: str = "10.0.0.2",
    command: str = "MAIL",
    argument: str | None = "FROM:<a@b.com>",
    response_code: int | None = None,
    mail_from: str | None = "a@b.com",
    rcpt_to: list[str] | None = None,
    timestamp: str = "2024-01-01T00:00:00+00:00",
) -> ParsedSMTP:
    ts = datetime.fromisoformat(timestamp) if timestamp else None
    return ParsedSMTP(
        pcap_id=uuid4(),
        timestamp=ts,
        src_ip=IPv4Address(src_ip),
        dst_ip=IPv4Address(dst_ip),
        command=command,
        argument=argument,
        response_code=response_code,
        mail_from=mail_from,
        rcpt_to=rcpt_to,
    )


__all__ = [
    "DNS_QUERY_PACKET",
    "DNS_RESPONSE_PACKET",
    "HTTP_REQUEST_PACKET",
    "HTTP_RESPONSE_PACKET",
    "FTP_COMMAND_PACKET",
    "FTP_RESPONSE_PACKET",
    "SMTP_COMMAND_PACKET",
    "SMTP_RESPONSE_PACKET",
    "TCP_PACKET",
    "UDP_PACKET",
    "ICMP_PACKET",
    "ICMP_RESPONSE_PACKET",
    "make_expected_timestamp",
    "make_parsed_packet",
    "make_parsed_dns",
    "make_parsed_http",
    "make_parsed_ftp",
    "make_parsed_smtp",
]
