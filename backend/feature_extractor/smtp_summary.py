"""SMTP summary builder: per-IP message rates and failed auth."""


from backend.contracts.features import SMTPFlow
from backend.contracts.parser_output import ParsedSMTP


class SMTPSummaryBuilder:
    """Accumulate SMTP messages and produce per-IP SMTPFlow list."""

    def __init__(self) -> None:
        self._by_src: dict[str, dict] = {}

    def add_smtp(self, smtp: ParsedSMTP) -> None:
        """Ingest a single parsed SMTP command or response."""
        src_key = str(smtp.src_ip)
        if src_key not in self._by_src:
            self._by_src[src_key] = {
                "src_ip": smtp.src_ip,
                "message_count": 0,
                "recipients": set(),
                "failed_auth": 0,
                "total_connections": 0,
                "total_sizes": [],
                "first_seen": smtp.timestamp,
                "last_seen": smtp.timestamp,
            }
        g = self._by_src[src_key]

        if smtp.timestamp:
            if g["first_seen"] is None or (smtp.timestamp and smtp.timestamp < g["first_seen"]):
                g["first_seen"] = smtp.timestamp
            if g["last_seen"] is None or (smtp.timestamp and smtp.timestamp > g["last_seen"]):
                g["last_seen"] = smtp.timestamp

        # Count RCPT TO as message indicators
        if smtp.command and smtp.command.upper() == "MAIL":
            g["message_count"] += 1

        # Track unique recipients
        if smtp.rcpt_to:
            for rcpt in smtp.rcpt_to:
                g["recipients"].add(rcpt.strip("<>"))

        # Auth failure detection: response code 535 or 550
        if smtp.response_code is not None and smtp.response_code == 535:
            g["failed_auth"] += 1

        # Count MAIL + RCPT as connection activity; EHLO/HELO as connections
        if smtp.command and smtp.command.upper() in ("EHLO", "HELO"):
            g["total_connections"] += 1

        # If no EHLO/HELO observed, estimate connections from message_count
        if g["total_connections"] == 0 and g["message_count"] > 0:
            g["total_connections"] = g["message_count"]

    def finalize(self) -> list[SMTPFlow]:
        """Build sorted SMTPFlow list."""
        results = []
        for g in self._by_src.values():
            if g["first_seen"] and g["last_seen"]:
                (g["last_seen"] - g["first_seen"]).total_seconds()

            avg_size = None
            if g["total_sizes"]:
                avg_size = round(sum(g["total_sizes"]) / len(g["total_sizes"]), 2)

            if g["total_connections"] == 0:
                g["total_connections"] = max(1, g["message_count"])

            results.append(
                SMTPFlow(
                    src_ip=g["src_ip"],
                    message_count=g["message_count"],
                    unique_recipients=len(g["recipients"]),
                    failed_auth_count=g["failed_auth"],
                    total_connections=g["total_connections"],
                    avg_message_size_bytes=avg_size,
                )
            )

        results.sort(key=lambda f: str(f.src_ip))
        return results
