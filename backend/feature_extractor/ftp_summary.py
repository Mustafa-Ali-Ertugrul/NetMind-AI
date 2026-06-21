"""FTP summary builder: per-IP auth rate and command counts."""


from backend.contracts.features import FTPFlow
from backend.contracts.parser_output import ParsedFTP


class FTPSummaryBuilder:
    """Accumulate FTP session entries and produce per-IP FTPFlow list."""

    def __init__(self) -> None:
        self._by_src: dict[str, dict] = {}

    def add_ftp(self, ftp: ParsedFTP) -> None:
        """Ingest a single parsed FTP command or response."""
        src_key = str(ftp.src_ip)
        if src_key not in self._by_src:
            self._by_src[src_key] = {
                "src_ip": ftp.src_ip,
                "failed_auth": 0,
                "success_auth": 0,
                "total_commands": 0,
                # Timestamps for rate computation
                "first_seen": ftp.timestamp,
                "last_seen": ftp.timestamp,
            }
        g = self._by_src[src_key]

        if ftp.timestamp:
            if g["first_seen"] is None or (ftp.timestamp and ftp.timestamp < g["first_seen"]):
                g["first_seen"] = ftp.timestamp
            if g["last_seen"] is None or (ftp.timestamp and ftp.timestamp > g["last_seen"]):
                g["last_seen"] = ftp.timestamp

        # Count commands (non-empty command means a command packet)
        if ftp.command:
            g["total_commands"] += 1
            # Auth attempts: USER command
            if ftp.command.upper() == "USER":
                pass  # will be resolved as success/failure by response
        # Auth result from response code
        if ftp.response_code is not None:
            if ftp.response_code == 230:
                g["success_auth"] += 1
            elif ftp.response_code == 530:
                g["failed_auth"] += 1

    def finalize(self) -> list[FTPFlow]:
        """Build sorted FTPFlow list."""
        results = []
        for g in self._by_src.values():
            duration = None
            if g["first_seen"] and g["last_seen"]:
                duration = (g["last_seen"] - g["first_seen"]).total_seconds()
            auth_rate = None
            if duration and duration > 0 and g["total_commands"] > 0:
                auth_rate = round((g["success_auth"] + g["failed_auth"]) / duration, 4)

            total_auth = g["failed_auth"] + g["success_auth"]
            failed_auth_ratio = round(g["failed_auth"] / total_auth, 4) if total_auth > 0 else 0.0

            results.append(
                FTPFlow(
                    src_ip=g["src_ip"],
                    failed_auth_count=g["failed_auth"],
                    success_auth_count=g["success_auth"],
                    total_commands=g["total_commands"],
                    auth_rate_per_second=auth_rate,
                    failed_auth_ratio=failed_auth_ratio,
                )
            )

        results.sort(key=lambda f: str(f.src_ip))
        return results
