"""Tshark wrapper for streaming JSON output from PCAP files.

This module provides a subprocess-based wrapper around tshark that streams
JSON output line-by-line for memory-efficient processing of large PCAP files.
"""

import json
import os
import shutil
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path


@dataclass
class TsharkVersion:
    """Parsed tshark version information."""

    major: int
    minor: int
    patch: int
    raw: str

    @property
    def version_tuple(self) -> tuple[int, int, int]:
        return (self.major, self.minor, self.patch)

    def __str__(self) -> str:
        return self.raw


class TsharkError(Exception):
    """Exception raised when tshark execution fails."""

    def __init__(self, message: str, return_code: int | None = None, stderr: str | None = None):
        super().__init__(message)
        self.return_code = return_code
        self.stderr = stderr


class TsharkWrapper:
    """Wrapper for tshark command-line tool with streaming JSON output."""

    # Layers to include in nested JSON output via tshark -j
    # This is MUCH more efficient than -e and preserves structure for parsers.
    DEFAULT_LAYERS = [
        "frame",
        "eth",
        "ip",
        "ipv6",
        "tcp",
        "udp",
        "icmp",
        "dns",
        "http",
        "ftp",
        "smtp",
    ]

    def __init__(
        self,
        tshark_path: str | None = None,
        layers: list[str] | None = None,
        extra_layers: list[str] | None = None,
    ):
        """Initialize the tshark wrapper.

        Args:
            tshark_path: Path to tshark executable. If None, searches PATH.
            layers: Custom layers to extract. If None, uses DEFAULT_LAYERS.
            extra_layers: Additional layers to append to default layers.
        """
        self.tshark_path = tshark_path or self._find_tshark()
        self.layers = layers or list(self.DEFAULT_LAYERS)
        if extra_layers:
            self.layers.extend(extra_layers)

    @staticmethod
    def _find_tshark() -> str:
        """Find tshark executable in PATH or environment."""
        # Check environment variable first
        env_path = os.environ.get("NETMIND_TSHARK_PATH")
        if env_path:
            if os.path.isfile(env_path):
                return env_path
            # If not a full path, maybe it's a name to look for in PATH
            path = shutil.which(env_path)
            if path:
                return path

        # Default fallback
        path = shutil.which("tshark")
        if not path:
            # Common Windows path as a last resort
            windows_path = "C:\\Program Files\\Wireshark\\tshark.exe"
            if os.name == "nt" and os.path.isfile(windows_path):
                return windows_path
            raise TsharkError("tshark not found in PATH. Please install Wireshark/tshark.")
        return path

    def get_version(self) -> TsharkVersion:
        """Get tshark version."""
        try:
            result = subprocess.run(
                [self.tshark_path, "-v"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                raise TsharkError(
                    f"tshark -v failed with code {result.returncode}",
                    return_code=result.returncode,
                    stderr=result.stderr,
                )

            # Parse version from output like "TShark (Wireshark) 4.2.0 (Git v4.2.0 packaged as 4.2.0-1)"
            import re

            match = re.search(r"(\d+)\.(\d+)\.(\d+)", result.stdout)
            if match:
                major, minor, patch = map(int, match.groups())
            else:
                major, minor, patch = 0, 0, 0

            return TsharkVersion(major, minor, patch, result.stdout.strip())
        except subprocess.TimeoutExpired as exc:
            raise TsharkError("tshark -v timed out") from exc
        except FileNotFoundError as exc:
            raise TsharkError("tshark executable not found") from exc

    def _build_command(
        self,
        pcap_path: str | Path,
        display_filter: str | None = None,
    ) -> list[str]:
        """Build tshark command for JSON streaming output."""
        cmd = [
            self.tshark_path,
            "-r",
            str(pcap_path),
            "-T",
            "json",
            "-n",  # No name resolution
            "-j",
            " ".join(self.layers),
        ]

        if display_filter:
            cmd.extend(["-Y", display_filter])

        return cmd

    def stream_packets(
        self,
        pcap_path: str | Path,
        display_filter: str | None = None,
    ) -> Iterator[dict]:
        """Stream packets from PCAP as JSON objects.

        Yields one packet dict at a time for memory-efficient processing.

        Args:
            pcap_path: Path to PCAP/PCAPNG file.
            display_filter: Optional Wireshark display filter.

        Yields:
            Parsed packet dictionaries from tshark JSON output.

        Raises:
            TsharkError: If tshark execution fails.
        """
        pcap_path = Path(pcap_path)
        if not pcap_path.exists():
            raise TsharkError(f"PCAP file not found: {pcap_path}")

        cmd = self._build_command(pcap_path, display_filter)

        process: subprocess.Popen | None = None
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1024 * 1024,
            )

            if process.stdout is None:
                raise TsharkError("Failed to open tshark stdout")

            # High-performance line-based parsing for tshark -T json.
            # Tshark JSON output format:
            # [
            #   { <--- Start of packet (depth 1)
            #     "layers": { ... }
            #   }, <--- End of packet
            #   ...
            # ]
            packet_buffer: list[str] = []
            in_packet = False
            brace_depth = 0

            for line in process.stdout:
                # Tshark uses 2-space indentation for packet objects in the array.
                stripped = line.strip()
                if not in_packet and stripped.startswith("{"):
                    in_packet = True
                    packet_buffer = [stripped.rstrip(",")]
                    brace_depth = stripped.count("{") - stripped.count("}")
                elif in_packet:
                    cleaned = stripped.rstrip(",")
                    packet_buffer.append(cleaned)
                    brace_depth += cleaned.count("{") - cleaned.count("}")

                if in_packet and brace_depth <= 0:
                    packet_str = "".join(packet_buffer)
                    try:
                        # Note: tshark -T json output can be HUGE, json.loads is fast
                        yield json.loads(packet_str)
                    except json.JSONDecodeError:
                        pass
                    in_packet = False
                    packet_buffer = []
                    brace_depth = 0

            # Wait for process to complete
            return_code = process.wait(timeout=30)
            if return_code != 0:
                stderr = process.stderr.read() if process.stderr else ""
                # Ignore return code 1 if it's just "End of file" or similar common tshark quirks
                if return_code != 1 or "End of file" not in stderr:
                    raise TsharkError(
                        f"tshark exited with code {return_code}",
                        return_code=return_code,
                        stderr=stderr,
                    )

        except subprocess.TimeoutExpired as exc:
            if process is not None:
                process.kill()
            raise TsharkError("tshark process timed_out") from exc
        except Exception as e:
            if isinstance(e, TsharkError):
                raise
            raise TsharkError(f"Failed to execute tshark: {e}") from e

    def count_packets(self, pcap_path: str | Path) -> int:
        """Count total packets in PCAP file quickly."""
        cmd = [self.tshark_path, "-r", str(pcap_path), "-T", "fields", "-e", "frame.number"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode != 0:
                raise TsharkError(
                    f"tshark packet count failed: {result.stderr}",
                    return_code=result.returncode,
                )
            # Count non-empty lines
            return len([line for line in result.stdout.strip().split("\n") if line.strip()])
        except subprocess.TimeoutExpired as exc:
            raise TsharkError("tshark packet count timed out") from exc

    def get_file_info(self, pcap_path: str | Path) -> dict:
        """Get basic file information using capinfos."""
        capinfos_path = shutil.which("capinfos")
        if not capinfos_path:
            # Fallback to tshark
            return self._get_file_info_tshark(pcap_path)

        cmd = [capinfos_path, "-T", "-u", "-c", "-d", "-r", "-s", str(pcap_path)]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                return self._get_file_info_tshark(pcap_path)

            # Parse tab-separated output
            lines = result.stdout.strip().split("\n")
            if len(lines) >= 2:
                headers = lines[0].split("\t")
                values = lines[1].split("\t")
                return dict(zip(headers, values, strict=False))
            return {}
        except Exception:
            return self._get_file_info_tshark(pcap_path)

    def _get_file_info_tshark(self, pcap_path: str | Path) -> dict:
        """Fallback file info using tshark."""
        cmd = [self.tshark_path, "-r", str(pcap_path), "-T", "json", "-c", "1"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                if data and isinstance(data, list) and len(data) > 0:
                    frame = data[0].get("_source", {}).get("layers", {}).get("frame", {})
                    return {
                        "frame.time_epoch": frame.get("frame.time_epoch"),
                        "frame.len": frame.get("frame.len"),
                    }
        except Exception:
            pass
        return {}
