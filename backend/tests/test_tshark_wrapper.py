"""Tests for the TsharkWrapper class."""

import pytest
import json
from pathlib import Path
from unittest.mock import patch, MagicMock, PropertyMock

from backend.protocol_parser.tshark_wrapper import TsharkWrapper, TsharkError, TsharkVersion


class TestTsharkVersion:
    """Tests for TsharkVersion dataclass."""

    def test_version_tuple(self):
        v = TsharkVersion(major=4, minor=2, patch=0, raw="TShark 4.2.0")
        assert v.version_tuple == (4, 2, 0)

    def test_version_string(self):
        v = TsharkVersion(major=4, minor=2, patch=0, raw="TShark 4.2.0")
        assert str(v) == "TShark 4.2.0"


class TestTsharkWrapperInit:
    """Tests for TsharkWrapper initialization."""

    @patch("shutil.which", return_value="/usr/bin/tshark")
    def test_init_defaults(self, mock_which):
        wrapper = TsharkWrapper()
        assert wrapper.tshark_path == "/usr/bin/tshark"
        assert wrapper.fields == TsharkWrapper.DEFAULT_FIELDS
        mock_which.assert_called_once_with("tshark")

    @patch("shutil.which", return_value="/usr/bin/tshark")
    def test_init_custom_path(self, mock_which):
        wrapper = TsharkWrapper(tshark_path="/custom/tshark")
        assert wrapper.tshark_path == "/custom/tshark"
        mock_which.assert_not_called()

    @patch("shutil.which", return_value=None)
    def test_init_tshark_not_found(self, mock_which):
        with pytest.raises(TsharkError, match="tshark not found in PATH"):
            TsharkWrapper()

    @patch("shutil.which", return_value="/usr/bin/tshark")
    def test_init_with_extra_fields(self, mock_which):
        extra = ["dns.qry.name", "http.host"]
        wrapper = TsharkWrapper(extra_fields=extra)
        for field in extra:
            assert field in wrapper.fields


class TestTsharkWrapperBuildCommand:
    """Tests for _build_command method."""

    @patch("shutil.which", return_value="/usr/bin/tshark")
    def test_basic_command(self, mock_which):
        wrapper = TsharkWrapper()
        cmd = wrapper._build_command("/tmp/test.pcap")
        assert cmd[0] == "/usr/bin/tshark"
        assert "-r" in cmd
        assert "/tmp/test.pcap" in cmd
        assert "-T" in cmd
        assert "json" in cmd

    @patch("shutil.which", return_value="/usr/bin/tshark")
    def test_command_with_display_filter(self, mock_which):
        wrapper = TsharkWrapper()
        cmd = wrapper._build_command("/tmp/test.pcap", display_filter="dns")
        assert "-Y" in cmd
        assert "dns" in cmd

    @patch("shutil.which", return_value="/usr/bin/tshark")
    def test_command_includes_fields(self, mock_which):
        wrapper = TsharkWrapper(fields=["frame.number", "ip.src"])
        cmd = wrapper._build_command("/tmp/test.pcap")
        # Each field adds -e and the field name
        e_positions = [i for i, x in enumerate(cmd) if x == "-e"]
        assert len(e_positions) == 2


class TestTsharkWrapperStreamPackets:
    """Tests for stream_packets with mocked subprocess."""

    @patch("shutil.which", return_value="/usr/bin/tshark")
    def test_file_not_found(self, mock_which, tmp_path):
        wrapper = TsharkWrapper()
        nonexistent = tmp_path / "nonexistent" / "file.pcap"
        with pytest.raises(TsharkError, match="PCAP file not found"):
            # Must iterate the generator to trigger the exists() check
            next(wrapper.stream_packets(str(nonexistent)))

    @patch("shutil.which", return_value="/usr/bin/tshark")
    def test_single_packet(self, mock_which, tmp_path):
        """Should yield a parsed packet from tshark JSON output."""
        pcap_file = tmp_path / "test.pcap"
        pcap_file.write_text("fake-pcap-data")

        wrapper = TsharkWrapper()

        # Mock the subprocess.Popen to return json data
        mock_process = MagicMock()
        mock_process.stdout = [
            "[\n",
            '  {"_source": {"layers": {"frame": {"frame.number": "1"}}}}\n',
            "]\n",
        ]
        mock_process.wait.return_value = 0
        mock_process.stderr = None

        with patch("subprocess.Popen", return_value=mock_process):
            packets = list(wrapper.stream_packets(str(pcap_file)))

        assert len(packets) == 1
        assert packets[0]["_source"]["layers"]["frame"]["frame.number"] == "1"

    @patch("shutil.which", return_value="/usr/bin/tshark")
    def test_multiple_packets(self, mock_which, tmp_path):
        """Should yield multiple packets."""
        pcap_file = tmp_path / "test.pcap"
        pcap_file.write_text("fake-pcap-data")

        wrapper = TsharkWrapper()

        mock_process = MagicMock()
        mock_process.stdout = iter(
            [
                "[\n",
                '  {"_source": {"frame": {"frame.number": "1"}}},\n',
                '  {"_source": {"frame": {"frame.number": "2"}}},\n',
                "]\n",
            ]
        )
        mock_process.wait.return_value = 0

        with patch("subprocess.Popen", return_value=mock_process):
            packets = list(wrapper.stream_packets(str(pcap_file)))

        assert len(packets) == 2

    @patch("shutil.which", return_value="/usr/bin/tshark")
    def test_tshark_error_exit(self, mock_which, tmp_path):
        """Should raise TsharkError when tshark exits nonzero."""
        pcap_file = tmp_path / "test.pcap"
        pcap_file.write_text("fake-pcap-data")

        wrapper = TsharkWrapper()

        mock_process = MagicMock()
        mock_process.stdout = iter([])
        mock_process.wait.return_value = 1
        mock_stderr = MagicMock()
        mock_stderr.read.return_value = "Error reading file"
        mock_process.stderr = mock_stderr

        with patch("subprocess.Popen", return_value=mock_process):
            with pytest.raises(TsharkError, match="tshark exited with code 1"):
                list(wrapper.stream_packets(str(pcap_file)))


class TestTsharkWrapperCountPackets:
    """Tests for count_packets method."""

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_count_packets(self, mock_run, mock_which):
        """Should return correct packet count."""
        mock_result = MagicMock()
        mock_result.stdout = "1\n2\n3\n4\n5\n"
        mock_result.returncode = 0
        mock_run.return_value = mock_result

        wrapper = TsharkWrapper()
        count = wrapper.count_packets("/tmp/test.pcap")
        assert count == 5
