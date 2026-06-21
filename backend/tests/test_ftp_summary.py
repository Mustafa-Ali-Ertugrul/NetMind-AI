"""Tests for FTPSummaryBuilder."""


from backend.feature_extractor.ftp_summary import FTPSummaryBuilder

from .fixtures import make_parsed_ftp


class TestFTPSummaryBuilder:
    """Tests for FTP session aggregation."""

    def test_empty(self):
        fb = FTPSummaryBuilder()
        flows = fb.finalize()
        assert flows == []

    def test_single_command(self):
        fb = FTPSummaryBuilder()
        fb.add_ftp(make_parsed_ftp(command="USER", argument="anonymous"))
        flows = fb.finalize()
        assert len(flows) == 1
        assert flows[0].src_ip.packed == make_parsed_ftp().src_ip.packed
        assert flows[0].total_commands == 1

    def test_auth_success(self):
        fb = FTPSummaryBuilder()
        fb.add_ftp(make_parsed_ftp(command="USER", argument="test"))
        fb.add_ftp(make_parsed_ftp(command="", response_code=230))
        flows = fb.finalize()
        assert flows[0].success_auth_count == 1
        assert flows[0].failed_auth_count == 0

    def test_auth_failure(self):
        fb = FTPSummaryBuilder()
        fb.add_ftp(make_parsed_ftp(command="USER", argument="bad"))
        fb.add_ftp(make_parsed_ftp(command="", response_code=530))
        flows = fb.finalize()
        assert flows[0].failed_auth_count == 1
        assert flows[0].success_auth_count == 0

    def test_multiple_src_ips(self):
        fb = FTPSummaryBuilder()
        fb.add_ftp(make_parsed_ftp(src_ip="10.0.0.1", command="USER"))
        fb.add_ftp(make_parsed_ftp(src_ip="10.0.0.2", command="USER"))
        flows = fb.finalize()
        assert len(flows) == 2

    def test_failed_auth_ratio_mixed(self):
        """Should compute ratio of failed auth to total auth attempts."""
        fb = FTPSummaryBuilder()
        fb.add_ftp(make_parsed_ftp(command="USER", argument="test"))
        fb.add_ftp(make_parsed_ftp(command="", response_code=230))  # success
        fb.add_ftp(make_parsed_ftp(command="USER", argument="bad"))
        fb.add_ftp(make_parsed_ftp(command="", response_code=530))  # failure
        flows = fb.finalize()
        assert flows[0].failed_auth_count == 1
        assert flows[0].success_auth_count == 1
        assert flows[0].failed_auth_ratio == 0.5

    def test_failed_auth_ratio_no_attempts(self):
        """No auth attempts should give ratio 0.0."""
        fb = FTPSummaryBuilder()
        fb.add_ftp(make_parsed_ftp(command="PWD"))
        flows = fb.finalize()
        assert flows[0].failed_auth_ratio == 0.0

    def test_failed_auth_ratio_all_failed(self):
        """All failed auth should give ratio 1.0."""
        fb = FTPSummaryBuilder()
        for _ in range(3):
            fb.add_ftp(make_parsed_ftp(command="USER", argument="bad"))
            fb.add_ftp(make_parsed_ftp(command="", response_code=530))
        flows = fb.finalize()
        assert flows[0].failed_auth_ratio == 1.0
