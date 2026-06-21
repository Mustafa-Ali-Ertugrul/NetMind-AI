"""Tests for SMTPSummaryBuilder."""


from backend.feature_extractor.smtp_summary import SMTPSummaryBuilder

from .fixtures import make_parsed_smtp


class TestSMTPSummaryBuilder:
    """Tests for SMTP session aggregation."""

    def test_empty(self):
        sb = SMTPSummaryBuilder()
        flows = sb.finalize()
        assert flows == []

    def test_single_message(self):
        sb = SMTPSummaryBuilder()
        sb.add_smtp(
            make_parsed_smtp(
                command="MAIL",
                argument="FROM:<a@b.com>",
                mail_from="a@b.com",
            )
        )
        flows = sb.finalize()
        assert len(flows) == 1
        assert flows[0].message_count == 1

    def test_multiple_recipients(self):
        sb = SMTPSummaryBuilder()
        sb.add_smtp(
            make_parsed_smtp(
                command="RCPT",
                rcpt_to=["user1@example.com"],
            )
        )
        sb.add_smtp(
            make_parsed_smtp(
                command="RCPT",
                rcpt_to=["user2@example.com"],
            )
        )
        flows = sb.finalize()
        assert flows[0].unique_recipients == 2

    def test_failed_auth(self):
        sb = SMTPSummaryBuilder()
        sb.add_smtp(make_parsed_smtp(command="AUTH", response_code=535))
        flows = sb.finalize()
        assert flows[0].failed_auth_count == 1

    def test_multiple_src_ips(self):
        sb = SMTPSummaryBuilder()
        sb.add_smtp(make_parsed_smtp(src_ip="10.0.0.1", command="MAIL"))
        sb.add_smtp(make_parsed_smtp(src_ip="10.0.0.2", command="MAIL"))
        flows = sb.finalize()
        assert len(flows) == 2
