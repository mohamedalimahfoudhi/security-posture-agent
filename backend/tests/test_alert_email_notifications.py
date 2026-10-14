"""
Tests for the email alert notification system.

Tests the email_service.py (active Resend/SMTP path) and sender.py (Resend path
called from vulnerability_applicability.py).

Uses mocks for:
- Database calls (no real DB required)
- Resend API (no real email sent)
- SMTP (no real email sent)
"""
import os
import pytest
from unittest.mock import MagicMock, patch, call
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_alert_from_alerts_table():
    """Alert dict matching the `alerts` table schema."""
    return {
        "id": 42,
        "customer_id": 1,
        "risk_level": "HIGH",
        "title": "PostgreSQL 14.2 critical RCE vulnerability",
        "asset_technology": "PostgreSQL 14.2",
        "asset_vendor": "PostgreSQL Global Development Group",
        "business_impact": "Sensitive data exposure and potential data breach.",
        "recommendation": "Apply PostgreSQL patch CVE-2026-50334 immediately.",
        "escalation_recommendation": "ESCALATE_SOON",
        "ai_summary": "Unauthenticated remote code execution via buffer overflow.",
        "event_id": None,
        "created_at": "2026-08-31T10:00:00",
    }


@pytest.fixture
def sample_alert_from_third_party():
    """Alert dict matching the `third_party_alerts` table schema."""
    return {
        "id": 99,
        "customer_id": 1,
        "severity": "CRITICAL",
        "alert_type": "vulnerability",
        "vendor": "Microsoft",
        "affected_technology": "Azure DevOps",
        "business_relevance": "Critical supply chain exposure.",
        "recommended_action": "Rotate credentials and apply patch.",
        "cve_id": "CVE-2026-50334",
        "risk_score": 95,
        "status": "OPEN",
    }


@pytest.fixture
def sample_recipient():
    return {"id": 1, "name": "Security Team", "email": "sec@example.com", "customer_id": 1}


# ---------------------------------------------------------------------------
# Helper: build_html_email (no DB, no network)
# ---------------------------------------------------------------------------

class TestBuildHtmlEmail:
    def _import(self):
        from app.notifications.email_service import build_html_email
        return build_html_email

    def test_subject_with_vendor_technology_cve(self):
        build_html_email = self._import()
        alert = {"severity": "CRITICAL", "vendor": "Microsoft", "affected_technology": "Azure DevOps", "cve_id": "CVE-2026-50334"}
        subject, _ = build_html_email(alert)
        assert "CRITICAL" in subject
        assert "Microsoft" in subject
        assert "Azure DevOps" in subject
        assert "CVE-2026-50334" in subject

    def test_subject_vendor_and_technology_no_cve(self):
        build_html_email = self._import()
        alert = {"risk_level": "HIGH", "asset_vendor": "PostgreSQL Global Development Group", "asset_technology": "PostgreSQL 14.2"}
        subject, _ = build_html_email(alert)
        assert "HIGH" in subject
        assert "PostgreSQL" in subject
        assert "None" not in subject

    def test_subject_fallback_vendor_only(self):
        build_html_email = self._import()
        alert = {"risk_level": "HIGH", "asset_vendor": "Acme Corp"}
        subject, _ = build_html_email(alert)
        assert "HIGH" in subject
        assert "Acme Corp" in subject
        assert "None" not in subject

    def test_subject_empty_fields_fallback(self):
        build_html_email = self._import()
        alert = {"risk_level": "MEDIUM"}
        subject, _ = build_html_email(alert)
        assert "MEDIUM" in subject
        assert "None" not in subject
        assert "None by None" not in subject

    def test_html_body_no_none_strings(self, sample_alert_from_alerts_table):
        build_html_email = self._import()
        _, html = build_html_email(sample_alert_from_alerts_table)
        assert ">None<" not in html
        assert "None by None" not in html
        assert "Vendor: None" not in html
        assert "Technology: None" not in html

    def test_html_body_contains_real_vendor(self, sample_alert_from_alerts_table):
        build_html_email = self._import()
        _, html = build_html_email(sample_alert_from_alerts_table)
        assert "PostgreSQL Global Development Group" in html

    def test_html_body_contains_real_technology(self, sample_alert_from_alerts_table):
        build_html_email = self._import()
        _, html = build_html_email(sample_alert_from_alerts_table)
        assert "PostgreSQL 14.2" in html

    def test_html_body_contains_real_business_impact(self, sample_alert_from_alerts_table):
        build_html_email = self._import()
        _, html = build_html_email(sample_alert_from_alerts_table)
        assert "Sensitive data exposure" in html

    def test_html_body_contains_cve_when_present(self, sample_alert_from_third_party):
        build_html_email = self._import()
        _, html = build_html_email(sample_alert_from_third_party)
        assert "CVE-2026-50334" in html

    def test_html_body_no_cve_row_when_absent(self, sample_alert_from_alerts_table):
        build_html_email = self._import()
        _, html = build_html_email(sample_alert_from_alerts_table)
        # cve_id not in alert, so "CVE:" row should not appear
        assert "CVE:" not in html or "Not specified" not in html  # or simply verify no garbage

    def test_third_party_alert_subject(self, sample_alert_from_third_party):
        build_html_email = self._import()
        subject, _ = build_html_email(sample_alert_from_third_party)
        assert "CRITICAL" in subject
        assert "Microsoft" in subject
        assert "CVE-2026-50334" in subject
        assert "None" not in subject


# ---------------------------------------------------------------------------
# EmailService configuration
# ---------------------------------------------------------------------------

class TestEmailServiceConfiguration:
    def test_resend_enabled_when_key_set(self):
        with patch.dict(os.environ, {"RESEND_API_KEY": "re_test_key", "RESEND_FROM": "from@example.com"}):
            from app.notifications.email_service import EmailService
            svc = EmailService()
            assert svc.is_enabled() is True
            assert svc._use_resend is True

    def test_smtp_fallback_when_resend_not_set(self):
        env = {"RESEND_API_KEY": "", "SMTP_HOST": "smtp.example.com",
               "SMTP_USER": "u", "SMTP_PASSWORD": "p"}
        with patch.dict(os.environ, env):
            from app.notifications.email_service import EmailService
            svc = EmailService()
            assert svc.is_enabled() is True
            assert svc._use_resend is False
            assert svc._use_smtp is True

    def test_disabled_when_no_transport(self):
        env = {"RESEND_API_KEY": "", "SMTP_HOST": "", "SMTP_USER": "", "SMTP_PASSWORD": ""}
        with patch.dict(os.environ, env):
            from app.notifications.email_service import EmailService
            svc = EmailService()
            assert svc.is_enabled() is False

    def test_get_email_service_returns_singleton(self):
        # Reset singleton first
        import app.notifications.email_service as mod
        mod._email_service = None
        from app.notifications.email_service import get_email_service
        svc1 = get_email_service()
        svc2 = get_email_service()
        assert svc1 is svc2


# ---------------------------------------------------------------------------
# EmailService.send_alert_notification — Resend path
# ---------------------------------------------------------------------------

class TestEmailServiceResendPath:
    def _make_service(self):
        with patch.dict(os.environ, {"RESEND_API_KEY": "re_test", "RESEND_FROM": "from@test.com"}):
            from app.notifications.email_service import EmailService
            return EmailService()

    def _mock_recipients(self, service, recipients):
        service._get_recipients_for_customer = MagicMock(return_value=recipients)

    def _mock_no_duplicate(self, service):
        service._check_notification_exists = MagicMock(return_value=False)

    def _mock_is_duplicate(self, service):
        service._check_notification_exists = MagicMock(return_value=True)

    def _mock_create_record(self, service):
        service._create_notification_record = MagicMock(return_value=1)

    def test_send_succeeds_via_resend(self, sample_alert_from_alerts_table, sample_recipient):
        svc = self._make_service()
        self._mock_recipients(svc, [sample_recipient])
        self._mock_no_duplicate(svc)
        self._mock_create_record(svc)

        with patch.object(svc, "_send_via_resend", return_value=(True, None)) as mock_send:
            result = svc.send_alert_notification(sample_alert_from_alerts_table)

        assert result["notifications_sent"] == 1
        assert result["notifications_failed"] == 0
        mock_send.assert_called_once()

    def test_send_skipped_when_no_recipients(self, sample_alert_from_alerts_table):
        svc = self._make_service()
        svc._get_recipients_for_customer = MagicMock(return_value=[])
        result = svc.send_alert_notification(sample_alert_from_alerts_table)
        assert result["notifications_sent"] == 0
        assert result["recipients_count"] == 0

    def test_duplicate_skipped(self, sample_alert_from_alerts_table, sample_recipient):
        svc = self._make_service()
        self._mock_recipients(svc, [sample_recipient])
        self._mock_is_duplicate(svc)

        with patch.object(svc, "_send_via_resend") as mock_send:
            result = svc.send_alert_notification(sample_alert_from_alerts_table)

        mock_send.assert_not_called()
        assert result["notifications_sent"] == 0
        assert "Duplicate" in result.get("message", "")

    def test_failure_recorded_alert_survives(self, sample_alert_from_alerts_table, sample_recipient):
        """Email failure must NOT destroy the alert — it returns a result dict, not an exception."""
        svc = self._make_service()
        self._mock_recipients(svc, [sample_recipient])
        self._mock_no_duplicate(svc)
        self._mock_create_record(svc)

        with patch.object(svc, "_send_via_resend", return_value=(False, "Resend API error 500")):
            result = svc.send_alert_notification(sample_alert_from_alerts_table)

        # Alert survives: function returns cleanly (no exception)
        assert result["success"] is True
        assert result["notifications_failed"] == 1
        assert result["notifications_sent"] == 0

    def test_failure_reason_stored(self, sample_alert_from_alerts_table, sample_recipient):
        svc = self._make_service()
        self._mock_recipients(svc, [sample_recipient])
        self._mock_no_duplicate(svc)
        created_records = []

        def capture_record(**kwargs):
            created_records.append(kwargs)
            return 99

        svc._create_notification_record = MagicMock(side_effect=capture_record)

        with patch.object(svc, "_send_via_resend", return_value=(False, "timeout error")):
            svc.send_alert_notification(sample_alert_from_alerts_table)

        assert any(r.get("failure_reason") == "timeout error" for r in created_records)

    def test_no_email_sent_when_disabled(self, sample_alert_from_alerts_table):
        env = {"RESEND_API_KEY": "", "SMTP_HOST": "", "SMTP_USER": "", "SMTP_PASSWORD": ""}
        with patch.dict(os.environ, env):
            from app.notifications.email_service import EmailService
            svc = EmailService()
            svc._get_recipients_for_customer = MagicMock(return_value=[
                {"id": 1, "name": "X", "email": "x@x.com", "customer_id": 1}
            ])
            result = svc.send_alert_notification(sample_alert_from_alerts_table)
        assert result["notifications_sent"] == 0
        assert "No email transport" in result.get("message", "")

    def test_missing_alert_id_returns_error(self):
        svc = self._make_service()
        result = svc.send_alert_notification({"customer_id": 1})  # no id
        assert result["success"] is False

    def test_missing_customer_id_returns_error(self):
        svc = self._make_service()
        result = svc.send_alert_notification({"id": 1})  # no customer_id
        assert result["success"] is False


# ---------------------------------------------------------------------------
# Duplicate protection
# ---------------------------------------------------------------------------

class TestDuplicateProtection:
    def test_check_notification_exists_false_when_none(self):
        from app.notifications.email_service import EmailService
        svc = EmailService()
        with patch("app.notifications.email_service.get_connection") as mock_conn:
            mock_cur = MagicMock()
            mock_cur.fetchone.return_value = None
            mock_conn.return_value.__enter__ = MagicMock(return_value=mock_conn.return_value)
            mock_conn.return_value.cursor.return_value.__enter__ = MagicMock(return_value=mock_cur)
            mock_conn.return_value.cursor.return_value = mock_cur

            result = svc._check_notification_exists(1, "x@x.com", "new_alert")

        assert result is False

    def test_check_notification_exists_true_when_row_found(self):
        from app.notifications.email_service import EmailService
        svc = EmailService()
        with patch("app.notifications.email_service.get_connection") as mock_conn:
            mock_cur = MagicMock()
            mock_cur.fetchone.return_value = (1,)
            mock_conn.return_value.cursor.return_value = mock_cur

            result = svc._check_notification_exists(1, "x@x.com", "new_alert")

        assert result is True


# ---------------------------------------------------------------------------
# Tenant isolation
# ---------------------------------------------------------------------------

class TestTenantIsolation:
    def test_recipients_queried_by_customer_id(self, sample_alert_from_alerts_table):
        with patch.dict(os.environ, {"RESEND_API_KEY": "re_test"}):
            from app.notifications.email_service import EmailService
            svc = EmailService()

        called_with = []

        def fake_get_recipients(customer_id):
            called_with.append(customer_id)
            return []

        svc._get_recipients_for_customer = fake_get_recipients
        svc.send_alert_notification(sample_alert_from_alerts_table)
        assert called_with == [1], "Must query recipients for customer_id=1 only"

    def test_different_customer_cannot_see_other_recipients(self):
        with patch.dict(os.environ, {"RESEND_API_KEY": "re_test"}):
            from app.notifications.email_service import EmailService
            svc = EmailService()

        # Simulate: customer 2's alert only queries customer 2's recipients
        queried_ids = []
        svc._get_recipients_for_customer = lambda cid: (queried_ids.append(cid) or [])
        svc.send_alert_notification({"id": 100, "customer_id": 2, "risk_level": "HIGH"})
        assert queried_ids == [2]


# ---------------------------------------------------------------------------
# Data enrichment (sender.py enrich_alert_data)
# ---------------------------------------------------------------------------

class TestEnrichAlertData:
    def test_enriches_vendor_from_alerts_table(self):
        """Vendor from asset_vendor column is surfaced as 'vendor' key."""
        from app.notifications.sender import enrich_alert_data

        db_alert = MagicMock()
        db_alert.__getitem__ = lambda self, k: {
            "id": 4, "title": "Alert Title", "asset_vendor": "PostgreSQL",
            "asset_technology": "PostgreSQL 14.2", "business_impact": "Data breach risk.",
            "recommendation": "Patch immediately.", "escalation_recommendation": "ESCALATE_SOON",
            "ai_summary": "RCE via buffer overflow.", "event_id": None,
        }.get(k)
        db_alert.get = lambda k, d=None: {
            "id": 4, "title": "Alert Title", "asset_vendor": "PostgreSQL",
            "asset_technology": "PostgreSQL 14.2", "business_impact": "Data breach risk.",
            "recommendation": "Patch immediately.", "escalation_recommendation": "ESCALATE_SOON",
            "ai_summary": "RCE via buffer overflow.", "event_id": None,
        }.get(k, d)

        with patch("app.notifications.sender.get_connection") as mock_conn:
            mock_cur = MagicMock()
            # First call: alerts table → returns db_alert
            # Second call: third_party_alerts → returns None
            mock_cur.fetchone.side_effect = [db_alert, None]
            mock_conn.return_value.cursor.return_value = mock_cur

            result = enrich_alert_data(4, {"risk_level": "HIGH"})

        assert result.get("vendor") == "PostgreSQL"
        assert result.get("affected_technology") == "PostgreSQL 14.2"

    def test_enriches_cve_from_third_party_alerts(self):
        """CVE ID is set when third_party_alerts has it."""
        from app.notifications.sender import enrich_alert_data

        tp_data = {
            "cve_id": "CVE-2026-50334",
            "vendor": "MSFT",
            "affected_technology": "Azure",
            "threat_event_id": None,
            "business_relevance": "High risk.",
            "recommended_action": "Patch now.",
        }

        # Use a real dict-like object so .get() returns actual strings
        class DictRow(dict):
            pass

        tp_row = DictRow(tp_data)

        with patch("app.notifications.sender.get_connection") as mock_conn:
            mock_cur = MagicMock()
            mock_cur.fetchone.side_effect = [None, tp_row]  # no alerts row, tp_alert row
            mock_conn.return_value.cursor.return_value = mock_cur

            result = enrich_alert_data(99, {"risk_level": "CRITICAL"})

        assert result.get("cve_id") == "CVE-2026-50334"


    def test_no_none_strings_in_enriched_output(self):
        """After enrichment, 'None' string values are replaced by 'Not specified'."""
        from app.notifications.sender import enrich_alert_data

        db_alert = MagicMock()
        db_alert.get = lambda k, d=None: {
            "title": "Alert", "asset_vendor": None, "asset_technology": None,
            "business_impact": None, "recommendation": None,
            "escalation_recommendation": None, "ai_summary": None, "event_id": None,
        }.get(k, d)

        with patch("app.notifications.sender.get_connection") as mock_conn:
            mock_cur = MagicMock()
            mock_cur.fetchone.side_effect = [db_alert, None]
            mock_conn.return_value.cursor.return_value = mock_cur

            result = enrich_alert_data(1, {"risk_level": "HIGH"})

        for key, value in result.items():
            assert value != "None", f"Field '{key}' must not be the string 'None'"


# ---------------------------------------------------------------------------
# sender.py duplicate protection (notification_drafts table)
# ---------------------------------------------------------------------------

class TestSenderDuplicateProtection:
    def test_check_notification_exists_returns_false(self):
        from app.notifications.sender import check_notification_exists
        with patch("app.notifications.sender.get_connection") as mock_conn:
            mock_cur = MagicMock()
            mock_cur.fetchone.return_value = None
            mock_conn.return_value.cursor.return_value = mock_cur
            result = check_notification_exists(1, "x@x.com")
        assert result is False

    def test_check_notification_exists_returns_true(self):
        from app.notifications.sender import check_notification_exists
        with patch("app.notifications.sender.get_connection") as mock_conn:
            mock_cur = MagicMock()
            mock_cur.fetchone.return_value = {"id": 5}
            mock_conn.return_value.cursor.return_value = mock_cur
            result = check_notification_exists(1, "x@x.com")
        assert result is True


# ---------------------------------------------------------------------------
# generator.py severity gate
# ---------------------------------------------------------------------------

class TestNotificationGenerator:
    def test_low_severity_skipped(self):
        from app.notifications.generator import generate_and_send_notification
        result = generate_and_send_notification(1, {"risk_level": "LOW"})
        assert result is None

    def test_medium_severity_skipped(self):
        from app.notifications.generator import generate_and_send_notification
        result = generate_and_send_notification(1, {"risk_level": "MEDIUM"})
        assert result is None

    def test_high_severity_processed(self):
        from app.notifications.generator import generate_and_send_notification
        with patch("app.notifications.email_service.EmailService.send_alert_notification", return_value={"notifications_sent": 1, "results": [{"recipient": "a@a.com"}]}) as mock_send:
            result = generate_and_send_notification(99, {"risk_level": "HIGH"})
        mock_send.assert_called_once()
        assert result is not None
        assert result.get("status") == "sent"

    def test_critical_severity_processed(self):
        from app.notifications.generator import generate_and_send_notification
        with patch("app.notifications.email_service.EmailService.send_alert_notification", return_value={"notifications_sent": 1, "results": [{"recipient": "a@a.com"}]}) as mock_send:
            result = generate_and_send_notification(99, {"risk_level": "CRITICAL"})
        mock_send.assert_called_once()
        assert result is not None
        assert result.get("status") == "sent"

    def test_exception_does_not_raise(self):
        """Generator must never let an email failure surface as an uncaught exception."""
        from app.notifications.generator import generate_and_send_notification
        with patch("app.notifications.email_service.EmailService.send_alert_notification", side_effect=RuntimeError("network error")):
            result = generate_and_send_notification(99, {"risk_level": "HIGH"})
        assert result is not None
        assert result.get("status") == "error"

