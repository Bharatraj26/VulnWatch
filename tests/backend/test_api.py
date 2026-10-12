"""
VulnWatch Backend — Integration Tests (Flask + SQLite + Scanner)
================================================================
Automated integration tests verifying REST API routes, SQLite storage,
scan execution, and error handling.
"""

from __future__ import annotations

import email.message
import io
from unittest.mock import MagicMock, patch

import pypdf
import pytest
from app import create_app


@pytest.fixture
def app(tmp_path):
    """Create and configure a test Flask application with a temporary sqlite database file."""
    db_file = tmp_path / "test_vulnwatch.db"
    test_app = create_app(
        {
            "TESTING": True,
            "DATABASE_PATH": str(db_file),
            "CORS_ORIGINS": ["*"],
            "ALLOWED_TARGETS": ["localhost", "127.0.0.1", "::1"],
        }
    )
    return test_app


@pytest.fixture
def client(app):
    """A test client for the app."""
    return app.test_client()


def test_health_ok(client):
    """GET /api/health returns 200 with JSON {"status": "ok", "service": "VulnWatch API"}."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "ok"
    assert data["service"] == "VulnWatch API"


def test_scans_list_empty_initially(client):
    """GET /api/scans returns 200 with an empty list before any scans run."""
    response = client.get("/api/scans")
    assert response.status_code == 200
    data = response.get_json()
    assert isinstance(data, list)
    assert len(data) == 0


def test_create_scan_missing_target(client):
    """POST /api/scans with missing target_url returns 400."""
    response = client.post("/api/scans", json={})
    assert response.status_code == 400
    data = response.get_json()
    assert "target_url is required" in data["detail"].lower()


def test_create_scan_invalid_scan_type(client):
    """POST /api/scans with unrecognized scan_type returns 400."""
    response = client.post(
        "/api/scans",
        json={"target_url": "http://localhost:5000", "scan_type": "offensive_attack"},
    )
    assert response.status_code == 400
    data = response.get_json()
    assert "invalid scan_type" in data["detail"].lower()


def test_create_scan_prohibits_external_targets(client):
    """POST /api/scans rejects public third-party addresses."""
    response = client.post(
        "/api/scans",
        json={"target_url": "http://8.8.8.8:80", "scan_type": "basic"},
    )
    assert response.status_code == 400
    data = response.get_json()
    assert "target authorization error" in data["detail"].lower()


def test_create_scan_prohibits_cloud_metadata(client):
    """POST /api/scans rejects cloud metadata IP (169.254.169.254)."""
    response = client.post(
        "/api/scans",
        json={"target_url": "http://169.254.169.254", "scan_type": "basic"},
    )
    assert response.status_code == 400
    data = response.get_json()
    assert "target authorization error" in data["detail"].lower()


def test_create_and_retrieve_scan_with_persistence(client):
    """
    Simulates a successful scan against localhost using mock HTTP responses,
    verifying full persistence in SQLite across scans and reports endpoints.
    """
    mock_headers = email.message.EmailMessage()
    mock_headers["Server"] = "TestServer/1.0"
    mock_headers["Set-Cookie"] = "session=xyz123; HttpOnly"

    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.headers = mock_headers
    mock_response.__enter__.return_value = mock_response
    mock_response.__exit__.return_value = None

    mock_opener = MagicMock()
    mock_opener.open.return_value = mock_response

    with patch("urllib.request.build_opener", return_value=mock_opener):
        create_res = client.post(
            "/api/scans",
            json={"target_url": "http://localhost:5000", "scan_type": "basic"},
        )

    assert create_res.status_code == 201
    created_data = create_res.get_json()
    scan_id = created_data["id"]
    report_id = created_data["reportId"]
    assert scan_id.startswith("SCN-")
    assert report_id.startswith("RPT-")
    assert created_data["status"] == "completed"
    assert created_data["findings"] > 0
    assert 0 <= created_data["score"] <= 100

    # 1. Verify GET /api/scans lists the new scan
    list_res = client.get("/api/scans")
    assert list_res.status_code == 200
    scans_list = list_res.get_json()
    assert len(scans_list) == 1
    assert scans_list[0]["id"] == scan_id
    assert scans_list[0]["target"] == "http://localhost:5000/"

    # 2. Verify GET /api/scans/{scan_id} returns detailed scan with findings
    scan_res = client.get(f"/api/scans/{scan_id}")
    assert scan_res.status_code == 200
    scan_detail = scan_res.get_json()
    assert scan_detail["id"] == scan_id
    assert len(scan_detail["findingsList"]) > 0

    # 3. Verify GET /api/reports lists the report
    reports_res = client.get("/api/reports")
    assert reports_res.status_code == 200
    reports_list = reports_res.get_json()
    assert len(reports_list) == 1
    assert reports_list[0]["id"] == report_id
    assert reports_list[0]["scanId"] == scan_id

    # 4. Verify GET /api/reports/{scan_id} returns detailed report
    report_detail_res = client.get(f"/api/reports/{scan_id}")
    assert report_detail_res.status_code == 200
    report_detail = report_detail_res.get_json()
    assert report_detail["scanId"] == scan_id
    assert len(report_detail["findings_list"]) > 0
    assert "summary" in report_detail
    assert "securityScore" in report_detail

    # 5. Verify GET /api/scans/stats reflects current database counts
    stats_res = client.get("/api/scans/stats")
    assert stats_res.status_code == 200
    stats = stats_res.get_json()
    assert stats["totalScans"] == 1
    assert stats["vulnerabilitiesFound"] > 0
    assert stats["lastScan"] is not None


def test_scan_not_found(client):
    """GET /api/scans/SCN-unknown returns 404."""
    response = client.get("/api/scans/SCN-unknown")
    assert response.status_code == 404
    data = response.get_json()
    assert "not found" in data["detail"].lower()


def test_report_not_found(client):
    """GET /api/reports/RPT-unknown returns 404."""
    response = client.get("/api/reports/RPT-unknown")
    assert response.status_code == 404
    data = response.get_json()
    assert "not found" in data["detail"].lower()


# ─── Phase 3.1 Security Validation & Error Handling Tests ───────────────────


def test_create_scan_rejects_obfuscated_ips(client):
    """POST /api/scans rejects obfuscated IP formats."""
    # Dotted octal
    res1 = client.post("/api/scans", json={"target_url": "http://0177.0.0.1:8000"})
    assert res1.status_code == 400
    assert "prohibited ip format" in res1.get_json()["detail"].lower()

    # Hexadecimal
    res2 = client.post("/api/scans", json={"target_url": "http://0x7f000001:8000"})
    assert res2.status_code == 400
    assert "prohibited ip format" in res2.get_json()["detail"].lower()

    # DWORD / integer
    res3 = client.post("/api/scans", json={"target_url": "http://2130706433:8000"})
    assert res3.status_code == 400
    assert "prohibited ip format" in res3.get_json()["detail"].lower()


def test_create_scan_rejects_restricted_ports(client):
    """POST /api/scans rejects sensitive/restricted system service ports."""
    res1 = client.post("/api/scans", json={"target_url": "http://localhost:22"})
    assert res1.status_code == 400
    assert "restricted system service port" in res1.get_json()["detail"].lower()

    res2 = client.post("/api/scans", json={"target_url": "http://localhost:445"})
    assert res2.status_code == 400
    assert "restricted system service port" in res2.get_json()["detail"].lower()


def test_create_scan_ipv6_loopback_accepted(client):
    """POST /api/scans accepts properly formatted IPv6 loopback [::1]."""
    mock_headers = email.message.EmailMessage()
    mock_headers["Server"] = "IPv6Test/1.0"
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.headers = mock_headers
    mock_response.__enter__.return_value = mock_response
    mock_response.__exit__.return_value = None

    mock_opener = MagicMock()
    mock_opener.open.return_value = mock_response

    with patch("urllib.request.build_opener", return_value=mock_opener):
        res = client.post(
            "/api/scans",
            json={"target_url": "http://[::1]:8000", "scan_type": "basic"},
        )
    assert res.status_code == 201
    data = res.get_json()
    assert "[::1]" in data["target"]


def test_create_scan_database_error_rollback(client):
    """Database insertion failure triggers rollback and clean 500 error response."""
    import sqlite3

    mock_headers = email.message.EmailMessage()
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.headers = mock_headers
    mock_response.__enter__.return_value = mock_response
    mock_response.__exit__.return_value = None
    mock_opener = MagicMock()
    mock_opener.open.return_value = mock_response

    mock_db = MagicMock()
    mock_db.execute.side_effect = sqlite3.OperationalError("Simulated DB failure")

    with (
        patch("urllib.request.build_opener", return_value=mock_opener),
        patch("app.api.v1.endpoints.scans.get_db", return_value=mock_db),
    ):
        res = client.post(
            "/api/scans",
            json={"target_url": "http://localhost:5000", "scan_type": "basic"},
        )
    assert res.status_code == 500
    data = res.get_json()
    assert "failed to persist scan record" in data["detail"].lower()
    mock_db.rollback.assert_called_once()
    # Confirm no tracebacks or internal system details leaked
    assert "traceback" not in data["detail"].lower()


# ─── Report PDF & JSON Download Tests ────────────────────────────────────────


def test_download_report_pdf_success(client):
    """GET /api/reports/:id/pdf returns a valid binary PDF with appropriate headers."""
    mock_headers = email.message.EmailMessage()
    mock_headers["Server"] = "TestServer/2.0"
    mock_headers["Set-Cookie"] = "session=pdf_test_val; HttpOnly"

    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.headers = mock_headers
    mock_response.__enter__.return_value = mock_response
    mock_response.__exit__.return_value = None

    mock_opener = MagicMock()
    mock_opener.open.return_value = mock_response

    with patch("urllib.request.build_opener", return_value=mock_opener):
        create_res = client.post(
            "/api/scans",
            json={"target_url": "http://localhost:5000", "scan_type": "basic"},
        )
    assert create_res.status_code == 201
    created_payload = create_res.get_json()
    report_id = created_payload["reportId"]
    scan_id = created_payload["id"]

    # 1. Test dedicated /pdf endpoint
    pdf_res = client.get(f"/api/reports/{report_id}/pdf")
    assert pdf_res.status_code == 200
    assert "application/pdf" in pdf_res.content_type
    assert f"vulnwatch-report-{report_id}.pdf" in pdf_res.headers.get("Content-Disposition", "")
    assert pdf_res.data.startswith(b"%PDF-")
    assert len(pdf_res.data) > 1000

    # Parse and verify PDF structure and text using pypdf
    reader = pypdf.PdfReader(io.BytesIO(pdf_res.data))
    assert len(reader.pages) >= 1
    extracted_text = " ".join(p.extract_text() for p in reader.pages)
    assert report_id in extracted_text
    assert scan_id in extracted_text
    assert "http://localhost:5000/" in extracted_text
    assert "VulnWatch Security Assessment Report" in extracted_text

    # 2. Test download via scan ID
    pdf_scan_res = client.get(f"/api/reports/{scan_id}/pdf")
    assert pdf_scan_res.status_code == 200
    assert pdf_scan_res.data.startswith(b"%PDF-")

    # 3. Test direct .pdf route
    pdf_ext_res = client.get(f"/api/reports/{report_id}.pdf")
    assert pdf_ext_res.status_code == 200
    assert pdf_ext_res.data.startswith(b"%PDF-")

    # 4. Test unified /download endpoint (default PDF)
    dl_res = client.get(f"/api/reports/{report_id}/download")
    assert dl_res.status_code == 200
    assert "application/pdf" in dl_res.content_type
    assert dl_res.data.startswith(b"%PDF-")

    # 5. Test unified /download endpoint with ?format=json
    json_res = client.get(f"/api/reports/{report_id}/download?format=json")
    assert json_res.status_code == 200
    assert "application/json" in json_res.content_type
    json_data = json_res.get_json()
    assert json_data["id"] == report_id
    assert json_data["target"] == "http://localhost:5000/"
    assert "findings_list" in json_data


def test_download_report_pdf_nonexistent(client):
    """GET /api/reports/RPT-NONEXISTENT/pdf returns 404 JSON error."""
    res = client.get("/api/reports/RPT-NONEXISTENT/pdf")
    assert res.status_code == 404
    assert "application/json" in res.content_type
    data = res.get_json()
    assert "not found" in data["detail"].lower()



