import pytest
from unittest.mock import patch, MagicMock
from api.nvd_client import NVDClient

NVD_FIXTURE = {
    "vulnerabilities": [{
        "cve": {
            "id": "CVE-2021-44228",
            "published": "2021-11-26T00:00:00.000",
            "metrics": {
                "cvssMetricV31": [{
                    "cvssData": {"baseScore": 10.0}
                }]
            }
        }
    }]
}


def test_fetch_cve_success():
    client = NVDClient()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = NVD_FIXTURE

    with patch("api.nvd_client.requests.get", return_value=mock_resp):
        with patch.object(client, "_rate_limit"):
            result = client.fetch_cve("CVE-2021-44228")

    assert result["cvss_v3"] == 10.0
    assert result["published_date"] == "2021-11-26T00:00:00.000"
    assert result["error"] is None


def test_fetch_cve_404():
    client = NVDClient()
    mock_resp = MagicMock()
    mock_resp.status_code = 404

    with patch("api.nvd_client.requests.get", return_value=mock_resp):
        with patch.object(client, "_rate_limit"):
            result = client.fetch_cve("CVE-9999-99999")

    assert result["cvss_v3"] is None
    assert result["error"] == "not_found"
