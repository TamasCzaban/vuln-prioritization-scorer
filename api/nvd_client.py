import time
import requests
from config import NVD_BASE_URL, NVD_RATE_DELAY_NO_KEY, NVD_RATE_DELAY_WITH_KEY


class NVDClient:
    def __init__(self, api_key: str = None):
        self.api_key = api_key
        self._last_request = 0.0
        self._delay = NVD_RATE_DELAY_WITH_KEY if api_key else NVD_RATE_DELAY_NO_KEY

    def _rate_limit(self):
        elapsed = time.monotonic() - self._last_request
        if elapsed < self._delay:
            time.sleep(self._delay - elapsed)
        self._last_request = time.monotonic()

    def fetch_cve(self, cve_id: str) -> dict:
        """Returns {'cvss_v3': float|None, 'published_date': str|None}"""
        self._rate_limit()
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        try:
            resp = requests.get(NVD_BASE_URL, params={"cveId": cve_id}, headers=headers, timeout=15)
            if resp.status_code == 404:
                return {"cvss_v3": None, "published_date": None, "error": "not_found"}
            resp.raise_for_status()
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return {"cvss_v3": None, "published_date": None, "error": "not_found"}
            cve_data = vulns[0]["cve"]
            published = cve_data.get("published")
            cvss_v3 = None
            metrics = cve_data.get("metrics", {})
            for key in ["cvssMetricV31", "cvssMetricV30"]:
                if key in metrics and metrics[key]:
                    cvss_v3 = metrics[key][0]["cvssData"]["baseScore"]
                    break
            return {"cvss_v3": cvss_v3, "published_date": published, "error": None}
        except requests.exceptions.Timeout:
            return {"cvss_v3": None, "published_date": None, "error": "timeout"}
        except Exception as e:
            return {"cvss_v3": None, "published_date": None, "error": str(e)}

    def fetch_batch(self, cve_ids: list[str], progress_callback=None) -> dict[str, dict]:
        """Fetch all CVEs with optional progress callback(current, total)."""
        results = {}
        total = len(cve_ids)
        for i, cve_id in enumerate(cve_ids):
            results[cve_id] = self.fetch_cve(cve_id)
            if progress_callback:
                progress_callback(i + 1, total)
        return results
