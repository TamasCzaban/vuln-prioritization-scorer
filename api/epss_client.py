import requests
from config import EPSS_BASE_URL, EPSS_CHUNK_SIZE


class EPSSClient:
    def fetch(self, cve_ids: list[str]) -> dict[str, float]:
        """Returns {cve_id: epss_probability} for all CVEs."""
        results = {}
        chunks = [cve_ids[i:i + EPSS_CHUNK_SIZE] for i in range(0, len(cve_ids), EPSS_CHUNK_SIZE)]
        for chunk in chunks:
            params = {"cve": ",".join(chunk)}
            try:
                resp = requests.get(EPSS_BASE_URL, params=params, timeout=30)
                resp.raise_for_status()
                data = resp.json()
                for item in data.get("data", []):
                    results[item["cve"].upper()] = float(item["epss"])
            except Exception:
                pass  # graceful degradation
        return results
