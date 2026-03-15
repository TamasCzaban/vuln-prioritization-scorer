DEFAULT_WEIGHTS = {
    "cvss": 0.35,
    "epss": 0.30,
    "exposure": 0.20,
    "age": 0.15,
}

TIER_DEFAULTS = {
    "internet-facing": 1.0,
    "critical-infra": 0.9,
    "unknown": 0.6,
    "internal": 0.5,
}

PRIORITY_BANDS = [
    ("Critical", 0.75),
    ("High", 0.55),
    ("Medium", 0.35),
    ("Low", 0.0),
]

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_BASE_URL = "https://api.first.org/data/1.0/epss"
NVD_RATE_DELAY_NO_KEY = 6.5
NVD_RATE_DELAY_WITH_KEY = 0.6
EPSS_CHUNK_SIZE = 500
