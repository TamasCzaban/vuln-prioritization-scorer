import hashlib
import streamlit as st


def _cache_key(cve_ids: list[str]) -> str:
    sorted_ids = sorted(set(cve_ids))
    return hashlib.md5(",".join(sorted_ids).encode()).hexdigest()


def get_cached(cve_ids: list[str]) -> dict | None:
    key = _cache_key(cve_ids)
    return st.session_state.get(f"nvd_cache_{key}")


def set_cached(cve_ids: list[str], data: dict):
    key = _cache_key(cve_ids)
    st.session_state[f"nvd_cache_{key}"] = data
