from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

from collector.security.cve.product_aliases import enrich_software_entry


REPO_ROOT = Path(__file__).resolve().parents[3]

SOFTWARE_SNAPSHOT_PATH = REPO_ROOT / "collector" / "output" / "software_snapshot" / "software_snapshot_latest.json"
CVE_OUTPUT_DIR = REPO_ROOT / "collector" / "output" / "cve_snapshot"
CVE_OUTPUT_PATH = CVE_OUTPUT_DIR / "cve_snapshot_latest.json"

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

MAX_CVES_PER_PRODUCT = 20
REQUEST_DELAY_SECONDS = 6
MAX_RETRIES = 2
RATE_LIMIT_STATUS_CODE = 429


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}

    try:
        with path.open("r", encoding="utf-8") as file:
            data = json.load(file)

        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=2)


def get_existing_product(existing_snapshot: dict[str, Any], normalized_name: str) -> dict[str, Any] | None:
    products = existing_snapshot.get("products", [])

    if not isinstance(products, list):
        return None

    for product in products:
        if not isinstance(product, dict):
            continue

        if product.get("normalized_name") == normalized_name:
            return product

    return None


def fetch_cves(candidate: dict[str, Any]) -> tuple[list[dict[str, Any]], str]:
    query = candidate.get("query")

    if not query:
        return [], "missing_query"

    params = {
        "keywordSearch": query,
        "resultsPerPage": MAX_CVES_PER_PRODUCT,
    }

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = requests.get(NVD_API_URL, params=params, timeout=30)

            if response.status_code == RATE_LIMIT_STATUS_CODE:
                wait_seconds = REQUEST_DELAY_SECONDS * attempt
                print(f"[CVE RATE LIMIT] {query}: waiting {wait_seconds} seconds before retry {attempt}.")
                time.sleep(wait_seconds)
                continue

            response.raise_for_status()
            data = response.json()

            if not isinstance(data, dict):
                return [], "invalid_response"

            vulnerabilities = data.get("vulnerabilities", [])

            if not isinstance(vulnerabilities, list):
                return [], "invalid_vulnerabilities"

            return vulnerabilities, "fetched"

        except Exception as error:
            print(f"[CVE FETCH ERROR] {query}: {error}")

            if attempt < MAX_RETRIES:
                time.sleep(REQUEST_DELAY_SECONDS * attempt)

    return [], "fetch_failed"


def get_cvss_from_metrics(metrics: Any) -> dict[str, Any]:
    if not isinstance(metrics, dict):
        return {
            "metric_type": None,
            "base_score": None,
            "base_severity": None,
            "vector_string": None,
        }

    metric_order = [
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ]

    for metric_name in metric_order:
        values = metrics.get(metric_name)

        if not isinstance(values, list) or not values:
            continue

        metric = values[0]

        if not isinstance(metric, dict):
            continue

        cvss_data = metric.get("cvssData", {})

        if not isinstance(cvss_data, dict):
            cvss_data = {}

        return {
            "metric_type": metric_name,
            "base_score": cvss_data.get("baseScore"),
            "base_severity": cvss_data.get("baseSeverity") or metric.get("baseSeverity"),
            "vector_string": cvss_data.get("vectorString"),
        }

    return {
        "metric_type": None,
        "base_score": None,
        "base_severity": None,
        "vector_string": None,
    }


def extract_english_description(cve: dict[str, Any]) -> str:
    descriptions = cve.get("descriptions", [])

    if not isinstance(descriptions, list):
        return ""

    for description in descriptions:
        if not isinstance(description, dict):
            continue

        if description.get("lang") == "en":
            return str(description.get("value", ""))

    return ""


def extract_references(cve: dict[str, Any]) -> list[str]:
    raw_references = cve.get("references", [])

    if isinstance(raw_references, dict):
        references = raw_references.get("referenceData", [])
    elif isinstance(raw_references, list):
        references = raw_references
    else:
        references = []

    if not isinstance(references, list):
        return []

    urls = []

    for reference in references[:5]:
        if not isinstance(reference, dict):
            continue

        url = reference.get("url")

        if url:
            urls.append(str(url))

    return urls


def extract_cve_info(vulnerability: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(vulnerability, dict):
        return {}

    cve = vulnerability.get("cve", {})

    if not isinstance(cve, dict):
        cve = {}

    metrics = cve.get("metrics", {})

    return {
        "cve_id": cve.get("id"),
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "vuln_status": cve.get("vulnStatus"),
        "description": extract_english_description(cve),
        "cvss": get_cvss_from_metrics(metrics),
        "references": extract_references(cve),
    }


def build_candidates(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    software = snapshot.get("software", [])

    if not isinstance(software, list):
        return []

    candidates = []

    for entry in software:
        if not isinstance(entry, dict):
            continue

        enriched = enrich_software_entry(entry)

        if enriched:
            candidates.append(enriched)

    return candidates


def build_product_result(
    candidate: dict[str, Any],
    cves: list[dict[str, Any]],
    fetch_status: str,
) -> dict[str, Any]:
    return {
        "normalized_name": candidate["normalized_name"],
        "vendor": candidate["vendor"],
        "product": candidate["product"],
        "query": candidate["query"],
        "cpe": candidate.get("cpe"),
        "category": candidate["category"],
        "versions_seen": candidate.get("versions_seen", []),
        "hosts_seen": candidate.get("hosts_seen", []),
        "raw_names": candidate.get("raw_names", []),
        "fetch_status": fetch_status,
        "cve_count": len(cves),
        "cves": cves,
    }


def update_cve_snapshot(
    software_snapshot_path: Path = SOFTWARE_SNAPSHOT_PATH,
    output_path: Path = CVE_OUTPUT_PATH,
) -> dict[str, Any]:
    if not software_snapshot_path.exists():
        return {
            "ok": False,
            "message": f"Software snapshot not found: {software_snapshot_path}",
            "software_snapshot_path": str(software_snapshot_path),
            "output_path": str(output_path),
        }

    snapshot = load_json(software_snapshot_path)
    existing_snapshot = load_json(output_path)
    candidates = build_candidates(snapshot)

    products = []
    total_cves = 0
    fetched_products = 0
    reused_products = 0
    failed_products = 0

    for index, candidate in enumerate(candidates):
        if index > 0:
            time.sleep(REQUEST_DELAY_SECONDS)

        vulnerabilities, fetch_status = fetch_cves(candidate)

        cves = []

        for vulnerability in vulnerabilities:
            cve_info = extract_cve_info(vulnerability)

            if cve_info.get("cve_id"):
                cves.append(cve_info)

        if fetch_status != "fetched":
            existing_product = get_existing_product(existing_snapshot, candidate["normalized_name"])

            if existing_product:
                existing_cves = existing_product.get("cves", [])

                if isinstance(existing_cves, list):
                    cves = existing_cves
                    fetch_status = f"reused_existing_after_{fetch_status}"
                    reused_products += 1
                else:
                    failed_products += 1
            else:
                failed_products += 1
        else:
            fetched_products += 1

        product_result = build_product_result(candidate, cves, fetch_status)
        total_cves += len(cves)
        products.append(product_result)

    output = {
        "generated_at": utc_now().isoformat(),
        "source_snapshot": str(software_snapshot_path),
        "source_snapshot_generated_at": snapshot.get("generated_at"),
        "retrieval_method": "nvd_keyword_search_with_local_reuse",
        "max_cves_per_product": MAX_CVES_PER_PRODUCT,
        "request_delay_seconds": REQUEST_DELAY_SECONDS,
        "max_retries": MAX_RETRIES,
        "total_software": snapshot.get("software_count", 0),
        "total_candidates": len(candidates),
        "total_products": len(products),
        "fetched_products": fetched_products,
        "reused_products": reused_products,
        "failed_products": failed_products,
        "total_cves": total_cves,
        "products": products,
    }

    existing_total_cves = existing_snapshot.get("total_cves", 0)

    if isinstance(existing_total_cves, int) and existing_total_cves > total_cves and failed_products > 0:
        backup_path = output_path.with_name("cve_snapshot_failed_attempt.json")
        write_json(backup_path, output)

        return {
            "ok": False,
            "message": (
                "CVE update produced fewer records than the existing snapshot because some products failed. "
                "Existing snapshot was preserved."
            ),
            "software_snapshot_path": str(software_snapshot_path),
            "output_path": str(output_path),
            "failed_attempt_path": str(backup_path),
            "existing_total_cves": existing_total_cves,
            "new_total_cves": total_cves,
            "total_products": len(products),
            "fetched_products": fetched_products,
            "reused_products": reused_products,
            "failed_products": failed_products,
        }

    write_json(output_path, output)

    return {
        "ok": True,
        "message": f"CVE snapshot created for {len(products)} products with {total_cves} CVE record(s).",
        "software_snapshot_path": str(software_snapshot_path),
        "output_path": str(output_path),
        "total_products": len(products),
        "total_cves": total_cves,
        "fetched_products": fetched_products,
        "reused_products": reused_products,
        "failed_products": failed_products,
    }