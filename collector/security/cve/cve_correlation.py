from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[3]

CVE_SNAPSHOT_PATH = REPO_ROOT / "collector" / "output" / "cve_snapshot" / "cve_snapshot_latest.json"
CVE_FINDINGS_OUTPUT_DIR = REPO_ROOT / "collector" / "output" / "cve_findings"
CVE_FINDINGS_OUTPUT_PATH = CVE_FINDINGS_OUTPUT_DIR / "cve_findings_latest.json"

TOP_CVES_PER_PRODUCT = 3
MIN_CVSS_SCORE = 7.0
MAX_CVE_AGE_YEARS = 10


SEVERITY_RANK = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "UNKNOWN": 0,
}


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


def normalize_severity(value: Any) -> str:
    if not value:
        return "Unknown"

    severity = str(value).strip().upper()

    if severity in SEVERITY_RANK:
        return severity.title()

    return "Unknown"


def get_severity_rank(severity: str) -> int:
    return SEVERITY_RANK.get(severity.upper(), 0)


def get_cvss_score(cve: dict[str, Any]) -> float:
    cvss = cve.get("cvss", {})

    if not isinstance(cvss, dict):
        return 0.0

    score = cvss.get("base_score")

    try:
        return float(score)
    except (TypeError, ValueError):
        return 0.0


def get_cvss_severity(cve: dict[str, Any]) -> str:
    cvss = cve.get("cvss", {})

    if not isinstance(cvss, dict):
        return "Unknown"

    return normalize_severity(cvss.get("base_severity"))


def parse_datetime(value: Any) -> datetime | None:
    if not value:
        return None

    text = str(value).strip()

    if not text:
        return None

    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        pass

    formats = [
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d",
    ]

    for date_format in formats:
        try:
            parsed = datetime.strptime(text, date_format)
            return parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            continue

    return None


def is_recent_cve(cve: dict[str, Any]) -> bool:
    published = parse_datetime(cve.get("published"))

    if not published:
        return False

    if published.tzinfo is None:
        published = published.replace(tzinfo=timezone.utc)

    cutoff_year = utc_now().year - MAX_CVE_AGE_YEARS
    cutoff = datetime(cutoff_year, 1, 1, tzinfo=timezone.utc)

    return published >= cutoff


def is_high_signal_cve(cve: dict[str, Any]) -> bool:
    return get_cvss_score(cve) >= MIN_CVSS_SCORE and is_recent_cve(cve)


def sort_cves_by_risk(cves: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        cves,
        key=lambda cve: (
            get_severity_rank(get_cvss_severity(cve)),
            get_cvss_score(cve),
            str(cve.get("published", "")),
        ),
        reverse=True,
    )


def build_finding_id(hostname: str, product: str, cve_id: str) -> str:
    safe_hostname = hostname.lower().replace(" ", "_")
    safe_product = product.lower().replace(" ", "_")
    safe_cve = cve_id.lower().replace("-", "_")
    return f"cve_{safe_hostname}_{safe_product}_{safe_cve}"


def build_recommendation(product_name: str, raw_names: list[Any]) -> str:
    installed_name = ""

    if raw_names:
        installed_name = str(raw_names[0])

    if installed_name:
        return (
            f"Review and update {installed_name} to the latest vendor-supported version. "
            "Validate whether the listed CVE applies to the installed version before remediation. "
            "If the product is not required, remove it from the endpoint."
        )

    return (
        f"Review and update {product_name} to the latest vendor-supported version. "
        "Validate whether the listed CVE applies to the installed version before remediation. "
        "If the product is not required, remove it from the endpoint."
    )


def build_ai_explanation(product_name: str, cve: dict[str, Any]) -> str:
    cve_id = cve.get("cve_id", "Unknown CVE")
    severity = get_cvss_severity(cve)
    score = get_cvss_score(cve)
    published = cve.get("published", "unknown publication date")

    return (
        f"{cve_id} was correlated with installed software identified as {product_name}. "
        f"The vulnerability is rated {severity} with a CVSS score of {score} and was published on {published}. "
        "This finding passed the current SAGE-CH CVE signal filter because it is recent enough and meets the minimum CVSS threshold. "
        "Version-specific applicability should still be confirmed before final remediation."
    )


def build_finding(
    hostname: str,
    product_entry: dict[str, Any],
    cve: dict[str, Any],
) -> dict[str, Any]:
    product_name = str(product_entry.get("query") or product_entry.get("product") or "Unknown product")
    product = str(product_entry.get("product") or product_name)
    vendor = str(product_entry.get("vendor") or "unknown")
    category = str(product_entry.get("category") or "application")
    cve_id = str(cve.get("cve_id") or "Unknown CVE")
    severity = get_cvss_severity(cve)
    cvss_score = get_cvss_score(cve)
    description = str(cve.get("description") or "")
    references = cve.get("references", [])

    if not isinstance(references, list):
        references = []

    raw_names = product_entry.get("raw_names", [])
    versions_seen = product_entry.get("versions_seen", [])

    if not isinstance(raw_names, list):
        raw_names = []

    if not isinstance(versions_seen, list):
        versions_seen = []

    return {
        "finding_id": build_finding_id(hostname, product, cve_id),
        "hostname": hostname,
        "title": f"{cve_id} correlated with {product_name}",
        "severity": severity,
        "category": "Vulnerability",
        "status": "Open",
        "source": "CVE Correlation",
        "cis_control": "CIS Control 7: Continuous Vulnerability Management",
        "product": product,
        "vendor": vendor,
        "software_name": product_name,
        "software_category": category,
        "installed_versions": versions_seen,
        "raw_software_names": raw_names,
        "cve_id": cve_id,
        "cvss_score": cvss_score,
        "cvss_severity": severity,
        "published": cve.get("published"),
        "last_modified": cve.get("last_modified"),
        "vuln_status": cve.get("vuln_status"),
        "description": description,
        "recommendation": build_recommendation(product_name, raw_names),
        "ai_explanation": build_ai_explanation(product_name, cve),
        "references": references[:5],
    }


def build_findings_from_product(product_entry: dict[str, Any]) -> tuple[list[dict[str, Any]], int, int]:
    hosts_seen = product_entry.get("hosts_seen", [])
    cves = product_entry.get("cves", [])

    if not isinstance(hosts_seen, list):
        hosts_seen = []

    if not isinstance(cves, list):
        cves = []

    valid_cves = [cve for cve in cves if isinstance(cve, dict)]
    filtered_cves = [cve for cve in valid_cves if is_high_signal_cve(cve)]
    ranked_cves = sort_cves_by_risk(filtered_cves)
    selected_cves = ranked_cves[:TOP_CVES_PER_PRODUCT]

    findings = []

    for hostname in hosts_seen:
        hostname_text = str(hostname).strip()

        if not hostname_text:
            continue

        for cve in selected_cves:
            findings.append(build_finding(hostname_text, product_entry, cve))

    return findings, len(valid_cves), len(filtered_cves)


def correlate_cves_to_findings(
    cve_snapshot_path: Path = CVE_SNAPSHOT_PATH,
    output_path: Path = CVE_FINDINGS_OUTPUT_PATH,
) -> dict[str, Any]:
    if not cve_snapshot_path.exists():
        return {
            "ok": False,
            "message": f"CVE snapshot not found: {cve_snapshot_path}",
            "cve_snapshot_path": str(cve_snapshot_path),
            "output_path": str(output_path),
        }

    snapshot = load_json(cve_snapshot_path)
    products = snapshot.get("products", [])

    if not isinstance(products, list):
        products = []

    findings = []
    total_cves_evaluated = 0
    total_cves_after_filter = 0
    products_with_findings = 0

    for product_entry in products:
        if not isinstance(product_entry, dict):
            continue

        product_findings, evaluated_count, filtered_count = build_findings_from_product(product_entry)

        total_cves_evaluated += evaluated_count
        total_cves_after_filter += filtered_count

        if product_findings:
            products_with_findings += 1

        findings.extend(product_findings)

    output = {
        "generated_at": utc_now().isoformat(),
        "source_snapshot": str(cve_snapshot_path),
        "source_snapshot_generated_at": snapshot.get("generated_at"),
        "correlation_method": "software_presence_top_recent_high_cvss_cves",
        "top_cves_per_product": TOP_CVES_PER_PRODUCT,
        "min_cvss_score": MIN_CVSS_SCORE,
        "max_cve_age_years": MAX_CVE_AGE_YEARS,
        "total_products": len(products),
        "products_with_findings": products_with_findings,
        "total_cves_evaluated": total_cves_evaluated,
        "total_cves_after_filter": total_cves_after_filter,
        "total_findings": len(findings),
        "findings": findings,
    }

    write_json(output_path, output)

    return {
        "ok": True,
        "message": f"CVE correlation created {len(findings)} high-signal finding(s).",
        "cve_snapshot_path": str(cve_snapshot_path),
        "output_path": str(output_path),
        "total_products": len(products),
        "products_with_findings": products_with_findings,
        "total_cves_evaluated": total_cves_evaluated,
        "total_cves_after_filter": total_cves_after_filter,
        "total_findings": len(findings),
    }