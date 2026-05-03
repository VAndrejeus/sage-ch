from __future__ import annotations

from typing import Any


PRODUCT_ALIASES: dict[str, dict[str, Any]] = {
    "adobe acrobat": {
        "vendor": "adobe",
        "product": "acrobat",
        "query": "Adobe Acrobat",
        "cpe": "cpe:2.3:a:adobe:acrobat:*:*:*:*:*:*:*:*",
        "category": "application",
    },
    "adobe acrobat xi pro": {
        "vendor": "adobe",
        "product": "acrobat",
        "query": "Adobe Acrobat XI",
        "cpe": "cpe:2.3:a:adobe:acrobat:*:*:*:*:*:*:*:*",
        "category": "application",
    },
    "adobe creative cloud": {
        "vendor": "adobe",
        "product": "creative_cloud",
        "query": "Adobe Creative Cloud",
        "cpe": "cpe:2.3:a:adobe:creative_cloud:*:*:*:*:*:*:*:*",
        "category": "application",
    },
    "adobe dreamweaver 2021": {
        "vendor": "adobe",
        "product": "dreamweaver",
        "query": "Adobe Dreamweaver",
        "cpe": "cpe:2.3:a:adobe:dreamweaver:*:*:*:*:*:*:*:*",
        "category": "application",
    },
    "adobe illustrator 2025": {
        "vendor": "adobe",
        "product": "illustrator",
        "query": "Adobe Illustrator",
        "cpe": "cpe:2.3:a:adobe:illustrator:*:*:*:*:*:*:*:*",
        "category": "application",
    },
    "adobe photoshop 2025": {
        "vendor": "adobe",
        "product": "photoshop",
        "query": "Adobe Photoshop",
        "cpe": "cpe:2.3:a:adobe:photoshop:*:*:*:*:*:*:*:*",
        "category": "application",
    },
    "aida64 extreme v7.50": {
        "vendor": "finalwire",
        "product": "aida64",
        "query": "AIDA64",
        "cpe": "cpe:2.3:a:finalwire:aida64:*:*:*:*:*:*:*:*",
        "category": "application",
    },
    "bash": {
        "vendor": "gnu",
        "product": "bash",
        "query": "GNU Bash",
        "cpe": "cpe:2.3:a:gnu:bash:*:*:*:*:*:*:*:*",
        "category": "system_package",
    },
    "cisco packet tracer 9.0.0 64bit": {
        "vendor": "cisco",
        "product": "packet_tracer",
        "query": "Cisco Packet Tracer",
        "cpe": "cpe:2.3:a:cisco:packet_tracer:*:*:*:*:*:*:*:*",
        "category": "application",
    },
    "cpuid cpu-z msi 2.11": {
        "vendor": "cpuid",
        "product": "cpu-z",
        "query": "CPU-Z",
        "cpe": "cpe:2.3:a:cpuid:cpu-z:*:*:*:*:*:*:*:*",
        "category": "application",
    },
    "cups": {
        "vendor": "openprinting",
        "product": "cups",
        "query": "CUPS",
        "cpe": "cpe:2.3:a:openprinting:cups:*:*:*:*:*:*:*:*",
        "category": "system_package",
    },
    "curl": {
        "vendor": "haxx",
        "product": "curl",
        "query": "curl",
        "cpe": "cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*",
        "category": "system_package",
    },
    "git": {
        "vendor": "git-scm",
        "product": "git",
        "query": "Git",
        "cpe": "cpe:2.3:a:git-scm:git:*:*:*:*:*:*:*:*",
        "category": "developer_tool",
    },
    "mysql server": {
        "vendor": "oracle",
        "product": "mysql",
        "query": "MySQL Server",
        "cpe": "cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*",
        "category": "database",
    },
    "mysql workbench": {
        "vendor": "oracle",
        "product": "mysql_workbench",
        "query": "MySQL Workbench",
        "cpe": "cpe:2.3:a:oracle:mysql_workbench:*:*:*:*:*:*:*:*",
        "category": "developer_tool",
    },
    "notepad++": {
        "vendor": "notepad-plus-plus",
        "product": "notepad++",
        "query": "Notepad++",
        "cpe": "cpe:2.3:a:notepad-plus-plus:notepad\\+\\+:*:*:*:*:*:*:*:*",
        "category": "application",
    },
    "openssl": {
        "vendor": "openssl",
        "product": "openssl",
        "query": "OpenSSL",
        "cpe": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
        "category": "system_package",
    },
    "python": {
        "vendor": "python",
        "product": "python",
        "query": "Python",
        "cpe": "cpe:2.3:a:python:python:*:*:*:*:*:*:*:*",
        "category": "runtime",
    },
    "vlc": {
        "vendor": "videolan",
        "product": "vlc_media_player",
        "query": "VLC media player",
        "cpe": "cpe:2.3:a:videolan:vlc_media_player:*:*:*:*:*:*:*:*",
        "category": "application",
    },
    "winrar": {
        "vendor": "rarlab",
        "product": "winrar",
        "query": "WinRAR",
        "cpe": "cpe:2.3:a:rarlab:winrar:*:*:*:*:*:*:*:*",
        "category": "application",
    },
}


IGNORE_PREFIXES = (
    "default-fonts-",
    "dejavu-",
    "adobe-mappings-",
)

IGNORE_SUFFIXES = (
    "-firmware",
    "-fonts",
    "-libs",
    "-license",
    "-filesystem",
    "-common",
    "-data",
    "-docs",
)

IGNORE_EXACT = {
    "alternatives",
    "basesystem",
    "ca-certificates",
    "color-filesystem",
}


def should_ignore_product(normalized_name: str) -> bool:
    name = normalized_name.strip().lower()

    if name in IGNORE_EXACT:
        return True

    if any(name.startswith(prefix) for prefix in IGNORE_PREFIXES):
        return True

    if any(name.endswith(suffix) for suffix in IGNORE_SUFFIXES):
        return True

    return False


def get_product_alias(normalized_name: str) -> dict[str, Any] | None:
    name = normalized_name.strip().lower()

    if should_ignore_product(name):
        return None

    return PRODUCT_ALIASES.get(name)


def enrich_software_entry(entry: dict[str, Any]) -> dict[str, Any] | None:
    normalized_name = str(entry.get("normalized_name", "")).strip().lower()

    if not normalized_name:
        return None

    alias = get_product_alias(normalized_name)

    if not alias:
        return None

    return {
        "normalized_name": normalized_name,
        "raw_names": entry.get("raw_names", []),
        "versions_seen": entry.get("versions_seen", []),
        "hosts_seen": entry.get("hosts_seen", []),
        "source_files": entry.get("source_files", []),
        "vendor": alias["vendor"],
        "product": alias["product"],
        "query": alias["query"],
        "cpe": alias["cpe"],
        "category": alias["category"],
    }