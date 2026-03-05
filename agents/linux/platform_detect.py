from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Optional


OS_RELEASE_PATHS = [
    Path("/etc/os-release"),
    Path("/usr/lib/os-release"),  # fallback on some systems
]


@dataclass(frozen=True)
class PlatformInfo:
    """
    Normalized platform metadata for Linux endpoints.

    This class exists so the rest of the agent can remain distro-agnostic.
    Collectors read these fields and choose the correct commands.
    """
    os_type: str  # always "linux" for this agent
    distro_id: str  # e.g., "rhel", "ubuntu", "debian", "fedora"
    distro_like: List[str]  # parsed ID_LIKE as a list
    version_id: str  # e.g., "9.4", "22.04"
    pretty_name: str  # e.g., "Red Hat Enterprise Linux 9.4 (Plow)"

    # Normalized groupings we infer (for logic)
    family: str  # "rhel", "debian", or "unknown"
    pkg_manager: str  # "dnf", "yum", "apt", or "unknown"


def _read_os_release() -> dict:
    """
    Reads /etc/os-release (or /usr/lib/os-release) and returns key/value pairs.

    os-release is the standard way to identify Linux distributions.
    It is read-only and widely supported across modern distros.
    """
    content: Optional[str] = None
    for path in OS_RELEASE_PATHS:
        if path.exists():
            content = path.read_text(encoding="utf-8", errors="ignore")
            break

    if not content:
        return {}

    data: dict = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue

        k, v = line.split("=", 1)
        k = k.strip()
        v = v.strip().strip('"').strip("'")  # remove optional quotes
        data[k] = v

    return data


def _split_id_like(value: str) -> List[str]:
    """
    ID_LIKE can be space-separated: e.g., 'rhel fedora' or 'debian'.
    Normalize to a lowercase list.
    """
    if not value:
        return []
    return [token.strip().lower() for token in value.split() if token.strip()]


def _infer_family(distro_id: str, distro_like: List[str]) -> str:
    """
    Infer a coarse Linux 'family' to choose commands later.
    """
    candidates = [distro_id.lower()] + distro_like

    if any(x in candidates for x in ["rhel", "fedora", "centos", "rocky", "almalinux", "suse", "opensuse"]):
        # Note: SUSE is different, but we can treat it as non-debian for now.
        # We'll keep it under rhel-ish bucket for future extension or set to "unknown" if you prefer.
        if any(x in candidates for x in ["suse", "opensuse"]):
            return "unknown"
        return "rhel"

    if any(x in candidates for x in ["debian", "ubuntu", "linuxmint"]):
        return "debian"

    return "unknown"


def _infer_pkg_manager(family: str) -> str:
    """
    Choose the most likely package manager based on family.

    - RHEL family: prefer dnf (modern). yum exists as compatibility wrapper on many systems.
    - Debian family: apt.
    """
    if family == "rhel":
        return "dnf"
    if family == "debian":
        return "apt"
    return "unknown"


def detect_platform() -> dict:
    """
    Public function used by the Linux agent.

    Returns a JSON-serializable dict with normalized platform metadata.
    """
    osr = _read_os_release()

    distro_id = osr.get("ID", "unknown").lower()
    distro_like = _split_id_like(osr.get("ID_LIKE", ""))
    version_id = osr.get("VERSION_ID", "")
    pretty_name = osr.get("PRETTY_NAME", "")

    family = _infer_family(distro_id, distro_like)
    pkg_manager = _infer_pkg_manager(family)

    info = PlatformInfo(
        os_type="linux",
        distro_id=distro_id,
        distro_like=distro_like,
        version_id=version_id,
        pretty_name=pretty_name,
        family=family,
        pkg_manager=pkg_manager,
    )

    return asdict(info)