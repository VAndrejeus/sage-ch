import subprocess

def _run(cmd):
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=20,
        encoding="utf-8",
        errors="ignore"
    )
    return result.stdout

def collect():
    output = _run(["vssadmin", "list", "shadows"])

    has_shadow = "Shadow Copy ID" in output

    return {
        "shadow_copies_present": has_shadow,
        "raw": output
    }