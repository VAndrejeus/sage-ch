import platform


def detect_os():
    system = platform.system().lower()

    if "windows" in system:
        return {
            "host_os": "windows",
            "agent_options": [
                {
                    "label": "Windows Agent",
                    "value": "windows_agent"
                }
            ]
        }

    if "linux" in system:
        return {
            "host_os": "linux",
            "agent_options": [
                {
                    "label": "Linux Agent",
                    "value": "linux_agent"
                }
            ]
        }

    return {
        "host_os": "unknown",
        "agent_options": []
    }