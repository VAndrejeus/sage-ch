def _build_host_node(host):
    return {
        "id": host.get("host_id", "unknown-host"),
        "type": "host",
        "label": host.get("hostname", "unknown"),
        "os_name": host.get("os_name", "unknown"),
        "platform": host.get("source_os", "unknown")
    }


def _build_software_node(software_id, software):
    return {
        "id": software_id,
        "type": "software",
        "label": software.get("name", "unknown-software")
    }


def _build_software_edge(host_id, software_id, software):
    return {
        "source": host_id,
        "target": software_id,
        "type": "installed",
        "version": software.get("version"),
        "arch": software.get("arch")
    }


def _get_update_status_label(host):
    updates_available = host.get("update_status", {}).get("updates_available")

    if updates_available is True:
        return "updates-available"
    elif updates_available is False:
        return "up-to-date"
    return "unknown"


def _build_update_status_node(update_status_id, update_status_label):
    return {
        "id": update_status_id,
        "type": "update_status",
        "label": update_status_label
    }


def _build_update_status_edge(host_id, update_status_id):
    return {
        "source": host_id,
        "target": update_status_id,
        "type": "has_update_status"
    }


def _build_software_id(software):
    software_name = software.get("name", "unknown-software").lower()
    software_slug = software_name.replace(" ", "-")
    return f"software-{software_slug}"


def build_graph(hosts):
    nodes = []
    edges = []
    software_node_ids = set()
    update_status_node_ids = set()

    for host in hosts:
        host_id = host.get("host_id", "unknown-host")
        host_node = _build_host_node(host)
        nodes.append(host_node)

        for software in host.get("software", []):
            software_id = _build_software_id(software)

            if software_id not in software_node_ids:
                software_node = _build_software_node(software_id, software)
                nodes.append(software_node)
                software_node_ids.add(software_id)

            software_edge = _build_software_edge(host_id, software_id, software)
            edges.append(software_edge)

        update_status_label = _get_update_status_label(host)
        update_status_id = f"update-status-{update_status_label}"

        if update_status_id not in update_status_node_ids:
            update_status_node = _build_update_status_node(update_status_id, update_status_label)
            nodes.append(update_status_node)
            update_status_node_ids.add(update_status_id)

        update_status_edge = _build_update_status_edge(host_id, update_status_id)
        edges.append(update_status_edge)

    return {
        "nodes": nodes,
        "edges": edges
    }