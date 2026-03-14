def build_graph(hosts):
    nodes = []
    edges = []
    software_node_ids = set()

    for host in hosts:
        node = {
            "id": host["host_id"],
            "type": "host",
            "label": host["hostname"],
            "os_name": host["os_name"],
            "platform": host["source_os"]
        }
        nodes.append(node)
        for software in host["software"]:
            software_name = software["name"].lower()
            software_slug = software_name.replace(" ", "-")
            software_id = f"software-{software_slug}"

            if software_id not in software_node_ids:
                software_node = {
                    "id": software_id,
                    "type": "software",
                    "label": software["name"]
                }
                nodes.append(software_node)
                software_node_ids.add(software_id)
            edge = {
                "source": host["host_id"],
                "target": software_id,
                "type": "installed",
                "version": software["version"],
                "arch": software["arch"]
            }
            edges.append(edge)

    return {
        "nodes": nodes,
        "edges": edges
    }