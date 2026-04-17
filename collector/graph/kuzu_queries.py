from __future__ import annotations

NODE_COUNTS_BY_TYPE_QUERY = """
MATCH (n:GraphNode)
RETURN
    n.type AS node_type,
    COUNT(n) AS node_count
ORDER BY node_count DESC, node_type ASC;
"""

EDGE_COUNTS_BY_TYPE_QUERY = """
MATCH (e:GraphEdge)
RETURN
    e.type AS edge_type,
    COUNT(e) AS edge_count
ORDER BY edge_count DESC, edge_type ASC;
"""

ACTIVE_HOSTS_QUERY = """
MATCH (n:GraphNode)
WHERE n.type = 'Host' AND n.is_active = true
RETURN
    n.id AS host_id,
    n.label AS hostname,
    n.status AS status,
    n.first_seen AS first_seen,
    n.last_seen AS last_seen,
    n.last_run_id AS last_run_id
ORDER BY hostname ASC;
"""

ACTIVE_ASSETS_QUERY = """
MATCH (n:GraphNode)
WHERE n.type = 'Asset' AND n.is_active = true
RETURN
    n.id AS asset_id,
    n.label AS asset_label,
    n.status AS status,
    n.first_seen AS first_seen,
    n.last_seen AS last_seen,
    n.last_run_id AS last_run_id
ORDER BY asset_label ASC;
"""

NODE_BY_ID_QUERY = """
MATCH (n:GraphNode {id: $node_id})
RETURN
    n.id AS id,
    n.type AS type,
    n.label AS label,
    n.original_type AS original_type,
    n.semantic_type AS semantic_type,
    n.properties_json AS properties_json,
    n.first_seen AS first_seen,
    n.last_seen AS last_seen,
    n.last_run_id AS last_run_id,
    n.is_active AS is_active,
    n.status AS status;
"""

EDGE_BY_ID_QUERY = """
MATCH (e:GraphEdge {id: $edge_id})
RETURN
    e.id AS id,
    e.source_id AS source_id,
    e.target_id AS target_id,
    e.type AS type,
    e.original_type AS original_type,
    e.semantic_type AS semantic_type,
    e.properties_json AS properties_json,
    e.first_seen AS first_seen,
    e.last_seen AS last_seen,
    e.last_run_id AS last_run_id,
    e.is_active AS is_active,
    e.status AS status;
"""

HOST_SOFTWARE_QUERY = """
MATCH (host:GraphNode {id: $host_id})
MATCH (e:GraphEdge)-[:EDGE_SOURCE]->(host)
MATCH (e)-[:EDGE_TARGET]->(sw:GraphNode)
WHERE e.type = 'HAS_SOFTWARE' AND sw.type = 'Software'
RETURN
    host.id AS host_id,
    host.label AS hostname,
    sw.id AS software_id,
    sw.label AS software_name,
    e.id AS edge_id,
    e.last_seen AS last_seen,
    e.status AS edge_status
ORDER BY software_name ASC;
"""

HOST_SERVICES_QUERY = """
MATCH (host:GraphNode {id: $host_id})
MATCH (e:GraphEdge)-[:EDGE_SOURCE]->(host)
MATCH (e)-[:EDGE_TARGET]->(svc:GraphNode)
WHERE e.type = 'EXPOSES_SERVICE' AND svc.type = 'Service'
RETURN
    host.id AS host_id,
    host.label AS hostname,
    svc.id AS service_id,
    svc.label AS service_name,
    e.id AS edge_id,
    e.properties_json AS edge_properties_json,
    e.last_seen AS last_seen,
    e.status AS edge_status
ORDER BY service_name ASC;
"""

HOST_NEIGHBORS_QUERY = """
MATCH (host:GraphNode {id: $host_id})
MATCH (e:GraphEdge)-[:EDGE_SOURCE]->(host)
MATCH (e)-[:EDGE_TARGET]->(target:GraphNode)
RETURN
    e.id AS edge_id,
    e.type AS edge_type,
    target.id AS target_id,
    target.type AS target_type,
    target.label AS target_label,
    e.status AS edge_status
ORDER BY edge_type ASC, target_type ASC, target_label ASC;
"""

RECENT_NODE_OBSERVATIONS_QUERY = """
MATCH (o:NodeObservation)-[:OBSERVATION_OF_NODE]->(n:GraphNode {id: $node_id})
RETURN
    o.id AS observation_id,
    o.node_id AS node_id,
    o.observed_at AS observed_at,
    o.run_id AS run_id,
    o.type AS type,
    o.label AS label,
    o.properties_json AS properties_json
ORDER BY observed_at DESC;
"""

RECENT_EDGE_OBSERVATIONS_QUERY = """
MATCH (o:EdgeObservation)-[:OBSERVATION_OF_EDGE]->(e:GraphEdge {id: $edge_id})
RETURN
    o.id AS observation_id,
    o.edge_id AS edge_id,
    o.observed_at AS observed_at,
    o.run_id AS run_id,
    o.source_id AS source_id,
    o.target_id AS target_id,
    o.type AS type,
    o.properties_json AS properties_json
ORDER BY observed_at DESC;
"""

INACTIVE_NODES_QUERY = """
MATCH (n:GraphNode)
WHERE n.is_active = false
RETURN
    n.id AS node_id,
    n.type AS node_type,
    n.label AS label,
    n.status AS status,
    n.last_seen AS last_seen,
    n.last_run_id AS last_run_id
ORDER BY last_seen DESC, label ASC;
"""

INACTIVE_EDGES_QUERY = """
MATCH (e:GraphEdge)
WHERE e.is_active = false
RETURN
    e.id AS edge_id,
    e.type AS edge_type,
    e.source_id AS source_id,
    e.target_id AS target_id,
    e.status AS status,
    e.last_seen AS last_seen,
    e.last_run_id AS last_run_id
ORDER BY last_seen DESC, edge_type ASC;
"""