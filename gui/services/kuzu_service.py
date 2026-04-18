from __future__ import annotations

from pathlib import Path
from typing import Any

import pandas as pd


def _connect(db_path: Path):
    try:
        import kuzu
    except Exception as exc:
        return None, f"kuzu import failed: {exc}"

    try:
        db = kuzu.Database(str(db_path))
        conn = kuzu.Connection(db)
        return conn, None
    except Exception as exc:
        return None, str(exc)


def _query_df(conn: Any, query: str, params: dict | None = None) -> pd.DataFrame:
    try:
        result = conn.execute(query, params or {})
        if hasattr(result, "get_as_df"):
            return result.get_as_df()
        rows = []
        while result.has_next():
            rows.append(result.get_next())
        return pd.DataFrame(rows)
    except Exception:
        return pd.DataFrame()


def get_kuzu_graph_counts(db_path: Path) -> dict:
    result = {
        "ok": False,
        "node_counts": {},
        "edge_counts": {},
        "error": None,
    }

    if not db_path.exists():
        result["error"] = f"DB not found: {db_path}"
        return result

    conn, error = _connect(db_path)
    if error:
        result["error"] = error
        return result

    node_df = _query_df(
        conn,
        """
        MATCH (n:GraphNode)
        RETURN
            n.type AS node_type,
            COUNT(n) AS node_count
        ORDER BY node_count DESC, node_type ASC;
        """,
    )

    edge_df = _query_df(
        conn,
        """
        MATCH (e:GraphEdge)
        RETURN
            e.type AS edge_type,
            COUNT(e) AS edge_count
        ORDER BY edge_count DESC, edge_type ASC;
        """,
    )

    node_counts: dict[str, int] = {}
    edge_counts: dict[str, int] = {}

    if not node_df.empty:
        for _, row in node_df.iterrows():
            node_counts[str(row["node_type"])] = int(row["node_count"])

    if not edge_df.empty:
        for _, row in edge_df.iterrows():
            edge_counts[str(row["edge_type"])] = int(row["edge_count"])

    result["ok"] = bool(node_counts or edge_counts)
    result["node_counts"] = node_counts
    result["edge_counts"] = edge_counts
    return result


def get_kuzu_active_hosts(db_path: Path) -> dict:
    result = {
        "ok": False,
        "hosts_df": pd.DataFrame(),
        "error": None,
    }

    if not db_path.exists():
        result["error"] = f"DB not found: {db_path}"
        return result

    conn, error = _connect(db_path)
    if error:
        result["error"] = error
        return result

    hosts_df = _query_df(
        conn,
        """
        MATCH (n:GraphNode)
        WHERE n.type = 'Host' AND n.is_active = true
        RETURN
            n.id AS host_id,
            n.label AS hostname,
            n.status AS status,
            n.last_seen AS last_seen
        ORDER BY hostname ASC;
        """,
    )

    result["ok"] = not hosts_df.empty
    result["hosts_df"] = hosts_df if not hosts_df.empty else pd.DataFrame()
    if hosts_df.empty:
        result["error"] = "No active Host nodes found in Kuzu."
    return result


def get_kuzu_host_neighborhood(
    db_path: Path,
    host_id: str,
    max_nodes: int = 120,
    allowed_node_types: list[str] | None = None,
) -> dict:
    result = {
        "ok": False,
        "center_host_id": host_id,
        "nodes_df": pd.DataFrame(),
        "edges_df": pd.DataFrame(),
        "error": None,
    }

    if not db_path.exists():
        result["error"] = f"DB not found: {db_path}"
        return result

    conn, error = _connect(db_path)
    if error:
        result["error"] = error
        return result

    host_id = str(host_id).strip()
    if not host_id:
        result["error"] = "Host ID is required."
        return result

    max_nodes = max(10, min(int(max_nodes), 300))
    allowed_node_types = [str(x).strip() for x in (allowed_node_types or []) if str(x).strip()]

    center_df = _query_df(
        conn,
        """
        MATCH (n:GraphNode {id: $host_id})
        RETURN
            n.id AS node_id,
            n.type AS node_type,
            n.label AS label,
            n.status AS status,
            n.last_seen AS last_seen
        LIMIT 1;
        """,
        {"host_id": host_id},
    )

    if center_df.empty:
        result["error"] = f"Host not found in Kuzu: {host_id}"
        return result

    neighbor_edges_df = _query_df(
        conn,
        """
        MATCH (e:GraphEdge)-[:EDGE_SOURCE]->(src:GraphNode {id: $host_id})
        MATCH (e)-[:EDGE_TARGET]->(dst:GraphNode)
        WHERE e.is_active = true
        RETURN
            e.id AS edge_id,
            e.type AS edge_type,
            e.status AS edge_status,
            src.id AS source_id,
            src.label AS source_label,
            src.type AS source_type,
            dst.id AS target_id,
            dst.label AS target_label,
            dst.type AS target_type,
            e.last_seen AS last_seen
        UNION
        MATCH (e:GraphEdge)-[:EDGE_SOURCE]->(src:GraphNode)
        MATCH (e)-[:EDGE_TARGET]->(dst:GraphNode {id: $host_id})
        WHERE e.is_active = true
        RETURN
            e.id AS edge_id,
            e.type AS edge_type,
            e.status AS edge_status,
            src.id AS source_id,
            src.label AS source_label,
            src.type AS source_type,
            dst.id AS target_id,
            dst.label AS target_label,
            dst.type AS target_type,
            e.last_seen AS last_seen
        ORDER BY edge_type ASC, source_label ASC, target_label ASC;
        """,
        {"host_id": host_id},
    )

    node_rows = []
    seen_nodes: set[str] = set()

    for _, row in center_df.iterrows():
        node_id = str(row["node_id"])
        if node_id in seen_nodes:
            continue
        seen_nodes.add(node_id)
        node_rows.append(
            {
                "node_id": node_id,
                "node_type": str(row["node_type"]),
                "label": str(row["label"]),
                "status": row.get("status", ""),
                "last_seen": row.get("last_seen", ""),
                "is_center": True,
            }
        )

    if not neighbor_edges_df.empty:
        for _, row in neighbor_edges_df.iterrows():
            source_id = str(row["source_id"])
            target_id = str(row["target_id"])

            if source_id not in seen_nodes:
                seen_nodes.add(source_id)
                node_rows.append(
                    {
                        "node_id": source_id,
                        "node_type": str(row["source_type"]),
                        "label": str(row["source_label"]),
                        "status": "",
                        "last_seen": row.get("last_seen", ""),
                        "is_center": source_id == host_id,
                    }
                )

            if target_id not in seen_nodes:
                seen_nodes.add(target_id)
                node_rows.append(
                    {
                        "node_id": target_id,
                        "node_type": str(row["target_type"]),
                        "label": str(row["target_label"]),
                        "status": "",
                        "last_seen": row.get("last_seen", ""),
                        "is_center": target_id == host_id,
                    }
                )

    nodes_df = pd.DataFrame(node_rows)

    if allowed_node_types and not nodes_df.empty:
        nodes_df = nodes_df[
            nodes_df["node_type"].astype(str).isin(allowed_node_types)
            | nodes_df["node_id"].astype(str).eq(host_id)
        ].reset_index(drop=True)

    if nodes_df.empty:
        result["error"] = "No neighborhood nodes matched the selected node types."
        return result

    if len(nodes_df) > max_nodes:
        center_nodes_df = nodes_df[nodes_df["node_id"].astype(str) == host_id]
        other_nodes_df = nodes_df[nodes_df["node_id"].astype(str) != host_id].head(max_nodes - len(center_nodes_df))
        nodes_df = pd.concat([center_nodes_df, other_nodes_df], ignore_index=True)

    allowed_ids = set(nodes_df["node_id"].astype(str).tolist())

    if not neighbor_edges_df.empty:
        neighbor_edges_df = neighbor_edges_df[
            neighbor_edges_df["source_id"].astype(str).isin(allowed_ids)
            & neighbor_edges_df["target_id"].astype(str).isin(allowed_ids)
        ].reset_index(drop=True)

    result["ok"] = True
    result["nodes_df"] = nodes_df
    result["edges_df"] = neighbor_edges_df if not neighbor_edges_df.empty else pd.DataFrame()
    return result