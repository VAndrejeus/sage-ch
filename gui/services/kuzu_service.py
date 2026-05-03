from pathlib import Path
import kuzu
import pandas as pd


def get_connection(db_path: str | Path):
    db = kuzu.Database(str(db_path))
    return kuzu.Connection(db)


def get_kuzu_graph_counts(db_path):
    try:
        if not Path(db_path).exists():
            return {"ok": False, "error": f"DB not found: {db_path}", "node_counts": {}, "edge_counts": {}}

        conn = get_connection(db_path)

        node_df = conn.execute("""
            MATCH (n:GraphNode)
            RETURN n.type AS node_type, COUNT(n) AS count
        """).get_as_df()

        edge_df = conn.execute("""
            MATCH (e:GraphEdge)
            RETURN e.type AS edge_type, COUNT(e) AS count
        """).get_as_df()

        node_counts = {}
        edge_counts = {}

        if not node_df.empty:
            node_counts = dict(zip(node_df["node_type"], node_df["count"]))

        if not edge_df.empty:
            edge_counts = dict(zip(edge_df["edge_type"], edge_df["count"]))

        if not node_counts and not edge_counts:
            return {
                "ok": False,
                "error": "Kuzu graph tables exist but contain no graph rows.",
                "node_counts": {},
                "edge_counts": {},
            }

        return {
            "ok": True,
            "node_counts": node_counts,
            "edge_counts": edge_counts,
        }

    except Exception as e:
        return {"ok": False, "error": str(e), "node_counts": {}, "edge_counts": {}}


def get_kuzu_active_hosts(db_path):
    try:
        if not Path(db_path).exists():
            return {"ok": False, "error": f"DB not found: {db_path}", "hosts_df": pd.DataFrame()}

        conn = get_connection(db_path)

        df = conn.execute("""
            MATCH (n:GraphNode)
            WHERE LOWER(n.type) = 'host' AND n.is_active = true
            RETURN n.id AS host_id, n.label AS hostname
            ORDER BY hostname
        """).get_as_df()

        if not df.empty and "host_id" in df.columns:
            df = df[~df["host_id"].astype(str).str.startswith("host-discovered-")]

        if df.empty:
            return {"ok": False, "error": "No hosts found", "hosts_df": pd.DataFrame()}

        return {"ok": True, "hosts_df": df}

    except Exception as e:
        return {"ok": False, "error": str(e), "hosts_df": pd.DataFrame()}


def get_kuzu_host_neighborhood(db_path, host_id, max_nodes=80, allowed_node_types=None):
    try:
        if not Path(db_path).exists():
            return {
                "ok": False,
                "error": f"DB not found: {db_path}",
                "nodes_df": pd.DataFrame(),
                "edges_df": pd.DataFrame(),
                "center_host_id": host_id,
            }

        conn = get_connection(db_path)

        df = conn.execute("""
            MATCH (e:GraphEdge)-[:EDGE_SOURCE]->(src:GraphNode)
            MATCH (e)-[:EDGE_TARGET]->(dst:GraphNode)
            WHERE src.id = $host_id OR dst.id = $host_id
            RETURN
                src.id AS source_id,
                src.label AS source_label,
                src.type AS source_type,
                dst.id AS target_id,
                dst.label AS target_label,
                dst.type AS target_type,
                e.type AS edge_type
        """, {"host_id": host_id}).get_as_df()

        if df.empty:
            return {
                "ok": True,
                "nodes_df": pd.DataFrame(),
                "edges_df": pd.DataFrame(),
                "center_host_id": host_id,
            }

        nodes = {}
        edges = []

        for _, row in df.iterrows():
            src = row["source_id"]
            dst = row["target_id"]

            nodes[src] = {
                "node_id": src,
                "label": row["source_label"],
                "node_type": row["source_type"],
                "is_center": src == host_id,
            }

            nodes[dst] = {
                "node_id": dst,
                "label": row["target_label"],
                "node_type": row["target_type"],
                "is_center": dst == host_id,
            }

            edges.append({
                "source_id": src,
                "target_id": dst,
                "edge_type": row["edge_type"],
            })

        nodes_df = pd.DataFrame(nodes.values())
        edges_df = pd.DataFrame(edges)

        if allowed_node_types:
            nodes_df = nodes_df[
                (nodes_df["node_type"].isin(allowed_node_types)) | (nodes_df["is_center"])
            ]

            allowed_ids = set(nodes_df["node_id"])

            edges_df = edges_df[
                edges_df["source_id"].isin(allowed_ids) &
                edges_df["target_id"].isin(allowed_ids)
            ]

        nodes_df = nodes_df.head(max_nodes)

        return {
            "ok": True,
            "nodes_df": nodes_df,
            "edges_df": edges_df,
            "center_host_id": host_id,
        }

    except Exception as e:
        return {
            "ok": False,
            "error": str(e),
            "nodes_df": pd.DataFrame(),
            "edges_df": pd.DataFrame(),
            "center_host_id": host_id,
        }
