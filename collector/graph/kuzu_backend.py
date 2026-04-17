from __future__ import annotations

import hashlib
import json
import os
from typing import Any, Dict, Iterable, Optional, Set

import kuzu
import pandas as pd

from collector.graph.kuzu_schema import SCHEMA_STATEMENTS


class KuzuGraphBackend:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self.db: Optional[kuzu.Database] = None
        self.conn: Optional[kuzu.Connection] = None

    def initialize(self) -> None:
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.db = kuzu.Database(self.db_path)
        self.conn = kuzu.Connection(self.db)

        for statement in SCHEMA_STATEMENTS:
            self.conn.execute(statement)

    def _require_conn(self) -> kuzu.Connection:
        if self.conn is None:
            raise RuntimeError("KuzuGraphBackend is not initialized")
        return self.conn

    def _fetch_df(self, query: str, params: Optional[Dict[str, Any]] = None) -> pd.DataFrame:
        conn = self._require_conn()
        result = conn.execute(query, params or {})
        return result.get_as_df()

    def _exists_node(self, node_id: str) -> bool:
        df = self._fetch_df(
            "MATCH (n:GraphNode {id: $id}) RETURN COUNT(n) AS c;",
            {"id": node_id},
        )
        return not df.empty and int(df.iloc[0]["c"]) > 0

    def _exists_edge(self, edge_id: str) -> bool:
        df = self._fetch_df(
            "MATCH (e:GraphEdge {id: $id}) RETURN COUNT(e) AS c;",
            {"id": edge_id},
        )
        return not df.empty and int(df.iloc[0]["c"]) > 0

    def _relation_exists(self, rel_table: str, from_id: str, to_id: str) -> bool:
        if rel_table == "EDGE_SOURCE":
            query = """
                MATCH (e:GraphEdge {id: $from_id})-[r:EDGE_SOURCE]->(n:GraphNode {id: $to_id})
                RETURN COUNT(r) AS c;
            """
        elif rel_table == "EDGE_TARGET":
            query = """
                MATCH (e:GraphEdge {id: $from_id})-[r:EDGE_TARGET]->(n:GraphNode {id: $to_id})
                RETURN COUNT(r) AS c;
            """
        elif rel_table == "OBSERVATION_OF_NODE":
            query = """
                MATCH (o:NodeObservation {id: $from_id})-[r:OBSERVATION_OF_NODE]->(n:GraphNode {id: $to_id})
                RETURN COUNT(r) AS c;
            """
        elif rel_table == "OBSERVATION_OF_EDGE":
            query = """
                MATCH (o:EdgeObservation {id: $from_id})-[r:OBSERVATION_OF_EDGE]->(e:GraphEdge {id: $to_id})
                RETURN COUNT(r) AS c;
            """
        else:
            raise ValueError(f"Unsupported relation table: {rel_table}")

        df = self._fetch_df(query, {"from_id": from_id, "to_id": to_id})
        return not df.empty and int(df.iloc[0]["c"]) > 0

    def _create_relation(self, rel_table: str, from_id: str, to_id: str) -> None:
        conn = self._require_conn()

        if self._relation_exists(rel_table, from_id, to_id):
            return

        if rel_table == "EDGE_SOURCE":
            conn.execute(
                """
                MATCH (e:GraphEdge {id: $from_id}), (n:GraphNode {id: $to_id})
                CREATE (e)-[:EDGE_SOURCE]->(n);
                """,
                {"from_id": from_id, "to_id": to_id},
            )
            return

        if rel_table == "EDGE_TARGET":
            conn.execute(
                """
                MATCH (e:GraphEdge {id: $from_id}), (n:GraphNode {id: $to_id})
                CREATE (e)-[:EDGE_TARGET]->(n);
                """,
                {"from_id": from_id, "to_id": to_id},
            )
            return

        if rel_table == "OBSERVATION_OF_NODE":
            conn.execute(
                """
                MATCH (o:NodeObservation {id: $from_id}), (n:GraphNode {id: $to_id})
                CREATE (o)-[:OBSERVATION_OF_NODE]->(n);
                """,
                {"from_id": from_id, "to_id": to_id},
            )
            return

        if rel_table == "OBSERVATION_OF_EDGE":
            conn.execute(
                """
                MATCH (o:EdgeObservation {id: $from_id}), (e:GraphEdge {id: $to_id})
                CREATE (o)-[:OBSERVATION_OF_EDGE]->(e);
                """,
                {"from_id": from_id, "to_id": to_id},
            )
            return

        raise ValueError(f"Unsupported relation table: {rel_table}")

    @staticmethod
    def build_edge_id(edge: Dict[str, Any]) -> str:
        raw = "||".join(
            [
                str(edge.get("source") or ""),
                str(edge.get("target") or ""),
                str(edge.get("type") or ""),
            ]
        )
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]
        return f"edge-{digest}"

    @staticmethod
    def build_node_observation_id(node_id: str, observed_at: str, run_id: str) -> str:
        raw = f"{node_id}||{observed_at}||{run_id}"
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]
        return f"nodeobs-{digest}"

    @staticmethod
    def build_edge_observation_id(edge_id: str, observed_at: str, run_id: str, properties_json: str) -> str:
        raw = f"{edge_id}||{observed_at}||{run_id}||{properties_json}"
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]
        return f"edgeobs-{digest}"

    @staticmethod
    def _to_json(value: Any) -> str:
        return json.dumps(value or {}, sort_keys=True, default=str)

    def upsert_node(self, node: Dict[str, Any], observed_at: str, run_id: str) -> None:
        conn = self._require_conn()

        node_id = str(node["id"])
        node_type = str(node.get("type") or "Entity")
        label = str(node.get("label") or node_id)
        original_type = str(node.get("original_type") or "")
        semantic_type = str(node.get("semantic_type") or "entity")
        properties_json = self._to_json(node.get("properties"))

        create_params = {
            "id": node_id,
            "type": node_type,
            "label": label,
            "original_type": original_type,
            "semantic_type": semantic_type,
            "properties_json": properties_json,
            "first_seen": observed_at,
            "last_seen": observed_at,
            "last_run_id": run_id,
            "is_active": True,
            "status": "active",
        }

        update_params = {
            "id": node_id,
            "type": node_type,
            "label": label,
            "original_type": original_type,
            "semantic_type": semantic_type,
            "properties_json": properties_json,
            "last_seen": observed_at,
            "last_run_id": run_id,
            "is_active": True,
            "status": "active",
        }

        if self._exists_node(node_id):
            conn.execute(
                """
                MATCH (n:GraphNode {id: $id})
                SET n.type = $type,
                    n.label = $label,
                    n.original_type = $original_type,
                    n.semantic_type = $semantic_type,
                    n.properties_json = $properties_json,
                    n.last_seen = $last_seen,
                    n.last_run_id = $last_run_id,
                    n.is_active = $is_active,
                    n.status = $status;
                """,
                update_params,
            )
        else:
            conn.execute(
                """
                CREATE (n:GraphNode {
                    id: $id,
                    type: $type,
                    label: $label,
                    original_type: $original_type,
                    semantic_type: $semantic_type,
                    properties_json: $properties_json,
                    first_seen: $first_seen,
                    last_seen: $last_seen,
                    last_run_id: $last_run_id,
                    is_active: $is_active,
                    status: $status
                });
                """,
                create_params,
            )

        observation_id = self.build_node_observation_id(node_id, observed_at, run_id)

        conn.execute(
            """
            CREATE (o:NodeObservation {
                id: $id,
                node_id: $node_id,
                observed_at: $observed_at,
                run_id: $run_id,
                type: $type,
                label: $label,
                properties_json: $properties_json
            });
            """,
            {
                "id": observation_id,
                "node_id": node_id,
                "observed_at": observed_at,
                "run_id": run_id,
                "type": node_type,
                "label": label,
                "properties_json": properties_json,
            },
        )

        self._create_relation("OBSERVATION_OF_NODE", observation_id, node_id)

    def upsert_edge(self, edge: Dict[str, Any], observed_at: str, run_id: str) -> str:
        conn = self._require_conn()

        edge_id = self.build_edge_id(edge)
        source_id = str(edge["source"])
        target_id = str(edge["target"])
        edge_type = str(edge.get("type") or "RELATED_TO")
        original_type = str(edge.get("original_type") or "")
        semantic_type = str(edge.get("semantic_type") or "relationship")
        properties_json = self._to_json(edge.get("properties"))

        create_params = {
            "id": edge_id,
            "source_id": source_id,
            "target_id": target_id,
            "type": edge_type,
            "original_type": original_type,
            "semantic_type": semantic_type,
            "properties_json": properties_json,
            "first_seen": observed_at,
            "last_seen": observed_at,
            "last_run_id": run_id,
            "is_active": True,
            "status": "active",
        }

        update_params = {
            "id": edge_id,
            "source_id": source_id,
            "target_id": target_id,
            "type": edge_type,
            "original_type": original_type,
            "semantic_type": semantic_type,
            "properties_json": properties_json,
            "last_seen": observed_at,
            "last_run_id": run_id,
            "is_active": True,
            "status": "active",
        }

        if self._exists_edge(edge_id):
            conn.execute(
                """
                MATCH (e:GraphEdge {id: $id})
                SET e.source_id = $source_id,
                    e.target_id = $target_id,
                    e.type = $type,
                    e.original_type = $original_type,
                    e.semantic_type = $semantic_type,
                    e.properties_json = $properties_json,
                    e.last_seen = $last_seen,
                    e.last_run_id = $last_run_id,
                    e.is_active = $is_active,
                    e.status = $status;
                """,
                update_params,
            )
        else:
            conn.execute(
                """
                CREATE (e:GraphEdge {
                    id: $id,
                    source_id: $source_id,
                    target_id: $target_id,
                    type: $type,
                    original_type: $original_type,
                    semantic_type: $semantic_type,
                    properties_json: $properties_json,
                    first_seen: $first_seen,
                    last_seen: $last_seen,
                    last_run_id: $last_run_id,
                    is_active: $is_active,
                    status: $status
                });
                """,
                create_params,
            )

        self._create_relation("EDGE_SOURCE", edge_id, source_id)
        self._create_relation("EDGE_TARGET", edge_id, target_id)

        observation_id = self.build_edge_observation_id(edge_id, observed_at, run_id, properties_json)

        conn.execute(
            """
            CREATE (o:EdgeObservation {
                id: $id,
                edge_id: $edge_id,
                observed_at: $observed_at,
                run_id: $run_id,
                source_id: $source_id,
                target_id: $target_id,
                type: $type,
                properties_json: $properties_json
            });
            """,
            {
                "id": observation_id,
                "edge_id": edge_id,
                "observed_at": observed_at,
                "run_id": run_id,
                "source_id": source_id,
                "target_id": target_id,
                "type": edge_type,
                "properties_json": properties_json,
            },
        )

        self._create_relation("OBSERVATION_OF_EDGE", observation_id, edge_id)
        return edge_id

    def reconcile_nodes(self, observed_node_ids: Set[str], observed_at: str, active_types: Iterable[str]) -> int:
        active_types_list = list(active_types)
        if not active_types_list:
            return 0

        df = self._fetch_df(
            """
            MATCH (n:GraphNode)
            WHERE n.type IN $types AND n.is_active = true
            RETURN n.id AS id;
            """,
            {"types": active_types_list},
        )

        if df.empty:
            return 0

        all_active_ids = set(df["id"].tolist())
        missing_ids = sorted(all_active_ids - observed_node_ids)

        conn = self._require_conn()
        changed = 0

        for node_id in missing_ids:
            conn.execute(
                """
                MATCH (n:GraphNode {id: $id})
                SET n.is_active = false,
                    n.status = 'missing',
                    n.last_run_id = $last_run_id,
                    n.last_seen = $last_seen;
                """,
                {
                    "id": node_id,
                    "last_run_id": f"reconcile:{observed_at}",
                    "last_seen": observed_at,
                },
            )
            changed += 1

        return changed

    def reconcile_edges(self, observed_edge_ids: Set[str], observed_at: str) -> int:
        df = self._fetch_df(
            """
            MATCH (e:GraphEdge)
            WHERE e.is_active = true
            RETURN e.id AS id;
            """
        )

        if df.empty:
            return 0

        all_active_ids = set(df["id"].tolist())
        missing_ids = sorted(all_active_ids - observed_edge_ids)

        conn = self._require_conn()
        changed = 0

        for edge_id in missing_ids:
            conn.execute(
                """
                MATCH (e:GraphEdge {id: $id})
                SET e.is_active = false,
                    e.status = 'inactive',
                    e.last_run_id = $last_run_id,
                    e.last_seen = $last_seen;
                """,
                {
                    "id": edge_id,
                    "last_run_id": f"reconcile:{observed_at}",
                    "last_seen": observed_at,
                },
            )
            changed += 1

        return changed

    def ingest_mapped_graph(
        self,
        mapped_graph: Dict[str, Any],
        observed_at: str,
        run_id: str,
    ) -> Dict[str, Any]:
        nodes = mapped_graph.get("nodes", [])
        edges = mapped_graph.get("edges", [])

        observed_node_ids: Set[str] = set()
        observed_edge_ids: Set[str] = set()

        for node in nodes:
            if not isinstance(node, dict) or not node.get("id"):
                continue
            self.upsert_node(node, observed_at=observed_at, run_id=run_id)
            observed_node_ids.add(str(node["id"]))

        for edge in edges:
            if not isinstance(edge, dict):
                continue
            if not edge.get("source") or not edge.get("target"):
                continue
            edge_id = self.upsert_edge(edge, observed_at=observed_at, run_id=run_id)
            observed_edge_ids.add(edge_id)

        missing_node_count = self.reconcile_nodes(
            observed_node_ids=observed_node_ids,
            observed_at=observed_at,
            active_types=("Host", "Asset"),
        )
        inactive_edge_count = self.reconcile_edges(
            observed_edge_ids=observed_edge_ids,
            observed_at=observed_at,
        )

        return {
            "ok": True,
            "run_id": run_id,
            "observed_at": observed_at,
            "node_count": len(observed_node_ids),
            "edge_count": len(observed_edge_ids),
            "nodes_marked_missing": missing_node_count,
            "edges_marked_inactive": inactive_edge_count,
        }