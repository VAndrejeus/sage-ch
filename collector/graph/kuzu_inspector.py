from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

import pandas as pd

from collector.config import KUZU_DB_PATH
from collector.graph.kuzu_backend import KuzuGraphBackend
from collector.graph.kuzu_queries import (
    ACTIVE_ASSETS_QUERY,
    ACTIVE_HOSTS_QUERY,
    EDGE_BY_ID_QUERY,
    EDGE_COUNTS_BY_TYPE_QUERY,
    HOST_NEIGHBORS_QUERY,
    HOST_SERVICES_QUERY,
    HOST_SOFTWARE_QUERY,
    INACTIVE_EDGES_QUERY,
    INACTIVE_NODES_QUERY,
    NODE_BY_ID_QUERY,
    NODE_COUNTS_BY_TYPE_QUERY,
    RECENT_EDGE_OBSERVATIONS_QUERY,
    RECENT_NODE_OBSERVATIONS_QUERY,
)


class KuzuInspector:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self.backend = KuzuGraphBackend(db_path=db_path)
        self.backend.initialize()

    def query_df(self, query: str, params: Optional[Dict[str, Any]] = None) -> pd.DataFrame:
        return self.backend._fetch_df(query, params)

    def node_counts_by_type(self) -> pd.DataFrame:
        return self.query_df(NODE_COUNTS_BY_TYPE_QUERY)

    def edge_counts_by_type(self) -> pd.DataFrame:
        return self.query_df(EDGE_COUNTS_BY_TYPE_QUERY)

    def active_hosts(self) -> pd.DataFrame:
        return self.query_df(ACTIVE_HOSTS_QUERY)

    def active_assets(self) -> pd.DataFrame:
        return self.query_df(ACTIVE_ASSETS_QUERY)

    def node_by_id(self, node_id: str) -> pd.DataFrame:
        return self.query_df(NODE_BY_ID_QUERY, {"node_id": node_id})

    def edge_by_id(self, edge_id: str) -> pd.DataFrame:
        return self.query_df(EDGE_BY_ID_QUERY, {"edge_id": edge_id})

    def host_software(self, host_id: str) -> pd.DataFrame:
        return self.query_df(HOST_SOFTWARE_QUERY, {"host_id": host_id})

    def host_services(self, host_id: str) -> pd.DataFrame:
        return self.query_df(HOST_SERVICES_QUERY, {"host_id": host_id})

    def host_neighbors(self, host_id: str) -> pd.DataFrame:
        return self.query_df(HOST_NEIGHBORS_QUERY, {"host_id": host_id})

    def recent_node_observations(self, node_id: str) -> pd.DataFrame:
        return self.query_df(RECENT_NODE_OBSERVATIONS_QUERY, {"node_id": node_id})

    def recent_edge_observations(self, edge_id: str) -> pd.DataFrame:
        return self.query_df(RECENT_EDGE_OBSERVATIONS_QUERY, {"edge_id": edge_id})

    def inactive_nodes(self) -> pd.DataFrame:
        return self.query_df(INACTIVE_NODES_QUERY)

    def inactive_edges(self) -> pd.DataFrame:
        return self.query_df(INACTIVE_EDGES_QUERY)


def print_section(title: str) -> None:
    print()
    print("=" * 80)
    print(title)
    print("=" * 80)


def print_df(df: pd.DataFrame, max_rows: int = 25) -> None:
    if df.empty:
        print("[no rows]")
        return

    if len(df) > max_rows:
        print(df.head(max_rows).to_string(index=False))
        print(f"... ({len(df)} total rows)")
        return

    print(df.to_string(index=False))


def pretty_print_json_field(df: pd.DataFrame, json_column: str) -> None:
    if df.empty or json_column not in df.columns:
        print_df(df)
        return

    for _, row in df.iterrows():
        row_dict = row.to_dict()
        raw_value = row_dict.get(json_column)

        print("-" * 80)
        for key, value in row_dict.items():
            if key == json_column:
                continue
            print(f"{key}: {value}")

        print(f"{json_column}:")
        try:
            parsed = json.loads(raw_value) if isinstance(raw_value, str) else raw_value
            print(json.dumps(parsed, indent=2, sort_keys=True))
        except Exception:
            print(raw_value)


def main() -> None:
    inspector = KuzuInspector(KUZU_DB_PATH)

    print_section(f"Kuzu DB: {KUZU_DB_PATH}")
    print(f"DB file exists: {Path(KUZU_DB_PATH).exists()}")

    print_section("Node counts by type")
    print_df(inspector.node_counts_by_type())

    print_section("Edge counts by type")
    print_df(inspector.edge_counts_by_type())

    print_section("Active hosts")
    active_hosts_df = inspector.active_hosts()
    print_df(active_hosts_df)

    print_section("Active assets")
    print_df(inspector.active_assets())

    print_section("Inactive nodes")
    print_df(inspector.inactive_nodes())

    print_section("Inactive edges")
    print_df(inspector.inactive_edges())

    if active_hosts_df.empty:
        return

    first_host_id = str(active_hosts_df.iloc[0]["host_id"])

    print_section(f"Host detail: {first_host_id}")
    pretty_print_json_field(inspector.node_by_id(first_host_id), "properties_json")

    print_section(f"Host software: {first_host_id}")
    print_df(inspector.host_software(first_host_id), max_rows=50)

    print_section(f"Host services: {first_host_id}")
    pretty_print_json_field(inspector.host_services(first_host_id), "edge_properties_json")

    print_section(f"Host neighbors: {first_host_id}")
    print_df(inspector.host_neighbors(first_host_id), max_rows=100)

    print_section(f"Recent node observations: {first_host_id}")
    pretty_print_json_field(inspector.recent_node_observations(first_host_id), "properties_json")


if __name__ == "__main__":
    main()