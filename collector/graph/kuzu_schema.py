from __future__ import annotations

SCHEMA_STATEMENTS = [
    """
    CREATE NODE TABLE IF NOT EXISTS GraphNode(
        id STRING,
        type STRING,
        label STRING,
        original_type STRING,
        semantic_type STRING,
        properties_json STRING,
        first_seen STRING,
        last_seen STRING,
        last_run_id STRING,
        is_active BOOLEAN,
        status STRING,
        PRIMARY KEY (id)
    );
    """,
    """
    CREATE NODE TABLE IF NOT EXISTS GraphEdge(
        id STRING,
        source_id STRING,
        target_id STRING,
        type STRING,
        original_type STRING,
        semantic_type STRING,
        properties_json STRING,
        first_seen STRING,
        last_seen STRING,
        last_run_id STRING,
        is_active BOOLEAN,
        status STRING,
        PRIMARY KEY (id)
    );
    """,
    """
    CREATE NODE TABLE IF NOT EXISTS NodeObservation(
        id STRING,
        node_id STRING,
        observed_at STRING,
        run_id STRING,
        type STRING,
        label STRING,
        properties_json STRING,
        PRIMARY KEY (id)
    );
    """,
    """
    CREATE NODE TABLE IF NOT EXISTS EdgeObservation(
        id STRING,
        edge_id STRING,
        observed_at STRING,
        run_id STRING,
        source_id STRING,
        target_id STRING,
        type STRING,
        properties_json STRING,
        PRIMARY KEY (id)
    );
    """,
    """
    CREATE REL TABLE IF NOT EXISTS EDGE_SOURCE(
        FROM GraphEdge TO GraphNode
    );
    """,
    """
    CREATE REL TABLE IF NOT EXISTS EDGE_TARGET(
        FROM GraphEdge TO GraphNode
    );
    """,
    """
    CREATE REL TABLE IF NOT EXISTS OBSERVATION_OF_NODE(
        FROM NodeObservation TO GraphNode
    );
    """,
    """
    CREATE REL TABLE IF NOT EXISTS OBSERVATION_OF_EDGE(
        FROM EdgeObservation TO GraphEdge
    );
    """,
]