from pathlib import Path
import sys

import networkx as nx
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

st.set_page_config(page_title="Graph", page_icon="🕸️", layout="wide")

GUI_DIR = Path(__file__).resolve().parents[1]
if str(GUI_DIR) not in sys.path:
    sys.path.append(str(GUI_DIR))

from services.nav import render_sidebar
from services.data_loader import get_graph_db_path, load_graph_counts_from_consolidated, load_latest_assessment_summary_payload
from services.kuzu_service import get_kuzu_active_hosts, get_kuzu_graph_counts, get_kuzu_host_neighborhood

render_sidebar()

st.title("Graph")
st.caption("Inspect graph state, node and edge counts, and render a host-centered graph directly from Kuzu.")

top_bar = st.container(border=True)
with top_bar:
    left, right = st.columns([1, 4])

    with left:
        if st.button("Refresh", use_container_width=True):
            st.rerun()

    with right:
        st.info(
            "This page draws a host-centered neighborhood directly from Kuzu. "
            "Select a host to render only its immediate graph neighborhood.",
            icon="ℹ️",
        )

graph_db_path = get_graph_db_path()
kuzu_counts = get_kuzu_graph_counts(graph_db_path)
json_graph_counts, graph_path = load_graph_counts_from_consolidated()
assessment_summary, summary_path = load_latest_assessment_summary_payload()
hosts_result = get_kuzu_active_hosts(graph_db_path)

graph_counts = kuzu_counts if kuzu_counts.get("ok") else json_graph_counts
graph_source = "Kuzu" if kuzu_counts.get("ok") else "Consolidated JSON fallback"
graph_persistence_status = json_graph_counts.get("graph_persistence_status", "unknown")

all_node_types = sorted(graph_counts.get("node_counts", {}).keys()) if graph_counts.get("node_counts") else []
default_types = [x for x in all_node_types if x not in {"EdgeObservation", "NodeObservation"}] or all_node_types

overview_box = st.container(border=True)
with overview_box:
    st.subheader("Overview")

    total_nodes = sum(graph_counts.get("node_counts", {}).values()) if graph_counts.get("node_counts") else 0
    total_edges = sum(graph_counts.get("edge_counts", {}).values()) if graph_counts.get("edge_counts") else 0

    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Graph Source", graph_source)
    m2.metric("Persistence", graph_persistence_status)
    m3.metric("Total Nodes", total_nodes)
    m4.metric("Total Edges", total_edges)
    m5.metric("Latest Batch", assessment_summary.get("batch_id", "N/A") if isinstance(assessment_summary, dict) else "N/A")

controls_box = st.container(border=True)
with controls_box:
    st.subheader("Host-Centered Graph Controls")

    if not hosts_result.get("ok"):
        st.warning(hosts_result.get("error") or "No active hosts found in Kuzu.")
        hosts_df = pd.DataFrame()
        selected_host_id = ""
        selected_node_types = []
        max_nodes = 80
        show_labels = False
    else:
        hosts_df = hosts_result.get("hosts_df", pd.DataFrame())
        host_options = hosts_df["host_id"].astype(str).tolist()
        host_label_map = {
            str(row["host_id"]): f"{row['hostname']} ({row['host_id']})"
            for _, row in hosts_df.iterrows()
        }

        c1, c2, c3 = st.columns([2, 1, 1])

        with c1:
            selected_host_id = st.selectbox(
                "Center host",
                host_options,
                format_func=lambda x: host_label_map.get(x, x),
            )

        with c2:
            max_nodes = st.slider(
                "Max nodes to draw",
                min_value=10,
                max_value=300,
                value=80,
                step=10,
            )

        with c3:
            show_labels = st.checkbox("Show labels", value=False)

        selected_node_types = st.multiselect(
            "Node types to include",
            all_node_types,
            default=default_types,
        )

if hosts_result.get("ok") and selected_host_id:
    subgraph = get_kuzu_host_neighborhood(
        graph_db_path,
        host_id=selected_host_id,
        max_nodes=max_nodes,
        allowed_node_types=selected_node_types,
    )
else:
    subgraph = {
        "ok": False,
        "nodes_df": pd.DataFrame(),
        "edges_df": pd.DataFrame(),
        "error": "No host selected.",
    }

graph_tab, counts_tab, summary_tab = st.tabs(["Graph View", "Counts", "Assessment Summary"])

with graph_tab:
    graph_box = st.container(border=True)
    with graph_box:
        st.subheader("Rendered Host Neighborhood")

        if not subgraph.get("ok"):
            st.warning(subgraph.get("error") or "Unable to load graph neighborhood from Kuzu.")
        else:
            nodes_df = subgraph.get("nodes_df", pd.DataFrame())
            edges_df = subgraph.get("edges_df", pd.DataFrame())
            center_host_id = subgraph.get("center_host_id", "")

            if nodes_df.empty:
                st.info("No graph nodes available to draw.")
            else:
                G = nx.Graph()

                for _, row in nodes_df.iterrows():
                    node_id = str(row["node_id"])
                    G.add_node(
                        node_id,
                        label=str(row.get("label", node_id)),
                        node_type=str(row.get("node_type", "unknown")),
                        is_center=bool(row.get("is_center", False)),
                    )

                if not edges_df.empty:
                    for _, row in edges_df.iterrows():
                        source_id = str(row["source_id"])
                        target_id = str(row["target_id"])
                        if source_id in G.nodes and target_id in G.nodes:
                            G.add_edge(
                                source_id,
                                target_id,
                                edge_type=str(row.get("edge_type", "unknown")),
                            )

                if G.number_of_nodes() == 0:
                    st.info("No graph nodes available to draw.")
                else:
                    pos = nx.spring_layout(G, seed=42, k=0.9)

                    edge_x = []
                    edge_y = []
                    for source, target in G.edges():
                        x0, y0 = pos[source]
                        x1, y1 = pos[target]
                        edge_x.extend([x0, x1, None])
                        edge_y.extend([y0, y1, None])

                    edge_trace = go.Scatter(
                        x=edge_x,
                        y=edge_y,
                        line=dict(width=1),
                        hoverinfo="none",
                        mode="lines",
                        name="edges",
                    )

                    node_x = []
                    node_y = []
                    node_text = []
                    node_hover = []
                    node_sizes = []

                    for node_id, attrs in G.nodes(data=True):
                        x, y = pos[node_id]
                        node_x.append(x)
                        node_y.append(y)

                        label = str(attrs.get("label", node_id))
                        node_type = str(attrs.get("node_type", "unknown"))
                        is_center = bool(attrs.get("is_center", False))

                        node_text.append(label if show_labels else "")
                        node_hover.append(
                            f"id: {node_id}<br>"
                            f"label: {label}<br>"
                            f"type: {node_type}<br>"
                            f"center: {'yes' if is_center else 'no'}"
                        )
                        node_sizes.append(20 if is_center else 12)

                    node_trace = go.Scatter(
                        x=node_x,
                        y=node_y,
                        mode="markers+text" if show_labels else "markers",
                        text=node_text,
                        textposition="top center",
                        hoverinfo="text",
                        hovertext=node_hover,
                        marker=dict(size=node_sizes, line=dict(width=1)),
                        name="nodes",
                    )

                    fig = go.Figure(
                        data=[edge_trace, node_trace],
                        layout=go.Layout(
                            showlegend=False,
                            hovermode="closest",
                            margin=dict(l=10, r=10, t=10, b=10),
                            xaxis=dict(showgrid=False, zeroline=False, visible=False),
                            yaxis=dict(showgrid=False, zeroline=False, visible=False),
                            height=720,
                        ),
                    )

                    st.plotly_chart(fig, use_container_width=True)

                    r1, r2, r3 = st.columns(3)
                    r1.metric("Center Host", center_host_id)
                    r2.metric("Rendered Nodes", G.number_of_nodes())
                    r3.metric("Rendered Edges", G.number_of_edges())

                    bottom_left, bottom_right = st.columns([1, 1])

                    with bottom_left:
                        st.markdown("#### Rendered Nodes")
                        st.dataframe(nodes_df, use_container_width=True, hide_index=True)

                    with bottom_right:
                        st.markdown("#### Rendered Edges")
                        if edges_df.empty:
                            st.info("No neighborhood edges found.")
                        else:
                            st.dataframe(edges_df, use_container_width=True, hide_index=True)

with counts_tab:
    left, right = st.columns(2)

    with left:
        counts_box_left = st.container(border=True)
        with counts_box_left:
            st.subheader("Node Counts")

            node_counts = graph_counts.get("node_counts", {})
            if node_counts:
                node_df = pd.DataFrame(
                    [{"node_type": key, "count": value} for key, value in sorted(node_counts.items())]
                )
                st.dataframe(node_df, use_container_width=True, hide_index=True)
            else:
                st.info("No node counts available.")

    with right:
        counts_box_right = st.container(border=True)
        with counts_box_right:
            st.subheader("Edge Counts")

            edge_counts = graph_counts.get("edge_counts", {})
            if edge_counts:
                edge_df = pd.DataFrame(
                    [{"edge_type": key, "count": value} for key, value in sorted(edge_counts.items())]
                )
                st.dataframe(edge_df, use_container_width=True, hide_index=True)
            else:
                st.info("No edge counts available.")

    details_box = st.container(border=True)
    with details_box:
        st.subheader("Graph Source Details")
        st.markdown(f"**Graph JSON source**  \n`{graph_path if graph_path else 'Not found'}`")
        st.markdown(f"**Kuzu DB path**  \n`{graph_db_path}`")

        graph_persistence = json_graph_counts.get("graph_persistence", {})
        if isinstance(graph_persistence, dict):
            error = graph_persistence.get("error", "")
            if error:
                with st.expander("Graph persistence details"):
                    st.code(str(error))

with summary_tab:
    summary_box = st.container(border=True)
    with summary_box:
        st.subheader("Assessment Summary")

        if assessment_summary:
            sev = assessment_summary.get("severity_counts", {})
            cat = assessment_summary.get("category_counts", {})

            s1, s2, s3, s4 = st.columns(4)
            s1.metric("Critical", sev.get("critical", 0))
            s2.metric("High", sev.get("high", 0))
            s3.metric("Medium", sev.get("medium", 0))
            s4.metric("Low", sev.get("low", 0))

            st.markdown("#### Findings by Category")
            if cat:
                cat_df = pd.DataFrame(
                    [{"category": key, "count": value} for key, value in sorted(cat.items())]
                )
                st.dataframe(cat_df, use_container_width=True, hide_index=True)
            else:
                st.info("No category summary available.")

            st.markdown("#### Source")
            st.markdown(f"**Assessment summary**  \n`{summary_path if summary_path else 'Not found'}`")
        else:
            st.info("No assessment summary available.")