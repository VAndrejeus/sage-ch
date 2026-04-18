from __future__ import annotations

import streamlit as st


def render_sidebar() -> None:
    with st.sidebar:
        st.markdown("## SAGE-CH")
        st.caption("Security Console")

        st.page_link("app.py", label="Home", icon="🛡️")
        st.page_link("pages/1_Dashboard.py", label="Dashboard", icon="📊")
        st.page_link("pages/2_Hosts.py", label="Hosts", icon="💻")
        st.page_link("pages/3_Findings.py", label="Findings", icon="🚨")
        st.page_link("pages/4_Graph.py", label="Graph", icon="🕸️")
        st.page_link("pages/5_Batches.py", label="Batches", icon="🗂️")
        st.page_link("pages/6_Settings.py", label="Settings", icon="⚙️")
        st.page_link("pages/7_Actions.py", label="Actions", icon="▶️")