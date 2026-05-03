from __future__ import annotations

from pathlib import Path

import streamlit as st


def get_logo_path() -> Path:
    return Path(__file__).resolve().parents[1] / "assets" / "sage_ch_logo.png"


def render_sidebar() -> None:
    logo_path = get_logo_path()

    with st.sidebar:
        if logo_path.exists():
            st.image(str(logo_path), use_container_width=True)

        st.markdown("## SAGE-CH")
        st.page_link("app.py", label="Home", icon="🛡️")
        st.page_link("pages/1_Dashboard.py", label="Dashboard", icon="📊")
        st.page_link("pages/2_Hosts.py", label="Hosts", icon="💻")
        st.page_link("pages/3_Findings.py", label="Findings", icon="🚨")
        st.page_link("pages/4_Graph.py", label="Graph", icon="🕸️")
        st.page_link("pages/5_Batches.py", label="Batches", icon="🗂️")

        st.divider()
        st.caption("Operations")
        st.page_link("pages/7_Actions.py", label="Actions", icon="▶️")
        st.page_link("pages/8_Pipeline_Health.py", label="Pipeline Health", icon="🩺")
        st.page_link("pages/6_Settings.py", label="Settings", icon="⚙️")
