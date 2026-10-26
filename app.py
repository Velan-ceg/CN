"""
LANGuard - Real-Time LAN Network Intrusion Detection & Traffic Anomaly Monitoring System
========================================================================================
Main Streamlit Interactive Dashboard
----------------------------------------------------------------------------------------
Computer Networks (CN) Capstone / Laboratory Project Application
Demonstrating TCP/IP Protocol Analysis, Rule-Based IDS, Statistical Anomaly Detection,
and Real-Time DNS Hostname Resolution.
"""

import sys
import os
import time
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from config import (
    DEFAULT_INTERFACE,
    IDS_RULES,
    ANOMALY_CONFIG,
    DASHBOARD_REFRESH_RATE,
    RECENT_PACKETS_DISPLAY_LIMIT,
    RECENT_ALERTS_DISPLAY_LIMIT,
    TOP_TALKERS_LIMIT
)
from core.sniffer import sniffer
from core.database import db_manager
from core.dns_resolver import dns_resolver
from core.anomaly_engine import anomaly_engine
from core.utils import (
    format_bytes,
    format_bps,
    format_timestamp,
    format_timestamp_full,
    classify_ip,
    get_severity_color
)
import attack_simulator

# -----------------------------------------------------------------------------
# PAGE CONFIGURATION & STYLING
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="LANGuard - Network IDS & Anomaly Monitor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom High-Tech Cyber Theme CSS
st.markdown("""
<style>
    /* Metric Cards */
    div[data-testid="stMetric"] {
        background-color: #111827;
        border: 1px solid #1F2937;
        padding: 12px 18px;
        border-radius: 8px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2);
    }
    div[data-testid="stMetricLabel"] {
        color: #9CA3AF !important;
        font-size: 0.85rem !important;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    div[data-testid="stMetricValue"] {
        color: #F9FAFB !important;
        font-size: 1.8rem !important;
        font-weight: 700;
    }
    
    /* Status Pills */
    .status-badge-running {
        display: inline-block;
        background-color: #064E3B;
        color: #34D399;
        border: 1px solid #059669;
        padding: 4px 12px;
        border-radius: 9999px;
        font-weight: 600;
        font-size: 0.85rem;
    }
    .status-badge-stopped {
        display: inline-block;
        background-color: #7F1D1D;
        color: #F87171;
        border: 1px solid #DC2626;
        padding: 4px 12px;
        border-radius: 9999px;
        font-weight: 600;
        font-size: 0.85rem;
    }
    
    /* Code highlight box */
    .code-cn-box {
        background-color: #0d1117;
        border: 1px solid #30363d;
        border-left: 4px solid #58a6ff;
        padding: 12px 16px;
        border-radius: 6px;
        margin-bottom: 12px;
        font-family: monospace;
    }
</style>
""", unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# SESSION STATE INITIALIZATION
# -----------------------------------------------------------------------------
if "sniffer_running" not in st.session_state:
    st.session_state.sniffer_running = False
if "selected_interface" not in st.session_state:
    st.session_state.selected_interface = None
if "sim_output" not in st.session_state:
    st.session_state.sim_output = ""
if "last_refresh_time" not in st.session_state:
    st.session_state.last_refresh_time = time.time()
if "locked_packet_id" not in st.session_state:
    st.session_state.locked_packet_id = None
if "locked_alert_id" not in st.session_state:
    st.session_state.locked_alert_id = None
if "packet_page" not in st.session_state:
    st.session_state.packet_page = 0

# -----------------------------------------------------------------------------
# SIDEBAR CONTROLS
# -----------------------------------------------------------------------------
with st.sidebar:
    st.title("🛡️ LANGuard Control")
    st.markdown("**Real-Time Network IDS & Monitor**")
    st.caption("Computer Networks Laboratory System")
    st.markdown("---")

    # 1. Interface Discovery
    interfaces = sniffer.get_available_interfaces()
    iface_options = {f"{i['name']} ({i['ip']})": i['name'] for i in interfaces}
    if not iface_options:
        iface_options = {"Default Interface": None}

    selected_label = st.selectbox(
        "🌐 Network Interface",
        options=list(iface_options.keys()),
        index=0,
        help="Select the network adapter (Wi-Fi, Ethernet, or Loopback) to sniff packets on."
    )
    chosen_iface_name = iface_options[selected_label]
    sniffer.interface = chosen_iface_name

    if chosen_iface_name:
        st.caption(f"📡 Selected Interface: **{chosen_iface_name}**")
        st.caption("*(To see live website traffic like w3schools.com, ensure Wi-Fi is selected)*")

    # 2. BPF Packet Capture Filter
    bpf_filter = st.text_input(
        "🔍 BPF Filter (Optional)",
        value="",
        placeholder="e.g. ip, tcp, port 80",
        help="Berkeley Packet Filter syntax (e.g. 'ip', 'tcp or udp', 'not broadcast'). Leave empty to capture all LAN traffic."
    )

    # 3. Start / Stop Sniffer
    col1, col2 = st.columns(2)
    with col1:
        if not sniffer.is_running:
            if st.button("▶️ Start Capture", use_container_width=True, type="primary"):
                sniffer.start(bpf_filter=bpf_filter)
                st.session_state.sniffer_running = True
                st.rerun()
        else:
            if st.button("⏹️ Stop Capture", use_container_width=True, type="secondary"):
                sniffer.stop()
                st.session_state.sniffer_running = False
                st.rerun()

    with col2:
        if st.button("🗑️ Clear DB", use_container_width=True, help="Wipe database tables for a fresh test run"):
            db_manager.clear_database()
            st.success("Database cleared!")
            st.rerun()

    # Capture Status Indicator
    st.markdown("<br>", unsafe_allow_html=True)
    if sniffer.is_running:
        st.markdown('<div class="status-badge-running">● SNIFFER ACTIVE (CAPTURING)</div>', unsafe_allow_html=True)
    else:
        st.markdown('<div class="status-badge-stopped">○ SNIFFER STOPPED</div>', unsafe_allow_html=True)

    st.markdown("---")
    
    # 4. Auto-Refresh Settings
    st.subheader("⚙️ Dashboard Settings")
    auto_refresh = st.checkbox("Auto-Refresh Dashboard", value=True)
    refresh_rate = st.slider("Refresh Interval (seconds)", min_value=1, max_value=10, value=DASHBOARD_REFRESH_RATE)

    st.markdown("---")
    st.caption("LANGuard v2.4 | Academic CN Edition")
    st.caption("RFC 791 / RFC 793 / RFC 826 / RFC 1035")

# -----------------------------------------------------------------------------
# TOP HEADER & OVERALL TELEMETRY METRICS
# -----------------------------------------------------------------------------
summary = db_manager.get_summary_stats()
latest_anomaly = anomaly_engine.get_latest_stats()

header_col1, header_col2 = st.columns([3, 1])
with header_col1:
    st.title("LANGuard: Real-Time LAN Intrusion Detection & Traffic Monitor")
    st.markdown(
        "*Real-time packet inspection, Layer 2-7 protocol disassembly, rule-based IDS, and statistical anomaly detection.*"
    )

with header_col2:
    st.metric(
        "Capture State",
        "RUNNING" if sniffer.is_running else "PAUSED",
        f"{sniffer.total_captured:,} pkts processed"
    )

# 5 KPI Metric Cards
kpi1, kpi2, kpi3, kpi4, kpi5 = st.columns(5)
with kpi1:
    st.metric("Total Packets Logged", f"{summary['total_packets']:,}")
with kpi2:
    st.metric("Total Traffic Volume", format_bytes(summary['total_bytes']))
with kpi3:
    st.metric("Security Alerts", f"{summary['total_alerts']}", delta=f"{summary['total_alerts']} Events", delta_color="inverse")
with kpi4:
    st.metric("Active LAN Hosts", f"{summary['total_hosts']}")
with kpi5:
    z_val = latest_anomaly.get("z_score_pps", 0.0)
    st.metric(
        "Current Rate (pps)",
        f"{latest_anomaly.get('current_pps', 0)} pps",
        delta=f"Z-Score: {z_val:.2f}" if abs(z_val) > 0.1 else "Normal Baseline",
        delta_color="inverse" if latest_anomaly.get("is_anomaly") else "off"
    )

st.markdown("---")

# -----------------------------------------------------------------------------
# MAIN APPLICATION TABS
# -----------------------------------------------------------------------------
tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
    "📡 Live Packet Stream",
    "📊 Protocol & Traffic Analytics",
    "🛡️ Intrusion Alerts (IDS)",
    "📈 Anomaly Detection (Z-Score)",
    "🌐 LAN Host & DNS Inventory",
    "🎯 Attack & Demo Simulator",
    "🎓 Computer Networks Code & Viva Guide"
])

# -----------------------------------------------------------------------------
# TAB 1: LIVE PACKET STREAM & HISTORICAL DATABASE VIEWER
# -----------------------------------------------------------------------------
with tab1:
    st.subheader("Network Packet Stream & Historical Database Archive")
    st.caption("All packets are persistently saved to SQLite (`languard.db`). Click on any row directly in the table to inspect its Layer 2 - 7 headers below.")

    # 1. Historical Filtering & Search Controls
    f_col1, f_col2, f_col3 = st.columns([1, 1, 2])
    with f_col1:
        proto_filter = st.selectbox("Protocol Filter", ["All", "TCP", "UDP", "ICMP", "ARP"], index=0, key="stream_proto_filter")
    with f_col2:
        page_size_options = [50, 100, 250, 500, 1000]
        selected_page_size = st.selectbox("Packets Per Page", page_size_options, index=1, key="stream_page_size")
    with f_col3:
        search_kw = st.text_input("Search Stored History (IP, Domain, Port, Summary, ID)", placeholder="e.g. 192.168.1.1, google.com, 443, SYN", key="stream_search_input")

    # Calculate pagination offset
    page_size = int(selected_page_size)
    current_page = st.session_state.packet_page
    offset = current_page * page_size

    # Query persistent SQLite database with filters and pagination
    packets_list, total_count = db_manager.get_packets_paged(
        limit=page_size,
        offset=offset,
        proto=proto_filter,
        search=search_kw
    )

    max_pages = max(1, (total_count + page_size - 1) // page_size)
    if current_page >= max_pages:
        st.session_state.packet_page = max(0, max_pages - 1)
        current_page = st.session_state.packet_page
        offset = current_page * page_size

    # 2. Pagination Navigation Bar
    p_nav1, p_nav2, p_nav3 = st.columns([2, 1, 1])
    with p_nav1:
        start_idx = offset + 1 if total_count > 0 else 0
        end_idx = min(offset + len(packets_list), total_count)
        st.markdown(f"**Showing Packets:** `{start_idx} - {end_idx}` of `{total_count:,}` stored in database | **Page** `{current_page + 1}` of `{max_pages}`")
    with p_nav2:
        if st.button("◀ Previous Page", use_container_width=True, disabled=(current_page <= 0)):
            st.session_state.packet_page = max(0, current_page - 1)
            st.rerun()
    with p_nav3:
        if st.button("Next Page ▶", use_container_width=True, disabled=(current_page >= max_pages - 1)):
            st.session_state.packet_page = min(max_pages - 1, current_page + 1)
            st.rerun()

    if packets_list:
        df_pkts = pd.DataFrame(packets_list)

        # Format columns for display
        df_display = pd.DataFrame()
        df_display["ID"] = df_pkts["id"]
        df_display["Time"] = df_pkts["timestamp"].apply(format_timestamp)
        df_display["L4 Proto"] = df_pkts["layer4_proto"]
        df_display["App/Service"] = df_pkts["app_proto"]
        df_display["Source"] = df_pkts.apply(
            lambda r: r["src_host"] if r["src_host"] and r["src_host"] != r["src_ip"] else r["src_ip"], axis=1
        )
        df_display["Src Port"] = df_pkts["src_port"].fillna("-").astype(str).replace(".0", "")
        df_display["Destination"] = df_pkts.apply(
            lambda r: r["dst_host"] if r["dst_host"] and r["dst_host"] != r["dst_ip"] else r["dst_ip"], axis=1
        )
        df_display["Dst Port"] = df_pkts["dst_port"].fillna("-").astype(str).replace(".0", "")
        df_display["Flags"] = df_pkts["tcp_flags"].replace("", "-")
        df_display["Bytes"] = df_pkts["packet_length"]
        df_display["Summary"] = df_pkts["summary"]

        cols_to_show = ["ID", "Time", "L4 Proto", "App/Service", "Source", "Src Port", "Destination", "Dst Port", "Flags", "Bytes", "Summary"]

        st.caption("👆 **Click on any row directly in the table below to inspect its detailed headers and payload.** (No dropdown needed!)")
        
        # Interactive table selection (native single-row click in Streamlit)
        table_selection = st.dataframe(
            df_display[cols_to_show],
            use_container_width=True,
            hide_index=True,
            on_select="rerun",
            selection_mode="single-row",
            key="live_packet_table"
        )

        # Handle direct row click
        if table_selection and hasattr(table_selection, "selection") and table_selection.selection.rows:
            clicked_idx = table_selection.selection.rows[0]
            if clicked_idx < len(df_display):
                clicked_id = int(df_display.iloc[clicked_idx]["ID"])
                st.session_state.locked_packet_id = clicked_id

        # -------------------------------------------------------------
        # DETAILED PACKET DISSECTION INSPECTOR (SHOWN BELOW THE TABLE)
        # -------------------------------------------------------------
        st.markdown("---")
        st.markdown("#### 🔬 Detailed Packet Inspector (Layer 2 - Layer 7 Dissection)")

        # Render Inspected Packet
        if st.session_state.locked_packet_id is not None:
            # Retrieve packet directly from SQLite by ID (works for any historical or current packet!)
            pkt_row = db_manager.get_packet_by_id(st.session_state.locked_packet_id)
            if pkt_row:
                insp_head1, insp_head2 = st.columns([4, 1])
                with insp_head1:
                    st.markdown(f"""
                    <div style="background-color: #064E3B; border: 1px solid #059669; padding: 10px 16px; border-radius: 6px; margin-bottom: 12px; display: flex; justify-content: space-between; align-items: center;">
                        <span style="color: #34D399; font-weight: 700; font-size: 1rem;">🔒 INSPECTING PACKET #{pkt_row['id']}</span>
                        <span style="color: #A7F3D0; font-size: 0.85rem;">Captured: {format_timestamp_full(pkt_row['timestamp'])} | Frame Size: {pkt_row['packet_length']} Bytes</span>
                    </div>
                    """, unsafe_allow_html=True)
                with insp_head2:
                    if st.button("🔓 Clear Selection", use_container_width=True, help="Deselect this packet"):
                        st.session_state.locked_packet_id = None
                        st.rerun()

                p_col1, p_col2 = st.columns(2)
                with p_col1:
                    st.markdown("##### 🌐 Layer 2 & 3: Frame / Network Headers")
                    st.markdown(f"""
                    - **Packet Database ID:** `#{pkt_row['id']}`
                    - **Frame Arrival Time:** `{format_timestamp_full(pkt_row['timestamp'])}`
                    - **Data Link Encapsulation:** Ethernet II (Layer 2)
                    - **Layer 3 Protocol:** `{pkt_row['layer3_proto']}`
                    - **Source IP Address:** `{pkt_row['src_ip']}` `[{classify_ip(pkt_row['src_ip'])}]`
                    - **Resolved Source Host:** `{pkt_row['src_host'] or 'Unresolved'}`
                    - **Destination IP Address:** `{pkt_row['dst_ip']}` `[{classify_ip(pkt_row['dst_ip'])}]`
                    - **Resolved Destination Host:** `{pkt_row['dst_host'] or 'Unresolved'}`
                    - **Time to Live (TTL):** `{pkt_row.get('ip_ttl') or 'N/A'}` hops
                    - **IP Packet Identification:** `{pkt_row.get('ip_id') or 'N/A'}`
                    """)

                with p_col2:
                    st.markdown("##### ⚡ Layer 4 & 7: Transport & Application")
                    st.markdown(f"""
                    - **Transport Protocol:** `{pkt_row['layer4_proto']}`
                    - **Source Port:** `{pkt_row['src_port'] or 'N/A'}`
                    - **Destination Port:** `{pkt_row['dst_port'] or 'N/A'}`
                    - **Application / Service:** `{pkt_row['app_proto'] or 'N/A'}`
                    - **TCP Sequence Number:** `{pkt_row.get('tcp_seq') or 'N/A'}`
                    - **TCP Acknowledgment Number:** `{pkt_row.get('tcp_ack') or 'N/A'}`
                    - **TCP Receive Window Size:** `{pkt_row.get('tcp_window') or 'N/A'}` bytes
                    - **Total Frame Length:** `{pkt_row['packet_length']} Bytes`
                    """)

                # TCP Control Flags Breakdown Visualizer
                if pkt_row['layer4_proto'] == "TCP":
                    st.markdown("###### TCP Control Flags Breakdown (RFC 793):")
                    flag_str = pkt_row['tcp_flags'] or ""
                    flag_cols = st.columns(6)
                    flags_to_check = [("SYN", "0x02"), ("ACK", "0x10"), ("FIN", "0x01"), ("RST", "0x04"), ("PSH", "0x08"), ("URG", "0x20")]
                    for idx, (fname, fmask) in enumerate(flags_to_check):
                        is_active = fname in flag_str
                        with flag_cols[idx]:
                            if is_active:
                                st.markdown(f"<div style='background-color: #065F46; border: 1px solid #10B981; color: #34D399; text-align: center; border-radius: 4px; padding: 4px 0;'><b>[{fname}]</b><br><small>{fmask}</small></div>", unsafe_allow_html=True)
                            else:
                                st.markdown(f"<div style='background-color: #1F2937; border: 1px solid #374151; color: #6B7280; text-align: center; border-radius: 4px; padding: 4px 0;'>{fname}<br><small>{fmask}</small></div>", unsafe_allow_html=True)

                st.markdown("<br>", unsafe_allow_html=True)
                st.info(f"**Dissection Summary:** {pkt_row['summary']}")

                # Application Layer Payload Preview (Hex & ASCII)
                if pkt_row.get('payload_ascii'):
                    with st.expander("📦 Application Layer Payload Preview (ASCII / Data Load)", expanded=True):
                        st.code(pkt_row['payload_ascii'], language="text")
            else:
                st.warning(f"Packet #{st.session_state.locked_packet_id} was not found in database.")
        else:
            st.info("👆 **No packet selected.** Click on any row in the table above to view its complete Computer Networks header breakdown and payload here.")

        # -------------------------------------------------------------
        # EXPORT FEATURE (FULFILLS ABSTRACT PROMISE)
        # -------------------------------------------------------------
        st.markdown("---")
        with st.expander("📥 Export Traffic Summaries & Detection Logs (For Future Analysis)"):
            st.caption("As specified in the system abstract: SQLite can be used to store relevant traffic summaries and detection logs for future forensic analysis.")
            exp_col1, exp_col2 = st.columns(2)
            with exp_col1:
                export_packets = db_manager.get_all_packets_for_export(limit=5000)
                if export_packets:
                    df_exp_p = pd.DataFrame(export_packets)
                    st.download_button(
                        "📄 Download Captured Packets (CSV)",
                        data=df_exp_p.to_csv(index=False),
                        file_name=f"languard_packets_{int(time.time())}.csv",
                        mime="text/csv",
                        use_container_width=True
                    )
            with exp_col2:
                export_alerts = db_manager.get_all_alerts_for_export(limit=1000)
                if export_alerts:
                    df_exp_a = pd.DataFrame(export_alerts)
                    st.download_button(
                        "🚨 Download Security Alerts Log (CSV)",
                        data=df_exp_a.to_csv(index=False),
                        file_name=f"languard_alerts_{int(time.time())}.csv",
                        mime="text/csv",
                        use_container_width=True
                    )
    else:
        st.info("No packets found in database matching your filter. Start capture or run an attack test from Tab 6!")

# -----------------------------------------------------------------------------
# TAB 2: PROTOCOL & TRAFFIC ANALYTICS
# -----------------------------------------------------------------------------
with tab2:
    st.subheader("Network Protocol Distribution & Traffic Trends")
    
    # 1. Protocol Distribution
    proto_dist = db_manager.get_protocol_distribution()
    p_col1, p_col2 = st.columns(2)

    with p_col1:
        st.markdown("##### Layer 4 / Protocol Breakdown")
        if proto_dist:
            df_proto = pd.DataFrame(list(proto_dist.items()), columns=["Protocol", "Packets"])
            fig_pie = px.pie(
                df_proto,
                names="Protocol",
                values="Packets",
                hole=0.45,
                color="Protocol",
                color_discrete_map={
                    "TCP": "#3B82F6",
                    "UDP": "#10B981",
                    "ICMP": "#F59E0B",
                    "ARP": "#EC4899",
                    "Other": "#8B5CF6"
                }
            )
            fig_pie.update_layout(
                margin=dict(t=20, b=20, l=20, r=20),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#E5E7EB")
            )
            st.plotly_chart(fig_pie, use_container_width=True)
        else:
            st.info("Awaiting traffic to compile protocol distribution...")

    with p_col2:
        st.markdown("##### Packet Size Distribution (Bytes)")
        pkts_sample = db_manager.get_recent_packets(limit=300)
        if pkts_sample:
            df_sizes = pd.DataFrame(pkts_sample)
            fig_hist = px.histogram(
                df_sizes,
                x="packet_length",
                nbins=25,
                labels={"packet_length": "Frame Length (Bytes)"},
                color_discrete_sequence=["#06B6D4"]
            )
            fig_hist.update_layout(
                margin=dict(t=20, b=20, l=20, r=20),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#E5E7EB")
            )
            st.plotly_chart(fig_hist, use_container_width=True)
        else:
            st.info("Awaiting packet length statistics...")

    # 2. Real-Time Time-Series Throughput Chart
    st.markdown("##### Real-Time Throughput Timeline (Packets/sec & Bytes/sec)")
    metrics = db_manager.get_time_series_metrics(limit_seconds=60)
    if metrics:
        df_metrics = pd.DataFrame(metrics)
        df_metrics["Time"] = df_metrics["timestamp"].apply(format_timestamp)
        df_metrics["KBps"] = df_metrics["byte_count"] / 1024.0

        fig_ts = go.Figure()
        fig_ts.add_trace(go.Scatter(
            x=df_metrics["Time"],
            y=df_metrics["packet_count"],
            name="Packets / Sec",
            line=dict(color="#3B82F6", width=2.5),
            mode="lines+markers"
        ))
        fig_ts.add_trace(go.Scatter(
            x=df_metrics["Time"],
            y=df_metrics["tcp_count"],
            name="TCP Packets",
            line=dict(color="#60A5FA", width=1.5, dash="dot"),
        ))
        fig_ts.add_trace(go.Scatter(
            x=df_metrics["Time"],
            y=df_metrics["udp_count"],
            name="UDP Packets",
            line=dict(color="#34D399", width=1.5, dash="dot"),
        ))
        fig_ts.add_trace(go.Scatter(
            x=df_metrics["Time"],
            y=df_metrics["icmp_count"],
            name="ICMP Packets",
            line=dict(color="#F87171", width=1.5, dash="dot"),
        ))
        fig_ts.update_layout(
            xaxis_title="Time",
            yaxis_title="Packets / Second",
            margin=dict(t=30, b=20, l=20, r=20),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#E5E7EB"),
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
        )
        st.plotly_chart(fig_ts, use_container_width=True)
    else:
        st.info("Collecting time-series throughput samples...")

# -----------------------------------------------------------------------------
# TAB 3: INTRUSION DETECTION SYSTEM (IDS) ALERTS
# -----------------------------------------------------------------------------
with tab3:
    st.subheader("🛡️ Rule-Based Intrusion Detection System (IDS)")
    st.caption("Active Signatures: Vertical Port Scan, Horizontal Sweep, SYN Flood, ICMP Flood, UDP Flood, Stealth Scans (Xmas/NULL), ARP Poisoning, Cleartext Services")

    alerts = db_manager.get_recent_alerts(limit=RECENT_ALERTS_DISPLAY_LIMIT)

    col_stat1, col_stat2, col_stat3, col_stat4 = st.columns(4)
    crit_count = sum(1 for a in alerts if a["severity"] == "CRITICAL")
    high_count = sum(1 for a in alerts if a["severity"] == "HIGH")
    med_count = sum(1 for a in alerts if a["severity"] == "MEDIUM")
    low_count = sum(1 for a in alerts if a["severity"] == "LOW")

    with col_stat1:
        st.markdown(f"<div style='border-left: 4px solid #EF4444; padding-left: 8px;'><b>CRITICAL:</b> {crit_count}</div>", unsafe_allow_html=True)
    with col_stat2:
        st.markdown(f"<div style='border-left: 4px solid #F97316; padding-left: 8px;'><b>HIGH:</b> {high_count}</div>", unsafe_allow_html=True)
    with col_stat3:
        st.markdown(f"<div style='border-left: 4px solid #EAB308; padding-left: 8px;'><b>MEDIUM:</b> {med_count}</div>", unsafe_allow_html=True)
    with col_stat4:
        st.markdown(f"<div style='border-left: 4px solid #3B82F6; padding-left: 8px;'><b>LOW / INFO:</b> {low_count}</div>", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    if alerts:
        df_alerts = pd.DataFrame(alerts)
        df_alerts["Time"] = df_alerts["timestamp"].apply(format_timestamp)
        
        # Display Alerts Table with Direct Row Click Selection
        df_alerts_display = df_alerts.copy()
        df_alerts_display["ID"] = df_alerts["id"]
        cols_alert = ["ID", "Time", "severity", "alert_type", "src_host", "dst_host", "status", "signature"]

        st.caption("👆 **Direct Table Selection:** Click on any security alert row directly in the table to review its forensic details and mitigation below.")
        alert_selection = st.dataframe(
            df_alerts_display[cols_alert],
            use_container_width=True,
            hide_index=True,
            on_select="rerun",
            selection_mode="single-row",
            key="alerts_table_view"
        )

        if alert_selection and hasattr(alert_selection, "selection") and alert_selection.selection.rows:
            a_idx = alert_selection.selection.rows[0]
            if a_idx < len(df_alerts_display):
                st.session_state.locked_alert_id = int(df_alerts_display.iloc[a_idx]["ID"])

        # Render Forensic Details for the selected alert
        matching_rows = df_alerts[df_alerts["id"] == st.session_state.locked_alert_id]
        alert_row = matching_rows.iloc[0] if not matching_rows.empty else df_alerts.iloc[0]
        sev_color = get_severity_color(alert_row['severity'])

        st.markdown(f"""
        <div style="background-color: #1F2937; border-left: 6px solid {sev_color}; padding: 16px; border-radius: 8px;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <h3 style="margin-top: 0; color: {sev_color};">[{alert_row['severity']}] {alert_row['alert_type']}</h3>
                <span style="background-color: #374151; color: #E5E7EB; padding: 2px 8px; border-radius: 4px; font-size: 0.85rem;">Investigation Status: <b>{alert_row.get('status', 'Under Investigation')}</b></span>
            </div>
            <p><b>Signature ID:</b> <code>{alert_row['signature']}</code> | <b>Timestamp:</b> {format_timestamp_full(alert_row['timestamp'])}</p>
            <p><b>Attacker (Source):</b> {alert_row['src_host']} ({alert_row['src_ip']})</p>
            <p><b>Target (Destination):</b> {alert_row['dst_host']} ({alert_row['dst_ip']})</p>
            <hr style="border-color: #374151;">
            <p><b>Description & RFC State Violation:</b><br>{alert_row['description']}</p>
            <p><b>Recommended Computer Networks Mitigation:</b><br><span style="color: #6EE7B7;">🛡️ {alert_row['mitigation']}</span></p>
        </div>
        """, unsafe_allow_html=True)

        # Investigation & Triage Section (Matches Abstract: "These alerts indicate potential threats and require further investigation rather than confirming an attack")
        st.markdown("<br>", unsafe_allow_html=True)
        with st.expander(f"🕵️ Analyst Incident Triage & Forensic Notes (Alert #{alert_row['id']})", expanded=True):
            st.caption("As highlighted in the project abstract: alerts indicate potential threats requiring further investigation rather than confirming an attack. Use this console to classify and document your findings.")
            inv_col1, inv_col2 = st.columns([1, 2])
            with inv_col1:
                curr_status = alert_row.get("status") or "Under Investigation"
                status_choices = ["Under Investigation", "Confirmed Security Threat", "False Positive / Benign Noise", "Mitigated / Resolved"]
                default_s_idx = status_choices.index(curr_status) if curr_status in status_choices else 0
                new_status = st.selectbox("Investigation Verdict", status_choices, index=default_s_idx, key=f"inv_status_{alert_row['id']}")
            with inv_col2:
                notes_val = st.text_input("Analyst Forensic Notes", value=alert_row.get("notes") or "", placeholder="e.g. Verified student testing port scanner; firewall rule applied to block host.", key=f"inv_notes_{alert_row['id']}")
            
            if st.button("💾 Save Investigation Verdict", key=f"save_verdict_{alert_row['id']}"):
                db_manager.update_alert_investigation(alert_row['id'], new_status, notes_val)
                st.success(f"Updated Alert #{alert_row['id']} to '{new_status}'!")
                st.rerun()

    else:
        st.success("✅ No intrusion attempts detected. Network status is healthy! Run an attack test from Tab 6 to trigger IDS rules.")

# -----------------------------------------------------------------------------
# TAB 4: STATISTICAL ANOMALY DETECTION
# -----------------------------------------------------------------------------
with tab4:
    st.subheader("📈 Statistical Anomaly Detection (Z-Score & Dynamic Baseline)")
    st.caption("Detects sudden traffic surges, flash crowds, and volumetric DDoS using sliding-window Gaussian distribution modeling.")

    stat_col1, stat_col2, stat_col3, stat_col4 = st.columns(4)
    with stat_col1:
        st.metric("Instantaneous Rate", f"{latest_anomaly['current_pps']} pps")
    with stat_col2:
        st.metric("Rolling Baseline (μ)", f"{latest_anomaly['mean_pps']:.1f} pps")
    with stat_col3:
        st.metric("Dispersion (StdDev σ)", f"{latest_anomaly['std_pps']:.1f}")
    with stat_col4:
        st.metric("Z-Score Distance (Z)", f"{latest_anomaly['z_score_pps']:.2f}",
                  delta="Outlier (>3.0)" if latest_anomaly.get("is_anomaly") else "Within Envelope",
                  delta_color="inverse" if latest_anomaly.get("is_anomaly") else "off")

    st.markdown("---")
    
    # Anomaly visualization curve
    metrics_history = db_manager.get_time_series_metrics(limit_seconds=60)
    if len(metrics_history) >= 5:
        df_ano = pd.DataFrame(metrics_history)
        df_ano["Time"] = df_ano["timestamp"].apply(format_timestamp)
        
        # Calculate rolling mean and threshold envelope
        window = min(10, len(df_ano))
        df_ano["Rolling_Mean"] = df_ano["packet_count"].rolling(window=window, min_periods=1).mean()
        df_ano["Rolling_Std"] = df_ano["packet_count"].rolling(window=window, min_periods=1).std().fillna(1.0)
        df_ano["Upper_Threshold_3Sigma"] = df_ano["Rolling_Mean"] + (3.0 * df_ano["Rolling_Std"])

        fig_ano = go.Figure()
        # Upper threshold envelope
        fig_ano.add_trace(go.Scatter(
            x=df_ano["Time"],
            y=df_ano["Upper_Threshold_3Sigma"],
            name="Anomaly Upper Threshold (μ + 3σ)",
            line=dict(color="#EF4444", width=2, dash="dash"),
            fill=None
        ))
        # Rolling baseline
        fig_ano.add_trace(go.Scatter(
            x=df_ano["Time"],
            y=df_ano["Rolling_Mean"],
            name="Baseline Average (μ)",
            line=dict(color="#10B981", width=2),
            fill=None
        ))
        # Actual Observed Traffic
        fig_ano.add_trace(go.Scatter(
            x=df_ano["Time"],
            y=df_ano["packet_count"],
            name="Observed Traffic (pps)",
            line=dict(color="#3B82F6", width=2.5),
            mode="lines+markers"
        ))

        fig_ano.update_layout(
            title="Statistical Baseline vs. Observed Traffic Rate (Z-Score Modeling)",
            xaxis_title="Time",
            yaxis_title="Packets Per Second (pps)",
            margin=dict(t=40, b=20, l=20, r=20),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#E5E7EB"),
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
        )
        st.plotly_chart(fig_ano, use_container_width=True)
    else:
        st.info("Gathering historical data points to construct the Gaussian threshold envelope...")

# -----------------------------------------------------------------------------
# TAB 5: LAN HOST INVENTORY & REVERSE DNS RESOLUTION
# -----------------------------------------------------------------------------
with tab5:
    st.subheader("🌐 LAN Host Inventory & Passive/Active DNS Resolution")
    st.caption("Automatically correlates IP addresses with domain names (Google, GitHub, Wikipedia, etc.) and profiles local hosts.")

    hosts = db_manager.get_top_talkers(limit=TOP_TALKERS_LIMIT * 3)

    if hosts:
        df_hosts = pd.DataFrame(hosts)
        df_hosts["Classification"] = df_hosts["ip"].apply(classify_ip)
        df_hosts["Bandwidth"] = df_hosts["total_bytes"].apply(format_bytes)
        df_hosts["Last Active"] = df_hosts["last_seen"].apply(format_timestamp)
        
        # Display Top Talkers Bar Chart
        st.markdown("##### Top Bandwidth Consumers (Top Talkers)")
        df_top = df_hosts.head(8)
        fig_bar = px.bar(
            df_top,
            x="total_bytes",
            y="display_name",
            orientation="h",
            labels={"total_bytes": "Total Transferred (Bytes)", "display_name": "Host / Website"},
            color="total_bytes",
            color_continuous_scale="Viridis"
        )
        fig_bar.update_layout(
            margin=dict(t=20, b=20, l=20, r=20),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#E5E7EB"),
            yaxis=dict(autorange="reversed")
        )
        st.plotly_chart(fig_bar, use_container_width=True)

        # Full Host Matrix
        st.markdown("##### Active Endpoints Table")
        cols_hosts = ["ip", "display_name", "mac", "Classification", "total_packets", "Bandwidth", "alert_count", "Last Active"]
        st.dataframe(
            df_hosts[cols_hosts],
            use_container_width=True,
            hide_index=True
        )
    else:
        st.info("No hosts discovered yet. Start the sniffer to discover active network devices.")

# -----------------------------------------------------------------------------
# TAB 6: ATTACK & DEMO SIMULATOR
# -----------------------------------------------------------------------------
with tab6:
    st.subheader("🎯 Built-in Attack & Network Traffic Simulation Suite")
    st.markdown("""
    Use these pre-built, benign test generators to demonstrate LANGuard's detection capabilities
    live during laboratory evaluations, viva examinations, and project demonstrations!
    """)

    sim_target = st.text_input("Simulation Target IP", value="127.0.0.1", help="Target IP for generated test packets. 127.0.0.1 tests locally without leaving your machine.")

    col_btn1, col_btn2, col_btn3 = st.columns(3)
    col_btn4, col_btn5, col_btn6 = st.columns(3)

    with col_btn1:
        if st.button("🚀 Vertical Port Scan", use_container_width=True):
            st.session_state.sim_output = attack_simulator.simulate_vertical_port_scan(target_ip=sim_target)
            st.rerun()

    with col_btn2:
        if st.button("💥 TCP SYN Flood (DoS)", use_container_width=True):
            st.session_state.sim_output = attack_simulator.simulate_syn_flood(target_ip=sim_target)
            st.rerun()

    with col_btn3:
        if st.button("🌊 ICMP Ping Flood", use_container_width=True):
            st.session_state.sim_output = attack_simulator.simulate_icmp_ping_flood(target_ip=sim_target)
            st.rerun()

    with col_btn4:
        if st.button("🕵️ Stealth Scans (Xmas & NULL)", use_container_width=True):
            st.session_state.sim_output = attack_simulator.simulate_stealth_scans(target_ip=sim_target)
            st.rerun()

    with col_btn5:
        if st.button("🌐 DNS Resolution Test", use_container_width=True):
            st.session_state.sim_output = attack_simulator.simulate_dns_activity()
            st.rerun()

    with col_btn6:
        if st.button("⚡ Traffic Anomaly Burst", use_container_width=True):
            st.session_state.sim_output = attack_simulator.simulate_traffic_burst(target_ip=sim_target)
            st.rerun()

    if st.session_state.sim_output:
        st.success(st.session_state.sim_output)

    # Live Website Traffic Tester & Domain Resolver
    st.markdown("---")
    st.markdown("#### 🌐 Live Website Traffic Tester & Domain Resolver")
    st.caption("Generate real HTTPS packets with TLS Server Name Indication (SNI) to test any website (e.g. `w3schools.com`, `google.com`, `github.com`). The website name will immediately show in Tab 1!")

    web_col1, web_col2 = st.columns([3, 1])
    with web_col1:
        target_web = st.text_input("Enter Website Domain to Test", value="w3schools.com", key="web_tester_domain_input")
    with web_col2:
        st.markdown("<div style='margin-top: 28px;'></div>", unsafe_allow_html=True)
        if st.button("🌐 Send Website Packets", use_container_width=True):
            st.session_state.sim_output = attack_simulator.test_website_traffic(target_web)
            st.rerun()

    st.markdown("---")
    st.info("💡 **Tip for Presentation:** Start the sniffer in the sidebar (using Wi-Fi for internet or Loopback for local tests), click any attack button or website test above, and switch back to **Tab 1 (Live Packets)** or **Tab 3 (IDS Alerts)** to watch the events appear instantaneously!")

# -----------------------------------------------------------------------------
# TAB 7: COMPUTER NETWORKS CODE & VIVA GUIDE (MAM'S EXAM GUIDE)
# -----------------------------------------------------------------------------
with tab7:
    st.subheader("🎓 Computer Networks (CN) Code Architecture & Viva Guide")
    st.markdown("""
    This section is designed to help you explain the project to your teacher or examiner ("Mam").
    It maps every major syllabus topic of **Computer Networks** directly to the exact file and lines of code in LANGuard!
    """)

    st.markdown("### 📂 Map of Networking Code in LANGuard")
    st.markdown("""
| Computer Networks Concept | Relevant File | Key Function / Class | What to Explain to Mam |
| :--- | :--- | :--- | :--- |
| **Layer 2 Data Link & ARP** | `core/protocols.py`<br>`core/ids_engine.py` | `dissect_packet()`<br>`_arp_table` check | Explain how ARP maps IP to MAC (RFC 826) and how LANGuard detects ARP spoofing (conflicting MAC addresses for an IP). |
| **Layer 3 IPv4 Protocol Header** | `core/protocols.py` | `dissect_packet()` (Case 2) | Explain IPv4 header fields: TTL (Time to Live), Protocol number (6 for TCP, 17 for UDP, 1 for ICMP), Source & Destination IP addresses. |
| **Layer 4 TCP 3-Way Handshake & Flags** | `core/protocols.py`<br>`core/ids_engine.py` | `parse_tcp_flags()`<br>`_tcp_syn_history` | Explain TCP control bits (SYN, ACK, FIN, RST, PSH, URG). Show how SYN flood exhausts the server's half-open backlog queue without ACK. |
| **Port Scanning Detection** | `core/ids_engine.py` | `_vertical_scan_tracker` | Explain vertical scan (probing 15+ ports on 1 IP) and horizontal sweep (probing 1 port across multiple LAN IPs). |
| **Stealth Scans (RFC Violations)** | `core/ids_engine.py` | `DETECT_XMAS_SCAN`<br>`DETECT_NULL_SCAN` | Explain how Xmas scan sets FIN+PSH+URG and NULL scan sets 0 flags, violating TCP RFC 793 to bypass naive firewalls. |
| **ICMP Ping Flood (DoS)** | `core/ids_engine.py` | `_icmp_echo_history` | Explain ICMP Type 8 (Echo Request) and Type 0 (Echo Reply), and how ping flooding exhausts link bandwidth. |
| **Application Layer: DNS Snooping** | `core/dns_resolver.py`<br>`core/protocols.py` | `_extract_dns_records()`<br>`learn_dns_mapping()` | Explain RFC 1035: Intercepting DNS A records (Type 1) to passively map IP addresses to domain names (e.g. google.com). |
| **Statistical Traffic Anomaly** | `core/anomaly_engine.py` | `record_interval_metric()` | Explain Gaussian distribution, moving average (μ), standard deviation (σ), and how Z-score ($Z > 3.0$) detects abnormal surges. |
    """)

    st.markdown("### 🔍 Highlighted Code Snippets to Open & Show")
    
    with st.expander("1. Show TCP Flag Dissection & 3-Way Handshake (`core/protocols.py`)", expanded=True):
        st.code("""
# In core/protocols.py:
TCP_FLAG_FIN = 0x01  # Finish (Teardown)
TCP_FLAG_SYN = 0x02  # Synchronize (Initiate 3-way handshake)
TCP_FLAG_RST = 0x04  # Reset (Abort connection)
TCP_FLAG_PSH = 0x08  # Push data to application
TCP_FLAG_ACK = 0x10  # Acknowledgment number valid
TCP_FLAG_URG = 0x20  # Urgent pointer valid

def parse_tcp_flags(flags_val):
    flag_int = int(flags_val)
    flag_map = {
        "FIN": bool(flag_int & TCP_FLAG_FIN),
        "SYN": bool(flag_int & TCP_FLAG_SYN),
        "RST": bool(flag_int & TCP_FLAG_RST),
        "PSH": bool(flag_int & TCP_FLAG_PSH),
        "ACK": bool(flag_int & TCP_FLAG_ACK),
        "URG": bool(flag_int & TCP_FLAG_URG),
    }
    return flag_map
        """, language="python")

    with st.expander("2. Show TCP SYN Flood Detection (`core/ids_engine.py`)"):
        st.code("""
# In core/ids_engine.py:
# Check if packet is TCP SYN without ACK (Embryonic Connection Attempt)
if l4_proto == "TCP" and flag_map.get("SYN") and not flag_map.get("ACK"):
    syn_q = self._tcp_syn_history[src_ip]
    syn_q.append(now)
    
    # Evict records older than sliding window (5 seconds)
    while syn_q and now - syn_q[0] > 5.0:
        syn_q.popleft()
        
    # If rate exceeds threshold (40 SYN packets/5s), trigger CRITICAL alert!
    if len(syn_q) >= 40:
        alert = self._create_alert(
            severity="CRITICAL",
            alert_type="TCP SYN Flood (DoS)",
            signature="IDS-DOS-SYN-06",
            description="Exhausting TCP connection backlog queue...",
            mitigation="Enable SYN Cookies (sysctl -w net.ipv4.tcp_syncookies=1)"
        )
        """, language="python")

    with st.expander("3. Show Passive DNS Resolution (`core/protocols.py` & `core/dns_resolver.py`)"):
        st.code("""
# In core/protocols.py:
# Extract DNS Answer A records (Type 1) passing through the LAN
if dns_layer.ancount > 0 and dns_layer.an:
    curr = dns_layer.an
    for _ in range(dns_layer.ancount):
        if curr.type == 1:  # IPv4 Host Address
            rdata_ip = str(curr.rdata)
            qname = curr.rrname.decode('utf-8').rstrip('.')
            dns_resolver.learn_dns_mapping(rdata_ip, qname, is_passive=True)
        """, language="python")

    with st.expander("4. Show Statistical Anomaly Detection & Z-Score (`core/anomaly_engine.py`)"):
        st.code("""
# In core/anomaly_engine.py:
# 1. Moving Average: μ = (1 / N) * Σ (x_i)
mean_pps = sum(pps_list) / n

# 2. Standard Deviation: σ = sqrt((1 / (N - 1)) * Σ (x_i - μ)^2)
variance_pps = sum((x - mean_pps) ** 2 for x in pps_list) / (n - 1)
std_pps = math.sqrt(variance_pps)

# 3. Z-Score Distance: Z = (x - μ) / σ
z_score = (packet_count - mean_pps) / effective_std

# Trigger alert if traffic is > 3 standard deviations above baseline (99.7% confidence)
if z_score >= 3.0 and packet_count > 15:
    alert = self._create_alert(
        severity="HIGH",
        alert_type="Statistical Traffic Anomaly",
        signature="ANOMALY-STAT-ZSCORE"
    )
        """, language="python")

    with st.expander("5. How the Detailed Packet Inspector & Abstract Promises Work"):
        st.markdown("""
        **Computer Networks Layer 2 to Layer 7 Mapping in the Inspector:**
        - **Data Link Layer (Ethernet II):** Displays source and destination 48-bit MAC addresses and EtherType (`0x0800` for IPv4, `0x0806` for ARP).
        - **Network Layer (IPv4 RFC 791):** Displays Source IP, Destination IP, Time to Live (TTL), Packet Identification, and Protocol Number (6=TCP, 17=UDP, 1=ICMP).
        - **Transport Layer (TCP RFC 793 / UDP RFC 768):** Displays 16-bit Port numbers, 32-bit Sequence numbers, 32-bit Acknowledgment numbers, Window size for flow control, and individual bitflags `[SYN] [ACK] [FIN] [RST] [PSH] [URG]`.
        - **Application Layer (RFC 1035):** Decodes well-known services and extracts raw payload in readable ASCII and hex dump format.
        - **Fixed Locking Guarantee:** The inspector is locked by primary key ID in session state, ensuring that the selected packet never changes dynamically during auto-refreshes.
        """)

# -----------------------------------------------------------------------------
# AUTO-REFRESH TRIGGER
# -----------------------------------------------------------------------------
if auto_refresh and sniffer.is_running:
    time.sleep(refresh_rate)
    st.rerun()
