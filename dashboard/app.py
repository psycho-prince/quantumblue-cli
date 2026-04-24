import streamlit as st
import sqlite3
import pandas as pd

# Page Configuration
st.set_page_config(page_title="QuantumBlue Dashboard", layout="wide")

# Theme styling (Matrix/Terminal Aesthetic)
st.markdown("""
    <style>
    .main { background-color: #0d0d0d; color: #00ff41; }
    .stApp { background-color: #0d0d0d; }
    h1, h2, h3 { color: #00ff41; }
    </style>
    """, unsafe_allow_html=True)

st.title("QuantumBlue: Precision Leak Suite")
st.sidebar.title("Navigation")
page = st.sidebar.radio("Go to", ["Dashboard", "Targets", "Vulnerability Queue"])

# DB Connection
conn = sqlite3.connect('quantumblue-cli/dashboard/db/quantumblue.db')

if page == "Dashboard":
    st.header("Overview")
    # Placeholder for heatmap
    st.info("Heatmap visualization coming soon...")
    
    st.subheader("Leak Projection Calculator")
    tx_count = st.number_input("Daily Transactions", value=50000)
    dust_size = st.number_input("Average Dust Lost (per TX)", value=0.000000000001, format="%.12f")
    daily_loss = tx_count * dust_size
    st.metric("Projected Daily Loss (Native Tokens)", f"{daily_loss:.6f}")
    st.metric("Projected Yearly Loss (Native Tokens)", f"{daily_loss * 365:.4f}")

elif page == "Targets":
    st.header("Indexed Targets")
    df = pd.read_sql_query("SELECT * FROM targets", conn)
    st.table(df)

elif page == "Vulnerability Queue":
    st.header("Vulnerability Status")
    # Join with targets
    query = """
    SELECT t.symbol, t.chain, v.leak_detected, v.poc_generated, v.report_status
    FROM vulnerabilities v
    JOIN targets t ON v.target_id = t.id
    """
    df = pd.read_sql_query(query, conn)
    st.table(df)

conn.close()
