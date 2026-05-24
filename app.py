import streamlit as st
import pandas as pd
import ipaddress
import time
import base64
import socket
from scanner import scan_ports


# ---------------- UI CONFIG ----------------
st.set_page_config(
    page_title="Cybersecurity Port Scanner",
    page_icon="🔐",
    layout="centered"
)


# ---------------- BACKGROUND IMAGE ----------------
def get_base64_image(image_path):
    with open(image_path, "rb") as img_file:
        return base64.b64encode(img_file.read()).decode()


bg_image = get_base64_image("C:/port scanner/bg_image.png")


# ---------------- CUSTOM CSS ----------------
st.markdown(f"""
<style>

.stApp {{
    background-image: url("data:image/png;base64,{bg_image}");
    background-size: cover;
    background-position: center;
    background-attachment: fixed;
}}

.main {{
    background: rgba(0, 0, 0, 0.45);
    backdrop-filter: blur(6px);
    border-radius: 20px;
    padding: 20px;
}}

h1 {{
    background: linear-gradient(90deg, #38bdf8, #22c55e);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    font-weight: 800;
}}

[data-testid="stTextInput"] input {{
    border-radius: 12px;
    border: 1px solid #334155;
    background: rgba(17, 24, 39, 0.75);
    backdrop-filter: blur(6px);
    color: white;
}}

[data-testid="stTextInput"] input:focus {{
    border: 1px solid #38bdf8;
    box-shadow: 0 0 8px #38bdf8;
}}

.stButton > button {{
    border-radius: 12px;
    padding: 0.6rem 1.4rem;
    background: linear-gradient(90deg, #2563eb, #06b6d4);
    color: white;
    border: none;
    font-weight: 600;
}}

.stButton > button:hover {{
    transform: scale(1.03);
    border: none;
    color: white;
}}

[data-testid="stMetric"] {{
    background: rgba(17, 24, 39, 0.75);
    backdrop-filter: blur(8px);
    padding: 18px;
    border-radius: 16px;
    border: 1px solid #334155;
}}

[data-testid="stDataFrame"] {{
    border-radius: 12px;
}}
</style>
""", unsafe_allow_html=True)


# ---------------- FUNCTIONS ----------------
def validate_ports(ports_input):
    ports = []

    for p in ports_input.split(","):
        port = int(p.strip())

        if port < 1 or port > 65535:
            raise ValueError

        ports.append(port)

    return ports


# ---------------- HEADER ----------------
st.title("🔐 Cybersecurity Port Scanner")
st.caption("⚡ Fast TCP port scanning with clean reports")

st.warning("⚠️ Only scan systems you own or have permission to test.")


# ---------------- INPUT ----------------
ip = st.text_input(
    "Enter Target IP Address or Domain",
    placeholder="e.g. 127.0.0.1 or google.com"
)

ports_input = st.text_input(
    "Enter Ports (comma separated)",
    "22, 80, 443, 8080"
)


# ---------------- SCAN BUTTON ----------------
if st.button("Start Scan"):

    if not ip:
        st.error("Please enter an IP address or domain")

    else:
        try:
            # Convert domain to IP
            target_ip = socket.gethostbyname(ip)

            ports = validate_ports(ports_input)

            progress_bar = st.progress(0)
            status_text = st.empty()

            start_time = time.time()

            status_text.text("Initializing scan...")
            progress_bar.progress(20)

            with st.spinner("Scanning ports... please wait"):
                results = scan_ports(target_ip, ports)

            progress_bar.progress(80)
            status_text.text("Generating report...")

            end_time = time.time()
            scan_duration = round(end_time - start_time, 2)

            df = pd.DataFrame(results)

            open_ports = df[df["Status"] == "OPEN"]
            closed_ports = df[df["Status"] == "CLOSED"]

            progress_bar.progress(100)
            status_text.text("Scan completed successfully!")

            # ---------------- TARGET INFO ----------------
            st.success(f"Target Resolved IP: {target_ip}")

            # ---------------- METRICS ----------------
            col1, col2, col3 = st.columns(3)

            col1.metric("📦 Total Ports", len(ports))
            col2.metric("🟢 Open Ports", len(open_ports))
            col3.metric("🔴 Closed Ports", len(closed_ports))

            st.info(f"⏱ Scan completed in {scan_duration} seconds")

            # ---------------- RESULTS TABLE ----------------
            st.subheader("📊 Scan Results")
            st.dataframe(df, use_container_width=True)

            # ---------------- SUMMARY ----------------
            if not open_ports.empty:
                st.error("⚠ Open Ports Detected")
                st.dataframe(open_ports, use_container_width=True)
            else:
                st.success("✅ No open ports detected")

            # ---------------- CSV DOWNLOAD ----------------
            csv = df.to_csv(index=False).encode("utf-8")

            st.download_button(
                label="⬇ Download Report (CSV)",
                data=csv,
                file_name=f"scan_{target_ip}.csv",
                mime="text/csv"
            )

        except socket.gaierror:
            st.error("Invalid IP address or domain name")

        except ValueError:
            st.error("Please enter valid port numbers between 1 and 65535")