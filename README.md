# Network Security Monitor

> **CodeAlpha Cyber Security Internship – Task 1: Network Sniffer**  
> *Authorized Defensive Real-Time Network Telemetry & SOC Dashboard*

---

## Description

The **Network Security Monitor** is a real-time, browser-based cybersecurity dashboard engineered using **Python**, **Scapy**, and **Flask**. Designed for defensive network visibility and educational analysis, it allows security analysts and network administrators to monitor authorized local network traffic without compromising user privacy.

The backend leverages Scapy's packet-filtering engine to capture live IP packets, categorize transport protocols (TCP, UDP, ICMP), calculate packet sizes, map source/destination communications, and calculate live metrics. Telemetry is streamed to a Security Operations Center (SOC)-style dark-mode interface via Server-Sent Events (SSE), providing instantaneous updates without page refreshes.

---

## Features

- **Real-Time Packet Monitoring**: Continuously intercepts and inspects live IP traffic on specified network interfaces using Scapy's raw packet engine.
- **TCP / UDP / ICMP Protocol Analysis**: Automatically identifies transmission protocols, displaying source/destination ports for TCP and UDP, and categorizing diagnostic ICMP frames.
- **Source & Destination IP Monitoring**: Maps network traffic endpoints to provide instantaneous visibility into internal and external communications.
- **Port Monitoring**: Identifies high-risk, standard, and ephemeral port usage across active connections.
- **Packet-Size Analysis**: Computes the exact byte length of incoming and outgoing frames in real time.
- **Protocol Statistics**: Aggregates live packet counts, percentages, data volume (KB/MB), and throughput rate (packets per second).
- **SOC-Style Dashboard**: Features a high-contrast dark aesthetic with glassmorphism, responsive grid layout, status indicators, live Chart.js doughnut graphs, and a real-time canvas traffic flow visualizer.
- **Interactive Filtering & Search**: Instant client-side filtering by protocol (ALL, TCP, UDP, ICMP) and keyword search by IP address or port number.
- **Forensic CSV Export**: One-click export of captured frame metadata to CSV for security audit trails and incident reporting.
- **Authorized Test Generator**: Built-in test trigger enabling immediate verification through localized ping (ICMP), DNS query (UDP), and loopback connection (TCP) probes.

---

## Technologies

- **Python**: Core programming language and asynchronous sniffing worker threads.
- **Scapy**: Packet sniffing, packet dissection, and network layer frame inspection.
- **Flask**: Lightweight web framework and Server-Sent Events (SSE) streaming engine.
- **HTML**: Semantic, accessible dashboard structure and knowledge panels.
- **CSS**: Custom dark SOC theme, glassmorphism, glowing micro-animations, and responsive layouts.
- **JavaScript**: Real-time DOM updates, EventSource SSE listeners, Chart.js graphs, and HTML5 Canvas particle animation.
- **Kali Linux**: Primary penetration testing and cybersecurity operational environment.

---

## Installation

Follow these steps to set up the Python virtual environment and install all dependencies:

### 1. Clone or Open the Repository
```bash
cd network-security-monitor
```

### 2. Create a Python Virtual Environment
Creating an isolated virtual environment ensures clean dependency management:
```bash
python3 -m venv venv
```

### 3. Activate the Virtual Environment
- **On Kali Linux / Ubuntu / Debian:**
  ```bash
  source venv/bin/activate
  ```
- **On Windows (PowerShell):**
  ```powershell
  .\venv\Scripts\Activate.ps1
  ```

### 4. Install Dependencies
```bash
pip install -r requirements.txt
```

---

## How to Run

To start the real-time Network Security Monitor:

### On Kali Linux / Linux:
```bash
source venv/bin/activate
sudo ./venv/bin/python app.py
```
*(Alternatively, execute `sudo python3 app.py` within the activated environment).*

### On Windows:
Open PowerShell or Command Prompt as **Administrator** (required for raw packet capture via Npcap):
```powershell
python app.py
```

### Why Elevated Privileges (Root / Administrator) Are Required:
Packet sniffing requires opening raw sockets at the operating system's network driver level (e.g., Linux `AF_PACKET` or Windows `Npcap`). Modern operating systems restrict raw socket access exclusively to elevated users (`root` or `Administrator`) to prevent unprivileged software from intercepting network frames.

### Accessing the Dashboard:
Once the server initializes, open your web browser and navigate to:
```
http://127.0.0.1:5000
```
Or accessible via your local IP at port `5000`.

---

## Testing

To verify that the sniffer and real-time dashboard are operating properly, generate **authorized traffic originating from your local machine**. 

### 1. ICMP Ping Test
Open a secondary terminal window and send an authorized ping to your local gateway or loopback interface:
```bash
ping -c 4 127.0.0.1
```
*Observe the ICMP counter increase on the dashboard and new ICMP rows appear with ports indicated as `-`.*

### 2. Normal Web Request (TCP Test)
Generate standard HTTP/HTTPS traffic to an authorized site:
```bash
curl -I https://www.google.com
```
*Observe outgoing TCP packets targeting port `443` appear in the live table.*

### 3. DNS Lookup (UDP Test)
Perform a domain name lookup to generate UDP traffic across port `53`:
```bash
nslookup localhost
```
*Observe UDP packets targeting port `53` streaming across the dashboard.*

### 4. Dashboard Test Probe
You can also click the **"Test Probe"** button or quick-action buttons directly on the web interface to trigger authorized local verification frames.

> **CRITICAL ETHICAL WARNING:**  
> Do not instruct or attempt to capture network traffic from networks or devices you do not own or do not have explicit administrative authorization to monitor.

---

## Privacy & Safety

This project has been architected strictly under defensive cybersecurity and ethical computing guidelines:

- **No Payload Inspection**: The application inspects only Layer 3 (IP) and Layer 4 (TCP/UDP/ICMP) headers. Packet payload contents are deliberately never read or displayed.
- **No Credential Harvesting**: Passwords, authentication cookies, private message bodies, and sensitive data streams are completely excluded by design.
- **Packet Retention Disabled**: Packet storage is disabled (`sniff(store=False)`) ensuring that raw network frames are never saved to disk or retained in application memory.
- **Authorized Environments Only**: Designed exclusively for local network troubleshooting, educational cyber defense demonstrations, and authorized SOC laboratory exercises.

---

## Project Structure

```text
network-security-monitor/
│
├── app.py                  # Flask web application & SSE streaming server
├── network_sniffer.py      # Scapy sniffing worker thread & thread-safe statistics
├── requirements.txt        # Python dependency manifest (Flask, Scapy)
├── README.md               # Comprehensive project documentation
├── .gitignore              # Git ignore rules for virtual environments & cache
│
├── templates/
│   └── index.html          # SOC cybersecurity dashboard template
│
├── static/
│   ├── style.css           # Glassmorphism dark theme & responsive UI
│   └── dashboard.js        # SSE stream client, Chart.js & canvas visualizer
│
└── screenshots/            # Dashboard preview images & operational captures
```

---

## License & Disclaimer

Developed as part of the **CodeAlpha Cyber Security Internship**.  
This project is intended strictly for educational and defensive cybersecurity monitoring. The authors assume no liability for unauthorized usage or misconfiguration.
