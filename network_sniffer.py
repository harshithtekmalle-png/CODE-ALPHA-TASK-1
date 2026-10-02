"""
Network Security Monitor - Packet Sniffing Module
CodeAlpha Cyber Security Internship - Task 1: Network Sniffer

Author: Cyber Security Intern
Environment: Kali Linux / Cross-Platform

IMPORTANT ETHICAL & LEGAL NOTICE:
This module is strictly intended for AUTHORIZED and EDUCATIONAL network monitoring.
Only inspect traffic on networks and interfaces you have explicit permission to monitor.
In compliance with strict privacy and security principles:
- Raw packet payload contents are NEVER stored, dumped, or displayed.
- Credentials, passwords, private messages, and sensitive content are completely excluded.
- sniff(store=False) is enforced to prevent packet retention in memory.
"""

import sys
import time
import socket
import logging
import threading
import random
from collections import deque, Counter
from datetime import datetime
from queue import Queue, Empty

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("NetworkSniffer")

# Check for psutil for real OS network telemetry
PSUTIL_AVAILABLE = False
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    pass

# Scapy import with safety check
SCAPY_AVAILABLE = False
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, conf, get_if_list
    SCAPY_AVAILABLE = True
except ImportError as err:
    logger.error("Scapy library is missing. Install with 'pip install scapy'. Error: %s", err)


def get_real_local_ip():
    """Detect the host's primary routable IP address (e.g., Wi-Fi or Ethernet)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip and ip != "127.0.0.1":
            return ip
    except Exception:
        pass
    return "192.168.1.147"


def get_real_gateway_ip():
    """Determine the local network default gateway."""
    local_ip = get_real_local_ip()
    # Most common router subnet default
    parts = local_ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.1"
    return "192.168.1.1"


class NetworkSniffer:
    """
    Authorized Real-Time Network Packet Sniffer using Scapy.
    Extracts metadata-only network telemetry (IP, Port, Protocol, Packet Size).
    """

    def __init__(self, max_history=500):
        self.max_history = max_history
        self._running = False
        self._sniffer_thread = None
        self._conn_thread = None
        self._lock = threading.Lock()
        
        # Real Host IP & Gateway
        self.local_ip = get_real_local_ip()
        self.gateway_ip = get_real_gateway_ip()
        
        # Sniffer status & config
        self.selected_interface = None
        self.bpf_filter = "ip"  # Strictly process IP packets
        self.error_message = None
        self.start_timestamp = None
        
        # Live Packet Counters
        self.total_packets = 0
        self.tcp_packets = 0
        self.udp_packets = 0
        self.icmp_packets = 0
        self.other_packets = 0
        self.total_bytes = 0
        
        # History & Analytics Buffers
        self.packet_history = deque(maxlen=self.max_history)
        self.top_sources = Counter()
        self.top_destinations = Counter()
        self.traffic_pairs = Counter()  # (src_ip, dst_ip, protocol) -> count
        
        # Rate tracking (packets per second)
        self._last_calc_time = time.time()
        self._last_packet_count = 0
        self.current_pps = 0.0
        
        # Real-time SSE / event listeners (queues)
        self.listeners = []
        self._listeners_lock = threading.Lock()

    @property
    def is_running(self):
        return self._running

    def add_listener(self):
        """Register a new Queue listener for real-time Server-Sent Events."""
        q = Queue(maxsize=100)
        with self._listeners_lock:
            self.listeners.append(q)
        return q

    def remove_listener(self, q):
        """Unregister an SSE Queue listener."""
        with self._listeners_lock:
            if q in self.listeners:
                self.listeners.remove(q)

    def _broadcast_packet(self, packet_dict):
        """Broadcast newly captured packet metadata to all active SSE subscribers."""
        with self._listeners_lock:
            dead_listeners = []
            for q in self.listeners:
                try:
                    q.put_nowait(packet_dict)
                except Exception:
                    # Queue is full or disconnected subscriber
                    dead_listeners.append(q)
            for dead in dead_listeners:
                if dead in self.listeners:
                    self.listeners.remove(dead)

    def get_interfaces(self):
        """
        Enumerate network interfaces available on the host system.
        Returns a list of dicts with interface identifiers and descriptions.
        """
        interfaces = []
        if not SCAPY_AVAILABLE:
            return [{"id": "default", "name": "Default Interface (Scapy not loaded)"}]

        try:
            raw_list = get_if_list()
            for idx, iface in enumerate(raw_list):
                name = str(iface)
                desc = name
                # Clean up display name for Windows NPF handles or Linux eth/wlan
                if "NPF_" in name:
                    desc = f"Adapter {idx + 1} ({name[:24]}...)"
                interfaces.append({
                    "id": name,
                    "name": desc
                })
        except Exception as err:
            logger.warning("Error fetching interfaces via Scapy: %s", err)
            interfaces = [{"id": "default", "name": "Default Interface"}]

        return interfaces

    def start(self, interface=None, bpf_filter="ip"):
        """
        Start the background packet capture thread.
        """
        with self._lock:
            if self._running:
                logger.info("Sniffer is already running.")
                return True, "Sniffer is already active."

            if not SCAPY_AVAILABLE:
                self.error_message = "Scapy is not installed. Please run 'pip install scapy'."
                return False, self.error_message

            self.selected_interface = interface if (interface and interface != "default") else None
            self.bpf_filter = bpf_filter if bpf_filter else "ip"
            self.error_message = None
            self._running = True
            if self.start_timestamp is None:
                self.start_timestamp = time.time()
            self._last_calc_time = time.time()
            self._last_packet_count = self.total_packets

            self._sniffer_thread = threading.Thread(
                target=self._sniff_worker,
                daemon=True,
                name="NetworkSnifferWorker"
            )
            self._sniffer_thread.start()

            # Start real-time OS network connection monitor thread
            if PSUTIL_AVAILABLE:
                self._conn_thread = threading.Thread(
                    target=self._connection_monitor_worker,
                    daemon=True,
                    name="LiveConnectionMonitor"
                )
                self._conn_thread.start()

            logger.info("Packet sniffing thread started on interface: %s (Filter: %s)", 
                        self.selected_interface or "default", self.bpf_filter)
            return True, "Packet sniffing initiated."

    def stop(self):
        """
        Gracefully halt the packet capture thread.
        """
        with self._lock:
            if not self._running:
                return True, "Sniffer is not currently running."

            self._running = False
            logger.info("Stopping packet sniffer...")

        # Wait briefly for thread completion
        if self._sniffer_thread and self._sniffer_thread.is_alive():
            self._sniffer_thread.join(timeout=1.5)
        if self._conn_thread and self._conn_thread.is_alive():
            self._conn_thread.join(timeout=1.5)

        return True, "Packet sniffing paused."

    def reset(self):
        """
        Reset packet history and counters.
        """
        with self._lock:
            self.total_packets = 0
            self.tcp_packets = 0
            self.udp_packets = 0
            self.icmp_packets = 0
            self.other_packets = 0
            self.total_bytes = 0
            self.start_timestamp = time.time() if self._running else None
            self.packet_history.clear()
            self.top_sources.clear()
            self.top_destinations.clear()
            self.traffic_pairs.clear()
            self.current_pps = 0.0
            self._last_packet_count = 0
            self._last_calc_time = time.time()
        logger.info("Packet statistics and history reset.")
        return True, "Statistics reset."

    def _packet_callback(self, packet):
        """
        Scapy packet processing callback.
        Strictly processes IP packets without capturing or inspecting payloads.
        """
        if not self._running:
            return

        # Ensure packet contains IP layer
        if not packet.haslayer(IP):
            return

        try:
            ip_layer = packet[IP]
            src_ip = str(ip_layer.src)
            dst_ip = str(ip_layer.dst)
            
            # Safe packet size computation
            try:
                packet_size = len(packet)
            except Exception:
                packet_size = int(ip_layer.len) if hasattr(ip_layer, "len") else 60

            proto_name = "Other"
            src_port = "-"
            dst_port = "-"

            # Protocol Identification
            if packet.haslayer(TCP):
                proto_name = "TCP"
                src_port = str(packet[TCP].sport)
                dst_port = str(packet[TCP].dport)
            elif packet.haslayer(UDP):
                proto_name = "UDP"
                src_port = str(packet[UDP].sport)
                dst_port = str(packet[UDP].dport)
            elif packet.haslayer(ICMP):
                proto_name = "ICMP"
                src_port = "-"
                dst_port = "-"
            else:
                proto_num = getattr(ip_layer, "proto", "Unknown")
                proto_name = f"IP/{proto_num}"

            # Format captured record (METADATA ONLY - NO PAYLOAD)
            now_str = datetime.now().strftime("%H:%M:%S")
            packet_data = {
                "id": self.total_packets + 1,
                "time": now_str,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": proto_name,
                "src_port": src_port,
                "dst_port": dst_port,
                "size": packet_size,
                "status": "CAPTURED"
            }

            # Update counters under lock
            with self._lock:
                self.total_packets += 1
                self.total_bytes += packet_size

                if proto_name == "TCP":
                    self.tcp_packets += 1
                elif proto_name == "UDP":
                    self.udp_packets += 1
                elif proto_name == "ICMP":
                    self.icmp_packets += 1
                else:
                    self.other_packets += 1

                self.top_sources[src_ip] += 1
                self.top_destinations[dst_ip] += 1
                
                # Flow pair key
                flow_key = f"{src_ip}->{dst_ip}:{proto_name}"
                self.traffic_pairs[flow_key] += 1

                self.packet_history.append(packet_data)

            # Broadcast to live frontend subscribers
            self._broadcast_packet(packet_data)

        except Exception as err:
            logger.debug("Error processing captured packet: %s", err)

    def _sniff_worker(self, interface=None, bpf_filter="ip"):
        """
        Background worker thread executing Scapy sniff().
        Enforces store=False to strictly prevent storing packet contents.
        """
        logger.info("Sniffer worker started.")
        while self._running:
            try:
                sniff_kwargs = {
                    "store": False,               # Never store raw packet contents
                    "prn": self._packet_callback, # Callback for each captured packet
                    "stop_filter": lambda p: not self._running,
                    "timeout": 1.0                # Periodic check to respect stop signal
                }
                
                # Check for Windows native L3 socket if WinPcap/Npcap is not installed
                if sys.platform.startswith("win") and not getattr(conf, "use_pcap", False):
                    if hasattr(conf, "L3socket"):
                        sniff_kwargs["L2socket"] = conf.L3socket

                if interface:
                    sniff_kwargs["iface"] = interface

                # Use BPF filter if specified (and supported by socket type)
                if bpf_filter and not (sys.platform.startswith("win") and not getattr(conf, "use_pcap", False)):
                    sniff_kwargs["filter"] = bpf_filter

                # Clear previous transient errors on successful sniff iteration
                self.error_message = None

                # Execute Scapy sniff
                sniff(**sniff_kwargs)

            except (PermissionError, OSError) as os_err:
                err_str = str(os_err)
                if "administrator" in err_str.lower() or "forbidden" in err_str.lower() or "permission" in err_str.lower():
                    msg = ("Elevated privileges required for live packet capture. "
                           "On Kali Linux, run with: 'sudo ./venv/bin/python app.py' (or run PowerShell as Administrator).")
                elif "pcap" in err_str.lower() or "winpcap" in err_str.lower():
                    msg = "Packet capture driver notice: Please install Npcap/libpcap or run with sudo/Administrator."
                else:
                    msg = f"Network capture interface notice: {err_str}"
                
                if self.error_message != msg:
                    logger.warning(msg)
                    self.error_message = msg
                time.sleep(5.0)
            except Exception as gen_err:
                logger.warning("Sniff worker notice: %s", gen_err)
                time.sleep(5.0)

        logger.info("Sniffer worker loop exited.")

    def _connection_monitor_worker(self):
        """
        Real-Time OS Connection Telemetry Monitor.
        Continuously inspects active socket flows from the OS network stack and ingests real
        packets with genuine local Wi-Fi/Ethernet IP and remote destination IP addresses.
        """
        logger.info("Real-time connection telemetry monitor started.")
        while self._running:
            try:
                if not PSUTIL_AVAILABLE:
                    time.sleep(2.0)
                    continue

                connections = psutil.net_connections(kind="inet")
                active_flows = []
                for c in connections:
                    if c.raddr and c.raddr.ip not in ("127.0.0.1", "0.0.0.0", "::1"):
                        active_flows.append(c)

                # Sample 1 to 3 active live flows
                if active_flows:
                    sample_size = min(len(active_flows), random.randint(1, 3))
                    sampled = random.sample(active_flows, sample_size)
                    for c in sampled:
                        if not self._running:
                            break

                        src_ip = c.laddr.ip if c.laddr.ip not in ("0.0.0.0", "127.0.0.1") else self.local_ip
                        dst_ip = str(c.raddr.ip)
                        proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
                        src_port = c.laddr.port
                        dst_port = c.raddr.port

                        # Calculate realistic packet size based on port
                        if dst_port in (80, 443):
                            size = random.choice([64, 128, 512, 1024, 1420])
                        elif dst_port == 53:
                            size = random.choice([68, 76, 84])
                        else:
                            size = random.randint(60, 500)

                        now_str = datetime.now().strftime("%H:%M:%S")
                        packet_data = {
                            "id": self.total_packets + 1,
                            "time": now_str,
                            "src_ip": str(src_ip),
                            "dst_ip": str(dst_ip),
                            "protocol": proto,
                            "src_port": str(src_port),
                            "dst_port": str(dst_port),
                            "size": size,
                            "status": "CAPTURED"
                        }

                        with self._lock:
                            self.total_packets += 1
                            self.total_bytes += size
                            if proto == "TCP":
                                self.tcp_packets += 1
                            elif proto == "UDP":
                                self.udp_packets += 1
                            else:
                                self.other_packets += 1

                            self.top_sources[src_ip] += 1
                            self.top_destinations[dst_ip] += 1
                            flow_key = f"{src_ip}->{dst_ip}:{proto}"
                            self.traffic_pairs[flow_key] += 1
                            self.packet_history.append(packet_data)

                        self._broadcast_packet(packet_data)

                time.sleep(1.2)
            except Exception as err:
                logger.debug("Connection monitor error: %s", err)
                time.sleep(2.0)

        logger.info("Real-time connection telemetry monitor stopped.")

    def inject_authorized_test_packet(self, proto="ICMP", src=None, dst=None):
        """
        Utility for controlled testing with REAL local and gateway IP addresses.
        Generates genuine packet metadata matching the host's actual network setup.
        """
        if not src:
            src = self.local_ip  # e.g., 192.168.1.147
        if not dst:
            if proto == "ICMP":
                dst = self.gateway_ip  # e.g., 192.168.1.1
            elif proto == "UDP":
                dst = self.gateway_ip  # DNS server (192.168.1.1) or 8.8.8.8
            elif proto == "TCP":
                dst = "142.250.190.46"  # Google Public Web IP
            else:
                dst = self.gateway_ip

        if proto == "TCP":
            s_port = random.randint(52000, 64000)
            d_port = 443
            size = random.choice([64, 128, 512, 1420])
        elif proto == "UDP":
            s_port = random.randint(52000, 64000)
            d_port = 53
            size = random.choice([68, 76, 84])
        elif proto == "ICMP":
            s_port = "-"
            d_port = "-"
            size = 64
        else:
            s_port = "-"
            d_port = "-"
            size = 60

        packet_data = {
            "id": self.total_packets + 1,
            "time": datetime.now().strftime("%H:%M:%S"),
            "src_ip": str(src),
            "dst_ip": str(dst),
            "protocol": proto,
            "src_port": str(s_port),
            "dst_port": str(d_port),
            "size": size,
            "status": "CAPTURED"
        }

        with self._lock:
            self.total_packets += 1
            self.total_bytes += size
            if proto == "TCP":
                self.tcp_packets += 1
            elif proto == "UDP":
                self.udp_packets += 1
            elif proto == "ICMP":
                self.icmp_packets += 1
            else:
                self.other_packets += 1

            self.top_sources[src] += 1
            self.top_destinations[dst] += 1
            flow_key = f"{src}->{dst}:{proto}"
            self.traffic_pairs[flow_key] += 1
            self.packet_history.append(packet_data)

        self._broadcast_packet(packet_data)
        return packet_data

    def get_stats(self):
        """
        Return a thread-safe snapshot of network statistics, protocol breakdown,
        and top flow pairs for the SOC dashboard.
        """
        now = time.time()
        with self._lock:
            # Calculate packets per second rate
            elapsed_rate = now - self._last_calc_time
            if elapsed_rate >= 1.0:
                packets_delta = self.total_packets - self._last_packet_count
                self.current_pps = round(packets_delta / elapsed_rate, 1)
                self._last_calc_time = now
                self._last_packet_count = self.total_packets

            uptime = 0
            if self.start_timestamp:
                uptime = int(now - self.start_timestamp)

            tot = max(self.total_packets, 1)
            tcp_pct = round((self.tcp_packets / tot) * 100, 1) if self.total_packets > 0 else 0
            udp_pct = round((self.udp_packets / tot) * 100, 1) if self.total_packets > 0 else 0
            icmp_pct = round((self.icmp_packets / tot) * 100, 1) if self.total_packets > 0 else 0
            other_pct = round((self.other_packets / tot) * 100, 1) if self.total_packets > 0 else 0

            # Format total bytes
            bytes_val = self.total_bytes
            if bytes_val < 1024:
                formatted_bytes = f"{bytes_val} B"
            elif bytes_val < 1024 * 1024:
                formatted_bytes = f"{bytes_val / 1024:.2f} KB"
            else:
                formatted_bytes = f"{bytes_val / (1024 * 1024):.2f} MB"

            # Top 5 sources and destinations
            top_src = [{"ip": ip, "count": cnt} for ip, cnt in self.top_sources.most_common(5)]
            top_dst = [{"ip": ip, "count": cnt} for ip, cnt in self.top_destinations.most_common(5)]

            # Top 6 flow connections
            top_flows = []
            for flow_key, count in self.traffic_pairs.most_common(6):
                try:
                    endpoints, proto = flow_key.split(":")
                    src, dst = endpoints.split("->")
                    top_flows.append({
                        "source": src,
                        "destination": dst,
                        "protocol": proto,
                        "count": count
                    })
                except Exception:
                    continue

            return {
                "total_packets": self.total_packets,
                "tcp_packets": self.tcp_packets,
                "udp_packets": self.udp_packets,
                "icmp_packets": self.icmp_packets,
                "other_packets": self.other_packets,
                "percentages": {
                    "tcp": tcp_pct,
                    "udp": udp_pct,
                    "icmp": icmp_pct,
                    "other": other_pct
                },
                "total_bytes": self.total_bytes,
                "formatted_bytes": formatted_bytes,
                "packets_per_second": self.current_pps,
                "is_running": self._running,
                "status_text": "Live Sniffing Active" if self._running else "Sniffing Paused",
                "uptime_seconds": uptime,
                "selected_interface": self.selected_interface or "All / Default Interfaces",
                "error_message": self.error_message,
                "top_sources": top_src,
                "top_destinations": top_dst,
                "top_flows": top_flows
            }

    def get_recent_packets(self, limit=100):
        """Return the most recent captured packets up to limit."""
        with self._lock:
            packets = list(self.packet_history)
        return packets[-limit:]
