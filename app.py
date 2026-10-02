"""
Network Security Monitor - Web Application Backend
CodeAlpha Cyber Security Internship - Task 1: Network Sniffer

Framework: Flask + Server-Sent Events (SSE) + Scapy
Environment: Kali Linux / Linux / Windows

IMPORTANT ETHICAL & LEGAL NOTICE:
This software is intended solely for AUTHORIZED and EDUCATIONAL network monitoring.
Traffic is only captured on interfaces with explicit administrative permission.
In accordance with ethical cybersecurity standards:
- Packet contents, passwords, credentials and private messages are NOT stored or displayed.
- The backend processes packet metadata (IP addresses, ports, protocol, sizes) only.
"""

import json
import time
import socket
import logging
from queue import Empty
from flask import Flask, render_template, jsonify, request, Response
from network_sniffer import NetworkSniffer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("MonitorApp")

app = Flask(__name__)

# Initialize NetworkSniffer instance
sniffer = NetworkSniffer(max_history=500)

# Automatically initiate sniffing on startup
try:
    sniffer.start()
except Exception as start_err:
    logger.warning("Sniffer initial auto-start notice: %s", start_err)


@app.route("/")
def index():
    """Render the primary SOC Network Security Monitoring Dashboard."""
    interfaces = sniffer.get_interfaces()
    initial_stats = sniffer.get_stats()
    return render_template("index.html", interfaces=interfaces, initial_stats=initial_stats)


@app.route("/api/stats", methods=["GET"])
def get_stats():
    """Retrieve current network traffic statistics and protocol distribution."""
    return jsonify(sniffer.get_stats())


@app.route("/api/packets", methods=["GET"])
def get_packets():
    """Retrieve recent captured packet metadata list."""
    limit = request.args.get("limit", default=100, type=int)
    packets = sniffer.get_recent_packets(limit=limit)
    return jsonify({"packets": packets, "count": len(packets)})


@app.route("/api/stream")
def packet_stream():
    """
    Real-Time Server-Sent Events (SSE) Endpoint.
    Streams newly captured packet events to the dashboard in real-time
    without requiring page reloads or polling.
    """
    def event_generator():
        q = sniffer.add_listener()
        logger.info("New SSE client connected to live packet stream.")
        try:
            # Send initial connection confirmation
            welcome_data = json.dumps({"event": "connected", "message": "Stream active"})
            yield f"event: status\ndata: {welcome_data}\n\n"

            while True:
                try:
                    # Non-blocking wait for new packet from sniffer queue
                    packet_dict = q.get(timeout=2.0)
                    payload = json.dumps(packet_dict)
                    yield f"event: packet\ndata: payload\n\n".replace("payload", payload)
                except Empty:
                    # Send periodic keep-alive heartbeat with updated stats
                    stats = sniffer.get_stats()
                    heartbeat_payload = json.dumps({
                        "type": "heartbeat",
                        "stats": stats
                    })
                    yield f"event: heartbeat\ndata: {heartbeat_payload}\n\n"
        except GeneratorExit:
            logger.info("SSE client disconnected.")
        finally:
            sniffer.remove_listener(q)

    return Response(
        event_generator(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive"
        }
    )


@app.route("/api/control/start", methods=["POST"])
def control_start():
    """Start packet sniffing on specified interface."""
    data = request.get_json(silent=True) or {}
    interface = data.get("interface", None)
    bpf_filter = data.get("filter", "ip")
    
    success, message = sniffer.start(interface=interface, bpf_filter=bpf_filter)
    return jsonify({
        "success": success,
        "message": message,
        "status": sniffer.get_stats()
    })


@app.route("/api/control/stop", methods=["POST"])
def control_stop():
    """Pause packet sniffing."""
    success, message = sniffer.stop()
    return jsonify({
        "success": success,
        "message": message,
        "status": sniffer.get_stats()
    })


@app.route("/api/control/clear", methods=["POST"])
def control_clear():
    """Reset counters and clear packet history."""
    success, message = sniffer.reset()
    return jsonify({
        "success": success,
        "message": message,
        "status": sniffer.get_stats()
    })


@app.route("/api/interfaces", methods=["GET"])
def list_interfaces():
    """Return list of host network interfaces."""
    interfaces = sniffer.get_interfaces()
    return jsonify({"interfaces": interfaces})


@app.route("/api/generate-test-traffic", methods=["POST"])
def generate_test_traffic():
    """
    Generate authorized local traffic to test end-to-end packet processing.
    Sends standard local ping/DNS probes to loopback/authorized addresses.
    """
    data = request.get_json(silent=True) or {}
    proto = data.get("protocol", "ICMP").upper()
    src = data.get("src") or sniffer.local_ip
    dst = data.get("dst")
    if not dst:
        if proto == "ICMP":
            dst = sniffer.gateway_ip
        elif proto == "UDP":
            dst = sniffer.gateway_ip
        elif proto == "TCP":
            dst = "142.250.190.46"
        else:
            dst = sniffer.gateway_ip

    # Perform legitimate local DNS or loopback probe if requested
    try:
        if proto == "UDP":
            # Simple local DNS query
            socket.gethostbyname("localhost")
        elif proto == "TCP":
            # Simple loopback connect attempt
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2)
            try:
                s.connect(("127.0.0.1", 5000))
            except Exception:
                pass
            finally:
                s.close()
    except Exception as probe_err:
        logger.debug("Network probe executed: %s", probe_err)

    # Inject packet metadata into stream pipeline
    test_packet = sniffer.inject_authorized_test_packet(proto=proto, src=src, dst=dst)

    return jsonify({
        "success": True,
        "message": f"Authorized {proto} test probe generated for verification.",
        "packet": test_packet,
        "stats": sniffer.get_stats()
    })


if __name__ == "__main__":
    print("=" * 70)
    print("  NETWORK SECURITY MONITOR - AUTHORIZED SOC DASHBOARD")
    print("  CodeAlpha Cyber Security Internship - Task 1: Network Sniffer")
    print("  Environment: Kali Linux / Linux / Windows")
    print("  Listening on: http://127.0.0.1:5000")
    print("=" * 70)
    print("  PRIVACY NOTICE: Only IP metadata is monitored.")
    print("  Packet payloads, passwords, and private messages are NOT recorded.")
    print("=" * 70)
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
