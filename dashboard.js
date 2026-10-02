/**
 * NETWORK SECURITY MONITOR - SOC DASHBOARD FRONTEND
 * CodeAlpha Cyber Security Internship - Task 1: Network Sniffer
 * 
 * Manages Server-Sent Events (SSE) streaming, live packet counters,
 * Chart.js protocol doughnut chart, dynamic canvas traffic visualizer,
 * filterable packet stream table, and sniffer API controls.
 */

document.addEventListener('DOMContentLoaded', () => {
    // =========================================================================
    // STATE & DOM ELEMENTS
    // =========================================================================
    const state = {
        isRunning: true,
        activeFilter: 'ALL',
        searchQuery: '',
        autoScroll: true,
        packets: [],
        maxTableRows: 250,
        protocolChart: null,
        eventSource: null,
        topSources: [],
        topDestinations: []
    };

    // Header & Controls Elements
    const pulseDot = document.getElementById('pulseDot');
    const globalStatusText = document.getElementById('globalStatusText');
    const globalStatusPill = document.getElementById('globalStatusPill');
    const toggleSnifferBtn = document.getElementById('toggleSnifferBtn');
    const toggleBtnText = document.getElementById('toggleBtnText');
    const clearDataBtn = document.getElementById('clearDataBtn');
    const exportCsvBtn = document.getElementById('exportCsvBtn');
    const testTrafficBtn = document.getElementById('testTrafficBtn');
    const interfaceSelect = document.getElementById('interfaceSelect');
    const alertNotice = document.getElementById('alertNotice');
    const alertNoticeMessage = document.getElementById('alertNoticeMessage');

    // Metric Cards Elements
    const cardTotalPackets = document.getElementById('cardTotalPackets');
    const cardPacketRate = document.getElementById('cardPacketRate');
    const cardTotalVolume = document.getElementById('cardTotalVolume');
    
    const cardTcpPackets = document.getElementById('cardTcpPackets');
    const cardTcpPercent = document.getElementById('cardTcpPercent');
    const tcpProgress = document.getElementById('tcpProgress');

    const cardUdpPackets = document.getElementById('cardUdpPackets');
    const cardUdpPercent = document.getElementById('cardUdpPercent');
    const udpProgress = document.getElementById('udpProgress');

    const cardIcmpPackets = document.getElementById('cardIcmpPackets');
    const cardIcmpPercent = document.getElementById('cardIcmpPercent');
    const icmpProgress = document.getElementById('icmpProgress');

    const cardStatusText = document.getElementById('cardStatusText');
    const cardStatusDot = document.getElementById('cardStatusDot');
    const cardUptime = document.getElementById('cardUptime');
    const cardIface = document.getElementById('cardIface');

    // Chart & Visualizer Elements
    const chartCenterTotal = document.getElementById('chartCenterTotal');
    const legendTcp = document.getElementById('legendTcp');
    const legendUdp = document.getElementById('legendUdp');
    const legendIcmp = document.getElementById('legendIcmp');
    const legendOther = document.getElementById('legendOther');
    const topSourcesList = document.getElementById('topSourcesList');
    const topDestinationsList = document.getElementById('topDestinationsList');
    const trafficFlowCanvas = document.getElementById('trafficFlowCanvas');

    // Table Elements
    const packetsTableBody = document.getElementById('packetsTableBody');
    const emptyStateRow = document.getElementById('emptyStateRow');
    const tableContainer = document.getElementById('tableContainer');
    const streamCounterBadge = document.getElementById('streamCounterBadge');
    const packetSearchInput = document.getElementById('packetSearchInput');
    const protocolFilterGroup = document.getElementById('protocolFilterGroup');
    const autoScrollCheck = document.getElementById('autoScrollCheck');

    // Quick Action Buttons
    const quickPingBtn = document.getElementById('quickPingBtn');
    const quickDnsBtn = document.getElementById('quickDnsBtn');
    const quickTcpBtn = document.getElementById('quickTcpBtn');

    // =========================================================================
    // CHART.JS PROTOCOL DISTRIBUTION INITIALIZATION
    // =========================================================================
    function initProtocolChart() {
        const ctx = document.getElementById('protocolDoughnutChart').getContext('2d');
        state.protocolChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['TCP', 'UDP', 'ICMP', 'Other'],
                datasets: [{
                    data: [0, 0, 0, 0],
                    backgroundColor: [
                        '#10b981', // TCP: Emerald
                        '#8b5cf6', // UDP: Purple
                        '#f59e0b', // ICMP: Amber
                        '#f43f5e'  // Other: Rose
                    ],
                    borderColor: '#111726',
                    borderWidth: 3,
                    hoverOffset: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '72%',
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: 'rgba(17, 24, 39, 0.95)',
                        titleColor: '#f8fafc',
                        bodyColor: '#cbd5e1',
                        borderColor: 'rgba(6, 182, 212, 0.4)',
                        borderWidth: 1,
                        padding: 10,
                        displayColors: true
                    }
                },
                animation: {
                    duration: 400
                }
            }
        });
    }

    // =========================================================================
    // CANVAS NETWORK TRAFFIC VISUALIZER
    // =========================================================================
    const canvas = trafficFlowCanvas;
    const ctx = canvas.getContext('2d');
    let particles = [];
    let canvasWidth = 0;
    let canvasHeight = 0;

    function resizeCanvas() {
        if (!canvas) return;
        canvasWidth = canvas.parentElement.clientWidth;
        canvasHeight = canvas.parentElement.clientHeight;
        canvas.width = canvasWidth;
        canvas.height = canvasHeight;
    }
    window.addEventListener('resize', resizeCanvas);
    resizeCanvas();

    class TrafficParticle {
        constructor(proto, srcIdx, dstIdx) {
            this.proto = proto;
            this.startX = 90;
            this.startY = 40 + (srcIdx % 5) * 36;
            this.endX = canvasWidth - 90;
            this.endY = 40 + (dstIdx % 5) * 36;
            this.midX = canvasWidth / 2;
            this.midY = canvasHeight / 2;
            this.progress = 0;
            this.speed = 0.02 + Math.random() * 0.015;
            
            // Color according to protocol
            if (proto === 'TCP') this.color = '#10b981';
            else if (proto === 'UDP') this.color = '#8b5cf6';
            else if (proto === 'ICMP') this.color = '#f59e0b';
            else this.color = '#06b6d4';
        }

        update() {
            this.progress += this.speed;
            return this.progress < 1.0;
        }

        draw(ctx) {
            // Quadratic bezier through central SOC hub
            const t = this.progress;
            const x = (1 - t) * (1 - t) * this.startX + 2 * (1 - t) * t * this.midX + t * t * this.endX;
            const y = (1 - t) * (1 - t) * this.startY + 2 * (1 - t) * t * this.midY + t * t * this.endY;

            ctx.save();
            ctx.shadowBlur = 10;
            ctx.shadowColor = this.color;
            ctx.fillStyle = this.color;
            ctx.beginPath();
            ctx.arc(x, y, 4, 0, Math.PI * 2);
            ctx.fill();
            ctx.restore();
        }
    }

    function animateTrafficCanvas() {
        ctx.clearRect(0, 0, canvasWidth, canvasHeight);

        // Draw faint guide lines connecting left and right hosts through central hub
        ctx.lineWidth = 1;
        ctx.strokeStyle = 'rgba(255, 255, 255, 0.03)';
        for (let i = 0; i < 5; i++) {
            const y1 = 40 + i * 36;
            const y2 = 40 + i * 36;
            ctx.beginPath();
            ctx.moveTo(90, y1);
            ctx.quadraticCurveTo(canvasWidth / 2, canvasHeight / 2, canvasWidth - 90, y2);
            ctx.stroke();
        }

        // Update & draw glowing particles
        for (let i = particles.length - 1; i >= 0; i--) {
            const p = particles[i];
            if (p.update()) {
                p.draw(ctx);
            } else {
                particles.splice(i, 1);
            }
        }

        requestAnimationFrame(animateTrafficCanvas);
    }
    requestAnimationFrame(animateTrafficCanvas);

    function triggerPacketAnimation(proto) {
        if (particles.length > 35) return;
        const srcIdx = Math.floor(Math.random() * 5);
        const dstIdx = Math.floor(Math.random() * 5);
        particles.push(new TrafficParticle(proto, srcIdx, dstIdx));
    }

    // =========================================================================
    // STATS UPDATE & UI RENDER
    // =========================================================================
    function updateMetricsUI(stats) {
        if (!stats) return;

        // Total Packets Card
        cardTotalPackets.textContent = Number(stats.total_packets || 0).toLocaleString();
        cardPacketRate.innerHTML = `<i class="fa-solid fa-wave-square"></i> ${stats.packets_per_second || 0.0} pps`;
        cardTotalVolume.textContent = stats.formatted_bytes || '0 B';

        // TCP Card
        cardTcpPackets.textContent = Number(stats.tcp_packets || 0).toLocaleString();
        const tcpPct = stats.percentages?.tcp || 0;
        cardTcpPercent.textContent = `${tcpPct}%`;
        tcpProgress.style.width = `${Math.min(tcpPct, 100)}%`;

        // UDP Card
        cardUdpPackets.textContent = Number(stats.udp_packets || 0).toLocaleString();
        const udpPct = stats.percentages?.udp || 0;
        cardUdpPercent.textContent = `${udpPct}%`;
        udpProgress.style.width = `${Math.min(udpPct, 100)}%`;

        // ICMP Card
        cardIcmpPackets.textContent = Number(stats.icmp_packets || 0).toLocaleString();
        const icmpPct = stats.percentages?.icmp || 0;
        cardIcmpPercent.textContent = `${icmpPct}%`;
        icmpProgress.style.width = `${Math.min(icmpPct, 100)}%`;

        // Monitoring Status Card & Global Pills
        state.isRunning = stats.is_running;
        if (stats.is_running) {
            pulseDot.className = 'pulse-dot active';
            cardStatusDot.className = 'live-dot';
            globalStatusPill.className = 'status-indicator-pill';
            globalStatusText.textContent = 'Live Sniffing Active';
            cardStatusText.textContent = 'Live Sniffing Active';
            toggleBtnText.textContent = 'Pause';
            toggleSnifferBtn.innerHTML = '<i class="fa-solid fa-pause"></i> <span id="toggleBtnText">Pause</span>';
            toggleSnifferBtn.className = 'btn btn-warning';
        } else {
            pulseDot.className = 'pulse-dot paused';
            cardStatusDot.className = 'live-dot paused';
            globalStatusPill.className = 'status-indicator-pill paused';
            globalStatusText.textContent = 'Sniffing Paused';
            cardStatusText.textContent = 'Sniffing Paused';
            toggleBtnText.textContent = 'Resume';
            toggleSnifferBtn.innerHTML = '<i class="fa-solid fa-play"></i> <span id="toggleBtnText">Resume</span>';
            toggleSnifferBtn.className = 'btn btn-cyan';
        }

        // Format uptime
        const uptimeSec = stats.uptime_seconds || 0;
        const mins = Math.floor(uptimeSec / 60);
        const secs = uptimeSec % 60;
        cardUptime.textContent = `${mins}m ${secs}s`;
        cardIface.textContent = stats.selected_interface || 'Auto';

        // Error message banner
        if (stats.error_message) {
            alertNotice.classList.remove('hidden');
            alertNoticeMessage.textContent = stats.error_message;
        } else {
            alertNotice.classList.add('hidden');
        }

        // Protocol Distribution Doughnut Chart Update
        if (state.protocolChart) {
            state.protocolChart.data.datasets[0].data = [
                stats.tcp_packets || 0,
                stats.udp_packets || 0,
                stats.icmp_packets || 0,
                stats.other_packets || 0
            ];
            state.protocolChart.update('none');
        }

        // Chart Center Text & Legend Values
        chartCenterTotal.textContent = Number(stats.total_packets || 0).toLocaleString();
        legendTcp.textContent = `${Number(stats.tcp_packets || 0).toLocaleString()} (${tcpPct}%)`;
        legendUdp.textContent = `${Number(stats.udp_packets || 0).toLocaleString()} (${udpPct}%)`;
        legendIcmp.textContent = `${Number(stats.icmp_packets || 0).toLocaleString()} (${icmpPct}%)`;
        const otherPct = stats.percentages?.other || 0;
        legendOther.textContent = `${Number(stats.other_packets || 0).toLocaleString()} (${otherPct}%)`;

        // Update Top Sources and Destinations
        updateHostNodes(stats.top_sources || [], stats.top_destinations || []);
    }

    function updateHostNodes(sources, destinations) {
        // Render Top Sources
        if (sources && sources.length > 0) {
            topSourcesList.innerHTML = sources.map(s => `
                <li class="host-node">
                    <span>${s.ip}</span>
                    <strong style="color: #38bdf8;">${s.count}</strong>
                </li>
            `).join('');
        } else {
            topSourcesList.innerHTML = '<li class="host-node empty">Awaiting packets...</li>';
        }

        // Render Top Destinations
        if (destinations && destinations.length > 0) {
            topDestinationsList.innerHTML = destinations.map(d => `
                <li class="host-node">
                    <span>${d.ip}</span>
                    <strong style="color: #a78bfa;">${d.count}</strong>
                </li>
            `).join('');
        } else {
            topDestinationsList.innerHTML = '<li class="host-node empty">Awaiting packets...</li>';
        }
    }

    // =========================================================================
    // LIVE PACKET STREAM TABLE RENDERING
    // =========================================================================
    function getProtocolBadgeClass(proto) {
        if (proto === 'TCP') return 'proto-tcp';
        if (proto === 'UDP') return 'proto-udp';
        if (proto === 'ICMP') return 'proto-icmp';
        return 'proto-other';
    }

    function createPacketRow(packet) {
        const tr = document.createElement('tr');
        tr.className = 'new-packet-flash';
        tr.dataset.protocol = packet.protocol || 'Other';
        tr.dataset.src = packet.src_ip || '';
        tr.dataset.dst = packet.dst_ip || '';
        tr.dataset.sport = packet.src_port || '';
        tr.dataset.dport = packet.dst_port || '';

        const badgeClass = getProtocolBadgeClass(packet.protocol);

        tr.innerHTML = `
            <td>${packet.time}</td>
            <td><span style="color: #38bdf8;">${packet.src_ip}</span></td>
            <td><span style="color: #a78bfa;">${packet.dst_ip}</span></td>
            <td><span class="proto-badge ${badgeClass}">${packet.protocol}</span></td>
            <td>${packet.src_port}</td>
            <td>${packet.dst_port}</td>
            <td>${packet.size} B</td>
            <td><span class="status-tag-captured"><i class="fa-solid fa-check"></i> ${packet.status || 'CAPTURED'}</span></td>
        `;

        // Check if row matches current filter and search
        if (!matchesFilter(packet)) {
            tr.style.display = 'none';
        }

        return tr;
    }

    function matchesFilter(packet) {
        // Protocol filter
        if (state.activeFilter !== 'ALL' && packet.protocol !== state.activeFilter) {
            return false;
        }

        // Search query filter (source, dest, or ports)
        if (state.searchQuery) {
            const q = state.searchQuery.toLowerCase();
            const textMatch = 
                packet.src_ip.toLowerCase().includes(q) ||
                packet.dst_ip.toLowerCase().includes(q) ||
                String(packet.src_port).toLowerCase().includes(q) ||
                String(packet.dst_port).toLowerCase().includes(q);
            if (!textMatch) return false;
        }

        return true;
    }

    function handleIncomingPacket(packet) {
        // Trigger visualizer particle animation
        triggerPacketAnimation(packet.protocol);

        // Hide empty state if visible
        if (emptyStateRow && emptyStateRow.parentElement) {
            emptyStateRow.remove();
        }

        // Keep local memory buffer
        state.packets.unshift(packet);
        if (state.packets.length > 500) {
            state.packets.pop();
        }

        // Insert new row at top of live table
        const row = createPacketRow(packet);
        packetsTableBody.insertBefore(row, packetsTableBody.firstChild);

        // Trim excess table rows for peak browser performance
        while (packetsTableBody.children.length > state.maxTableRows) {
            packetsTableBody.removeChild(packetsTableBody.lastChild);
        }

        // Update captured counter badge
        streamCounterBadge.textContent = `${state.packets.length} buffered`;

        // Handle auto-scroll if enabled
        if (state.autoScroll && tableContainer.scrollTop < 80) {
            tableContainer.scrollTop = 0;
        }
    }

    function applyFilters() {
        const rows = packetsTableBody.querySelectorAll('tr:not(.empty-row)');
        rows.forEach(tr => {
            const proto = tr.dataset.protocol;
            const src = tr.dataset.src;
            const dst = tr.dataset.dst;
            const sport = tr.dataset.sport;
            const dport = tr.dataset.dport;

            let show = true;
            if (state.activeFilter !== 'ALL' && proto !== state.activeFilter) {
                show = false;
            }

            if (show && state.searchQuery) {
                const q = state.searchQuery.toLowerCase();
                const matched = src.toLowerCase().includes(q) ||
                                dst.toLowerCase().includes(q) ||
                                sport.toLowerCase().includes(q) ||
                                dport.toLowerCase().includes(q);
                if (!matched) show = false;
            }

            tr.style.display = show ? '' : 'none';
        });
    }

    // =========================================================================
    // SERVER-SENT EVENTS (SSE) REAL-TIME PIPELINE
    // =========================================================================
    function connectEventStream() {
        if (state.eventSource) {
            state.eventSource.close();
        }

        try {
            state.eventSource = new EventSource('/api/stream');

            state.eventSource.addEventListener('packet', (event) => {
                try {
                    const packet = JSON.parse(event.data);
                    handleIncomingPacket(packet);
                } catch (e) {
                    console.error('Failed to parse incoming packet SSE:', e);
                }
            });

            state.eventSource.addEventListener('heartbeat', (event) => {
                try {
                    const data = JSON.parse(event.data);
                    if (data.stats) {
                        updateMetricsUI(data.stats);
                    }
                } catch (e) {
                    console.error('Failed to parse heartbeat SSE:', e);
                }
            });

            state.eventSource.onerror = (err) => {
                console.warn('SSE connection notice; will retry...', err);
            };
        } catch (err) {
            console.error('Failed to initialize EventSource:', err);
        }
    }

    // Periodic statistics poll fallback
    async function fetchStats() {
        try {
            const res = await fetch('/api/stats');
            if (res.ok) {
                const data = await res.json();
                updateMetricsUI(data);
            }
        } catch (err) {
            console.debug('Stats fetch notice:', err);
        }
    }

    // Initial packets load
    async function loadRecentPackets() {
        try {
            const res = await fetch('/api/packets?limit=50');
            if (res.ok) {
                const data = await res.json();
                if (data.packets && data.packets.length > 0) {
                    data.packets.forEach(p => handleIncomingPacket(p));
                }
            }
        } catch (err) {
            console.debug('Initial packets load notice:', err);
        }
    }

    // =========================================================================
    // USER CONTROLS & EVENT LISTENERS
    // =========================================================================
    
    // Toggle Sniffer (Start / Pause)
    toggleSnifferBtn.addEventListener('click', async () => {
        const endpoint = state.isRunning ? '/api/control/stop' : '/api/control/start';
        const payload = state.isRunning ? {} : { interface: interfaceSelect.value };

        try {
            const res = await fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            const data = await res.json();
            if (data.status) {
                updateMetricsUI(data.status);
            }
        } catch (err) {
            console.error('Toggle sniffer failed:', err);
        }
    });

    // Clear Live Data & Counters
    clearDataBtn.addEventListener('click', async () => {
        if (!confirm('Clear all packet telemetry and live counters?')) return;
        try {
            const res = await fetch('/api/control/clear', { method: 'POST' });
            const data = await res.json();
            state.packets = [];
            packetsTableBody.innerHTML = `
                <tr class="empty-row" id="emptyStateRow">
                    <td colspan="8">
                        <div class="table-empty-state">
                            <i class="fa-solid fa-radar fa-spin-pulse empty-icon"></i>
                            <p>Listening for authorized IP packets on network interface...</p>
                            <small>Generate local network traffic to observe real-time capture.</small>
                        </div>
                    </td>
                </tr>
            `;
            streamCounterBadge.textContent = '0 captured';
            if (data.status) updateMetricsUI(data.status);
        } catch (err) {
            console.error('Clear data failed:', err);
        }
    });

    // Interface Dropdown Selector
    interfaceSelect.addEventListener('change', async () => {
        const selected = interfaceSelect.value;
        try {
            await fetch('/api/control/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ interface: selected })
            });
            fetchStats();
        } catch (err) {
            console.error('Switch interface failed:', err);
        }
    });

    // Protocol Filter Pills (ALL, TCP, UDP, ICMP)
    protocolFilterGroup.addEventListener('click', (e) => {
        const pill = e.target.closest('.filter-pill');
        if (!pill) return;

        protocolFilterGroup.querySelectorAll('.filter-pill').forEach(btn => btn.classList.remove('active'));
        pill.classList.add('active');
        state.activeFilter = pill.dataset.filter;
        applyFilters();
    });

    // Live Search Filter Input
    packetSearchInput.addEventListener('input', (e) => {
        state.searchQuery = e.target.value.trim();
        applyFilters();
    });

    // Auto-scroll toggle
    autoScrollCheck.addEventListener('change', (e) => {
        state.autoScroll = e.target.checked;
    });

    // Export CSV
    exportCsvBtn.addEventListener('click', () => {
        if (state.packets.length === 0) {
            alert('No captured packet metadata to export yet.');
            return;
        }

        const headers = ['Time', 'Source IP', 'Destination IP', 'Protocol', 'Source Port', 'Destination Port', 'Packet Size (Bytes)', 'Status'];
        const csvRows = [headers.join(',')];

        state.packets.forEach(p => {
            const row = [
                `"${p.time}"`,
                `"${p.src_ip}"`,
                `"${p.dst_ip}"`,
                `"${p.protocol}"`,
                `"${p.src_port}"`,
                `"${p.dst_port}"`,
                p.size,
                `"${p.status}"`
            ];
            csvRows.push(row.join(','));
        });

        const csvContent = 'data:text/csv;charset=utf-8,' + encodeURIComponent(csvRows.join('\n'));
        const link = document.createElement('a');
        link.setAttribute('href', csvContent);
        link.setAttribute('download', `network_security_monitor_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.csv`);
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    });

    // Send Authorized Test Probe Helper
    async function sendTestProbe(proto) {
        try {
            const res = await fetch('/api/generate-test-traffic', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ protocol: proto })
            });
            const data = await res.json();
            if (data.packet) {
                handleIncomingPacket(data.packet);
            }
            if (data.stats) {
                updateMetricsUI(data.stats);
            }
        } catch (err) {
            console.error('Failed to generate test probe:', err);
        }
    }

    testTrafficBtn.addEventListener('click', () => sendTestProbe('ICMP'));
    quickPingBtn.addEventListener('click', () => sendTestProbe('ICMP'));
    quickDnsBtn.addEventListener('click', () => sendTestProbe('UDP'));
    quickTcpBtn.addEventListener('click', () => sendTestProbe('TCP'));

    // =========================================================================
    // STARTUP LIFECYCLE
    // =========================================================================
    initProtocolChart();
    loadRecentPackets();
    fetchStats();
    connectEventStream();

    // Secondary polling safety net (every 3 seconds)
    setInterval(fetchStats, 3000);
});
