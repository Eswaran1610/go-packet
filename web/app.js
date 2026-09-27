const ui = {
    interfaces: document.getElementById('interfaces'),
    bpfFilter: document.getElementById('bpf-filter'),
    displayFilter: document.getElementById('display-filter'),
    btnStart: document.getElementById('btn-start'),
    btnStop: document.getElementById('btn-stop'),
    btnClear: document.getElementById('btn-clear'),
    btnExport: document.getElementById('btn-export'),
    btnImport: document.getElementById('btn-import'),
    fileImport: document.getElementById('file-import'),
    btnRefreshFlows: document.getElementById('btn-refresh-flows'),
    status: document.getElementById('status'),
    stats: document.getElementById('stats'),
    packetList: document.getElementById('packet-list'),
    detailsContent: document.getElementById('details-content'),
    hexdumpContent: document.getElementById('hexdump-content'),
    flowsContent: document.getElementById('flows-content'),
    tabs: document.querySelectorAll('.tab-btn')
};

let packets = new Map();
let currentDisplayFilter = '';
let evtSource = null;

async function init() {
    // Load interfaces
    try {
        const res = await fetch('/api/interfaces');
        const ifaces = await res.json();
        ui.interfaces.innerHTML = ifaces.map(i => 
            `<option value="${i.name}">${i.name} ${i.addresses ? '('+i.addresses.join(', ')+')' : ''}</option>`
        ).join('');
    } catch (e) {
        console.error('Failed to load interfaces:', e);
    }

    // Event Listeners
    ui.btnStart.addEventListener('click', startCapture);
    ui.btnStop.addEventListener('click', stopCapture);
    ui.btnClear.addEventListener('click', clearPackets);
    ui.displayFilter.addEventListener('input', (e) => {
        currentDisplayFilter = e.target.value.toLowerCase();
        applyDisplayFilter();
    });
    
    ui.tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            ui.tabs.forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
            
            tab.classList.add('active');
            document.getElementById(tab.dataset.target).classList.add('active');
            
            if (tab.dataset.target === 'tab-conversations') {
                loadFlows();
            }
        });
    });

    ui.btnExport.addEventListener('click', () => window.location.href = '/api/export');
    
    ui.btnImport.addEventListener('click', () => ui.fileImport.click());
    ui.fileImport.addEventListener('change', async (e) => {
        if (!e.target.files.length) return;
        const formData = new FormData();
        formData.append('file', e.target.files[0]);
        ui.status.textContent = "Loading...";
        try {
            await fetch('/api/import', { method: 'POST', body: formData });
        } catch (err) {
            console.error(err);
            alert("Import failed: " + err);
        }
        e.target.value = ''; // reset
    });

    ui.btnRefreshFlows.addEventListener('click', loadFlows);

    // Setup SSE connection
    connectSSE();
    
    // Stats poller
    setInterval(updateStats, 1000);
}

function connectSSE() {
    if (evtSource) evtSource.close();
    
    evtSource = new EventSource('/ws');
    
    evtSource.onmessage = (e) => {
        const msg = JSON.parse(e.data);
        if (msg.type === 'packet') {
            addPacket(msg.payload);
        } else if (msg.type === 'packets') {
            msg.payload.forEach(addPacket);
        } else if (msg.type === 'clear') {
            packets.clear();
            ui.packetList.innerHTML = '';
            clearSelection();
        }
    };
    
    evtSource.onerror = () => {
        setTimeout(connectSSE, 2000); // Reconnect
    };
}

async function startCapture() {
    const iface = ui.interfaces.value;
    const bpf = ui.bpfFilter.value;
    
    if (!iface) return alert("Select an interface");
    
    try {
        const res = await fetch(`/api/start?interface=${encodeURIComponent(iface)}&bpf=${encodeURIComponent(bpf)}`);
        if (!res.ok) throw new Error(await res.text());
        
        ui.btnStart.disabled = true;
        ui.btnStop.disabled = false;
        ui.interfaces.disabled = true;
        ui.bpfFilter.disabled = true;
    } catch (e) {
        alert("Start failed: " + e.message);
    }
}

async function stopCapture() {
    try {
        await fetch('/api/stop');
        ui.btnStart.disabled = false;
        ui.btnStop.disabled = true;
        ui.interfaces.disabled = false;
        ui.bpfFilter.disabled = false;
    } catch (e) {
        console.error(e);
    }
}

async function clearPackets() {
    try {
        await fetch('/api/clear');
    } catch(e) {}
}

async function updateStats() {
    try {
        const res = await fetch('/api/stats');
        const stats = await res.json();
        
        ui.stats.textContent = `Recv: ${stats.received} | Drop: ${stats.dropped} | Saved: ${stats.saved}`;
        
        if (stats.active) {
            ui.status.textContent = 'Capturing';
            ui.status.classList.add('active');
            ui.btnStart.disabled = true;
            ui.btnStop.disabled = false;
            ui.interfaces.disabled = true;
            ui.bpfFilter.disabled = true;
        } else {
            ui.status.textContent = 'Idle';
            ui.status.classList.remove('active');
            ui.btnStart.disabled = false;
            ui.btnStop.disabled = true;
            ui.interfaces.disabled = false;
            ui.bpfFilter.disabled = false;
        }
    } catch (e) {}
}

const tableAutoScroll = true; // For a real app, maybe toggleable

function addPacket(pkt) {
    packets.set(pkt.id, pkt);
    
    const tr = document.createElement('tr');
    tr.dataset.id = pkt.id;
    tr.dataset.proto = pkt.protocol;
    tr.innerHTML = `
        <td>${pkt.id}</td>
        <td>${pkt.timestamp.split(' ')[1] || pkt.timestamp}</td>
        <td>${pkt.srcAddr || ''}</td>
        <td>${pkt.dstAddr || ''}</td>
        <td>${pkt.protocol}</td>
        <td>${pkt.length}</td>
        <td>${pkt.info}</td>
    `;
    
    tr.addEventListener('click', () => selectPacket(pkt.id, tr));
    
    if (currentDisplayFilter && !matchFilter(pkt, currentDisplayFilter)) {
        tr.classList.add('hidden');
    }

    const wasAtBottom = ui.packetList.parentElement.scrollHeight - ui.packetList.parentElement.scrollTop <= ui.packetList.parentElement.clientHeight + 50;
    
    ui.packetList.appendChild(tr);

    // Limit DOM nodes
    while (ui.packetList.children.length > 1000) {
        const first = ui.packetList.firstElementChild;
        packets.delete(parseInt(first.dataset.id));
        first.remove();
    }
    
    if (wasAtBottom && tableAutoScroll) {
        tr.scrollIntoView();
    }
}

function matchFilter(pkt, filter) {
    if (!filter) return true;
    const s = `${pkt.protocol} ${pkt.srcAddr} ${pkt.dstAddr} ${pkt.srcPort} ${pkt.dstPort} ${pkt.info}`.toLowerCase();
    return s.includes(filter);
}

function applyDisplayFilter() {
    Array.from(ui.packetList.children).forEach(tr => {
        const pkt = packets.get(parseInt(tr.dataset.id));
        if (pkt && matchFilter(pkt, currentDisplayFilter)) {
            tr.classList.remove('hidden');
        } else {
            tr.classList.add('hidden');
        }
    });
}

function clearSelection() {
    document.querySelectorAll('#packet-list tr.selected').forEach(el => el.classList.remove('selected'));
    document.querySelectorAll('.placeholder').forEach(el => el.style.display = 'block');
    ui.detailsContent.innerHTML = '';
    ui.hexdumpContent.textContent = '';
}

function selectPacket(id, trElement) {
    clearSelection();
    if (trElement) trElement.classList.add('selected');
    
    const pkt = packets.get(id);
    if (!pkt) return;
    
    document.querySelectorAll('.placeholder').forEach(el => el.style.display = 'none');
    
    // Details
    ui.detailsContent.innerHTML = pkt.layers.map(layer => `
        <div class="layer">
            <div class="layer-header" onclick="this.nextElementSibling.classList.toggle('hidden')">
                <span>${layer.name}</span>
                <span>▼</span>
            </div>
            <div class="layer-fields">
                ${layer.fields.map(f => `
                    <div class="field-key">${f.key}:</div>
                    <div class="field-val">${escapeHTML(f.value)}</div>
                `).join('')}
            </div>
        </div>
    `).join('');
    
    // Hex
    ui.hexdumpContent.textContent = pkt.hexDump || 'No payload';
}

async function loadFlows() {
    try {
        const res = await fetch('/api/conversations');
        const flows = await res.json();
        
        if (!flows || flows.length === 0) {
            ui.flowsContent.innerHTML = '<p class="placeholder">No flows detected yet.</p>';
            return;
        }
        
        // Sort by byte count descending
        flows.sort((a,b) => b.byteCount - a.byteCount);
        
        ui.flowsContent.innerHTML = flows.map(f => `
            <div class="flow-card">
                <div class="flow-header">${f.protocol} ${f.addrA}:${f.portA} ↔ ${f.addrB}:${f.portB}</div>
                <div class="flow-stats">${f.packetCount} pkts, ${f.byteCount} bytes</div>
                ${f.tcpStateStr ? `<div class="flow-state">${f.tcpStateStr}</div>` : ''}
                ${f.handshake && f.handshake.length > 0 ? `
                    <div style="margin-top: 5px;">
                        ${f.handshake.map(h => `<div class="hs-step">#${h.packetId} [${h.flags}] ${h.from} → ${h.to}</div>`).join('')}
                    </div>
                ` : ''}
            </div>
        `).join('');
        
    } catch(e) {
        console.error(e);
        ui.flowsContent.innerHTML = '<p style="color:var(--danger)">Failed to load flows</p>';
    }
}

function escapeHTML(str) {
    if (typeof str !== 'string') return str;
    return str.replace(/[&<>'"]/g, tag => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;'
    }[tag] || tag));
}

// Start
init();
