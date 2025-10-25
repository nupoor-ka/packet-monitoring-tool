const socket = io();
let isMonitoring = false;

// DOM elements
const statusEl = document.getElementById('status');
const startBtn = document.getElementById('startBtn');
const stopBtn = document.getElementById('stopBtn');
const eventsEl = document.getElementById('events');
const totalDropsEl = document.getElementById('totalDrops');
const tcpDropsEl = document.getElementById('tcpDrops');
const udpDropsEl = document.getElementById('udpDrops');
const otherDropsEl = document.getElementById('otherDrops');

let stats = {
    total_drops: 0,
    tcp_drops: 0,
    udp_drops: 0,
    other_drops: 0
};

// Socket event handlers
socket.on('connect', () => {
    console.log('Connected to server');
});

socket.on('disconnect', () => {
    console.log('Disconnected from server');
    updateStatus(false);
});

socket.on('initial_data', (data) => {
    stats = data.stats;
    updateStats();
    
    // Display initial events
    data.events.forEach(event => {
        addEvent(event);
    });
});

socket.on('packet_event', (event) => {
    stats.total_drops++;
    updateStats();
    addEvent(event);
});

socket.on('status', (data) => {
    updateStatus(data.running);
});

// Control functions
function startMonitor() {
    socket.emit('start_monitor');
    updateStatus(true);
}

function stopMonitor() {
    socket.emit('stop_monitor');
    updateStatus(false);
}

function clearEvents() {
    eventsEl.innerHTML = '';
}

// UI update functions
function updateStatus(running) {
    isMonitoring = running;
    
    if (running) {
        statusEl.textContent = 'Running';
        statusEl.className = 'status running';
        startBtn.disabled = true;
        stopBtn.disabled = false;
    } else {
        statusEl.textContent = 'Stopped';
        statusEl.className = 'status stopped';
        startBtn.disabled = false;
        stopBtn.disabled = true;
    }
}

function updateStats() {
    totalDropsEl.textContent = stats.total_drops.toLocaleString();
    tcpDropsEl.textContent = stats.tcp_drops.toLocaleString();
    udpDropsEl.textContent = stats.udp_drops.toLocaleString();
    otherDropsEl.textContent = stats.other_drops.toLocaleString();
}

function addEvent(event) {
    const eventEl = document.createElement('div');
    eventEl.className = 'event';
    
    const timestamp = new Date(event.timestamp * 1000).toLocaleTimeString();
    eventEl.textContent = `[${timestamp}] ${event.data}`;
    
    eventsEl.insertBefore(eventEl, eventsEl.firstChild);
    
    // Keep only the last 100 events
    while (eventsEl.children.length > 100) {
        eventsEl.removeChild(eventsEl.lastChild);
    }
}

// Initialize
fetch('/api/stats')
    .then(res => res.json())
    .then(data => {
        stats = data;
        updateStats();
    });
