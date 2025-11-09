from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO, emit
import json
import threading
import time
from collections import deque
import subprocess
import signal
import sys

app = Flask(__name__)
app.config['SECRET_KEY'] = 'packet-monitor-secret'
socketio = SocketIO(app, cors_allowed_origins="*")

# Store recent packet events
packet_events = deque(maxlen=1000)
stats = {
    'total_drops': 0,
    'tcp_drops': 0,
    'udp_drops': 0,
    'other_drops': 0
}

monitor_process = None
monitor_running = False

def parse_packet_event(line):
    """Parse and classify each packet event by protocol"""
    global stats
    text = line.strip()
    if not text or "Loading eBPF" in text or "Monitoring packets" in text:
        return None

    event = {
        'timestamp': time.strftime("%I:%M:%S %p"),
        'data': text
    }

    # Detect protocol only in lines that mention it
    if "Protocol:" in text:
        if "Protocol: TCP" in text:
            stats['tcp_drops'] += 1
        elif "Protocol: UDP" in text:
            stats['udp_drops'] += 1
        else:
            stats['other_drops'] += 1
        stats['total_drops'] += 1

    return event

def monitor_packets():
    """Background thread to monitor packets"""
    global monitor_running, packet_events, stats
    
    # Start the packet monitor (using Python CLI for simplicity)
    cmd = ['sudo', 'python3', '../src/packet_monitor_cli.py']
    
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )
        
        while monitor_running:
            line = process.stdout.readline()
            if line:
                event = parse_packet_event(line)
                if event:
                    packet_events.append(event)
                    stats['total_drops'] += 1
                    
                    # Emit to all connected clients
                    socketio.emit('packet_event', event)
                    
            if process.poll() is not None:
                break
                
    except Exception as e:
        print(f"Monitor error: {e}", file=sys.stderr)
    finally:
        if process:
            process.terminate()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/stats')
def get_stats():
    return jsonify(stats)

@app.route('/api/events')
def get_events():
    return jsonify(list(packet_events)[-100:])

@socketio.on('connect')
def handle_connect():
    print('Client connected')
    emit('initial_data', {
        'stats': stats,
        'events': list(packet_events)[-50:]
    })

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

@socketio.on('start_monitor')
def handle_start():
    global monitor_running
    if not monitor_running:
        monitor_running = True
        thread = threading.Thread(target=monitor_packets)
        thread.daemon = True
        thread.start()
        emit('status', {'running': True})

@socketio.on('stop_monitor')
def handle_stop():
    global monitor_running
    monitor_running = False
    emit('status', {'running': False})

def signal_handler(sig, frame):
    global monitor_running
    monitor_running = False
    sys.exit(0)

if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    print("Starting packet monitor dashboard on http://localhost:5000")
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
