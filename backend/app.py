from flask import Flask, request as flask_request
from flask_socketio import SocketIO
from flask_cors import CORS
import threading
import time
import random
from anomaly import check_anomalies
from capture import get_stats, start_capture
import logging
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR) # Sadece kritik hataları göster, GET/POST kalabalığını gizle!

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Demo modu toggle — True ise sahte veri karıştırır
DEMO_MODE = False

def demo_stats():
    """Görsel olarak hareketli sahte veri."""
    t = time.time()
    
    # Sinüs dalgası ile doğal görünümlü bant genişliği
    import math
    base = 30 + 20 * math.sin(t * 0.5)        # yavaş dalgalanma
    spike = 20 * math.sin(t * 2.3)             # hızlı 
    noise = random.uniform(-3, 3)              #  gürültü
    bandwidth = round(max(5, base + spike + noise), 2)

    pps = int(bandwidth * 12 + random.randint(-20, 20))

    # Protokol dağılımı demo için
    tcp  = random.randint(55, 72)
    udp  = random.randint(18, 30)
    icmp = 100 - tcp - udp

    talkers = sorted([
        {"ip": "192.168.1.101", "mbps": round(bandwidth * 0.35 + random.uniform(-1, 1), 2)},
        {"ip": "192.168.1.105", "mbps": round(bandwidth * 0.25 + random.uniform(-1, 1), 2)},
        {"ip": "10.0.0.22",     "mbps": round(bandwidth * 0.20 + random.uniform(-1, 1), 2)},
        {"ip": "172.16.0.8",    "mbps": round(bandwidth * 0.12 + random.uniform(-0.5, 0.5), 2)},
        {"ip": "192.168.1.200", "mbps": round(bandwidth * 0.08 + random.uniform(-0.5, 0.5), 2)},
    ], key=lambda x: x["mbps"], reverse=True)

    return {
        "bandwidth_mbps": bandwidth,
        "packets_per_second": pps,
        "protocols": {"TCP": tcp, "UDP": udp, "ICMP": icmp},
        "top_talkers": talkers
    }

def broadcast_loop():
    while True:
        if DEMO_MODE:
            stats = demo_stats()
        else:
            stats = get_stats()

        alerts = check_anomalies(
            stats["bandwidth_mbps"],
            stats["packets_per_second"]
        )
        stats["alerts"] = alerts
        socketio.emit("stats_update", stats)
        time.sleep(1)

@app.route("/")
def index():
    return {"status": "running", "demo_mode": DEMO_MODE}

# Demo modu açıp kapamak için endpoint
@app.route("/api/demo/<mode>")
def set_demo(mode):
    global DEMO_MODE
    DEMO_MODE = mode == "on"
    return {"demo_mode": DEMO_MODE}

@socketio.on("connect")
def handle_connect():
    print("Client bağlandı")

if __name__ == "__main__":
    capture_thread = threading.Thread(
        target=start_capture,
        kwargs={"interface": None},
        daemon=True
    )
    capture_thread.start()

    broadcast_thread = threading.Thread(target=broadcast_loop, daemon=True)
    broadcast_thread.start()

    socketio.run(app, debug=True, port=5000, use_reloader=False)