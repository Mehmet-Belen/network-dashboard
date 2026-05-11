from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict, deque
import threading
import time
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import ASYNCHRONOUS
import os
from dotenv import load_dotenv
from ping3 import ping
import geoip2.database

load_dotenv(override=True)

# --- 1. AMELİYAT: Dosya Yolu Garantisi (bat dosyasından çalışsa bile çökmez) ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'geo_lite_2_city.mmdb')

# GeoIP Veritabanını yükle
reader = geoip2.database.Reader(DB_PATH)

token = os.getenv("INFLUX_TOKEN")
org = os.getenv("INFLUX_ORG")
bucket = os.getenv("INFLUX_BUCKET")
url = os.getenv("INFLUX_URL")
print("🚨 PYTHON'UN GÖRDÜĞÜ TOKEN:", token)

client = InfluxDBClient(url=url, token=token, org=org)
write_api = client.write_api(write_options=ASYNCHRONOUS)

lock = threading.Lock()

# Kayan pencere — son 1 saniyelik paketler
packet_window = deque()
# Her IP'nin byte sayısını tut
ip_bytes = defaultdict(int)

# Son hesaplanan istatistikler — app.py buradan okuyor
current_stats = {
    "bandwidth_mbps": 0.0,
    "packets_per_second": 0,
    "protocols": {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0},
    "top_talkers": []
}

def process_packet(packet):
    """Her yakalanan paket sadece RAM'e (istatistik için) kaydedilir."""
    if not packet.haslayer(IP):
        return

    now = time.time()
    size = len(packet)

    if size > 1500:
        print(f"🔥 KANIT YAKALANDI: İşletim sistemi paketleri birleştirdi. Boyut: {size} Byte")

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    proto_name = "Other"
    src_port = "0"
    dst_port = "0"
    service = "Other"

    # Protokol ve Port Tespiti
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

    # Portlardan Servis Tahmini (Deep Packet Inspection Lite)
    if dst_port == "443" or src_port == "443":
        service = "HTTPS"
    elif dst_port == "80" or src_port == "80":
        service = "HTTP"
    elif dst_port == "53" or src_port == "53":
        service = "DNS"
    elif proto_name in ["TCP", "UDP"]:
        service = f"Unknown (Port {dst_port})"

    with lock:
        packet_window.append((now, size, proto_name, src_ip, dst_ip, src_port, dst_port, service))
        ip_bytes[src_ip] += size

def compute_stats():
    """
    Her saniye çalışır.
    Son 1 saniyelik penceredeki paketlerden istatistik hesaplar ve InfluxDB'ye TOPLU yazar.
    """
    global current_stats

    while True:
        time.sleep(1)
        now = time.time()
        window_start = now - 1.0

        with lock:
            while packet_window and packet_window[0][0] < window_start:
                packet_window.popleft()
            packets = list(packet_window)

        # ── Boş pencere ──
        if not packets:
            current_stats = {
                "bandwidth_mbps": 0.0,
                "packets_per_second": 0,
                "protocols": {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0},
                "top_talkers": []
            }
            try:
                write_api.write(
                    bucket=bucket,
                    record=Point("network_summary")
                        .field("bandwidth_mbps", 0.0)
                        .field("packets_per_second", 0)
                )
            except Exception as e:
                pass
            continue

        # ── Bant genişliği & PPS ──
        total_bytes = sum(p[1] for p in packets)
        bandwidth   = round((total_bytes * 8) / 1_000_000, 4)   # Mbps
        pps         = len(packets)

        influx_points = []
        aggregated_traffic = defaultdict(lambda: {"bytes": 0, "packets": 0})

        for p in packets:
            _, size, proto_name, src_ip, dst_ip, src_port, dst_port, service = p
            group_key = (src_ip, dst_ip, proto_name, src_port, dst_port, service)
            aggregated_traffic[group_key]["bytes"]   += size
            aggregated_traffic[group_key]["packets"] += 1

        for key, data in aggregated_traffic.items():
            src_ip, dst_ip, proto_name, src_port, dst_port, service = key
            
            # --- 2. AMELİYAT: Mükemmel Koordinat Tespiti ---
            lat = 0.0
            lon = 0.0
            external_ip = dst_ip
            
            # Eğer veri bize geliyorsa (Download), dış IP aslında 'src_ip'dir.
            if dst_ip.startswith(('192.168.', '10.', '172.', '127.')):
                external_ip = src_ip
                
            # Yerel ağları haritada aratıp sistemi yormamak için filtreliyoruz
            if external_ip and not external_ip.startswith(('192.168.', '10.', '172.', '127.', '255.')):
                try:
                    response = reader.city(external_ip)
                    if response.location.latitude and response.location.longitude:
                        lat = response.location.latitude
                        lon = response.location.longitude
                except Exception:
                    pass

            point = Point("network_traffic") \
                    .tag("protocol",  proto_name) \
                    .tag("source_ip", src_ip) \
                    .tag("dest_ip", dst_ip) \
                    .tag("src_port", src_port) \
                    .tag("dst_port", dst_port) \
                    .tag("service", service) \
                    .field("bytes",        data["bytes"]) \
                    .field("packet_count", data["packets"])
            
            # Koordinat bulunduysa pakete zımbala
            if lat != 0.0 and lon != 0.0:
                point.field("latitude", float(lat)).field("longitude", float(lon))
                
            influx_points.append(point)

        # ── Toplam bant genişliği özet noktası ──
        influx_points.append(
            Point("network_summary")
                .field("bandwidth_mbps",    bandwidth)
                .field("packets_per_second", pps)
        )

        try:
            write_api.write(bucket=bucket, record=influx_points)
        except Exception as e:
            print(f"InfluxDB Yazma Hatası: {e}")

        # ── Protokol sayımı (React için) ──
        proto_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
        for p in packets:
            proto_counts[p[2]] += 1

        total    = len(packets)
        proto_pct = {k: round((v / total) * 100) for k, v in proto_counts.items()}

        # ── Top talkers (React için) ──
        with lock:
            sorted_ips = sorted(ip_bytes.items(), key=lambda x: x[1], reverse=True)[:5]
            talkers = [
                {"ip": ip, "mbps": round((byte_count * 8) / 1_000_000, 4)}
                for ip, byte_count in sorted_ips
            ]
            ip_bytes.clear()

        current_stats = {
            "bandwidth_mbps": bandwidth,
            "packets_per_second": pps,
            "protocols": proto_pct,
            "top_talkers": talkers
        }

        print(f"[{time.strftime('%H:%M:%S')}] {bandwidth:.4f} Mbps | {pps} pkt/s")

def health_monitor():
    """Arka planda saniyede bir 8.8.8.8'e ping atarak ağın sağlığını ölçer."""
    while True:
        try:
            delay = ping('8.8.8.8', timeout=1, unit='ms')
            
            if delay is None or delay is False:
                rtt = 0.0
                loss = 1
                status = "Disconnected"
            else:
                rtt = round(delay, 2)
                loss = 0
                status = "Connected"
                
            health_point = Point("network_health") \
                .tag("target", "8.8.8.8") \
                .tag("status", status) \
                .field("rtt_ms", rtt) \
                .field("packet_loss", loss)
                
            write_api.write(bucket=bucket, record=health_point)
            
        except Exception as e:
            pass
            
        time.sleep(1)

def wifi_monitor():
    """Arka planda periyodik olarak Wi-Fi sinyal gücünü ölçer (Zorlu Tarama ile)."""
    import subprocess
    import re
    while True:
        try:
            # Zorlu tarama (Active Scan) tetikle. Bu komut Windows'u etraftaki ağları aramaya zorlar, 
            # böylece 'show interfaces' önbelleği güncellenir.
            subprocess.run(["netsh", "wlan", "show", "networks", "mode=bssid"], creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0)
            
            # Güncellenmiş veriyi al
            output = subprocess.check_output(["netsh", "wlan", "show", "interfaces"], encoding="utf-8", errors="ignore", creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0)
            # Öncelikle doğrudan RSSI değerini çekmeye çalışalım (dBm cinsinden, negatif)
            rssi_match = re.search(r"(?:Rssi|RSSI)\s*:\s*(-?\d+)", output)
            if rssi_match:
                signal_dbm = int(rssi_match.group(1))
            else:
                # Eğer RSSI satırı yoksa (eski Windows), Signal %'sinden yaklaşık dBm hesapla
                signal_match = re.search(r"(?:Signal|Sinyal)\s*:\s*(\d+)%", output)
                if signal_match:
                    quality = int(signal_match.group(1))
                    signal_dbm = (quality / 2) - 100
                else:
                    signal_dbm = None
                    
            if signal_dbm is not None:
                wifi_point = Point("network_wifi") \
                    .tag("interface", "Wi-Fi") \
                    .field("signal_dbm", float(signal_dbm))
                write_api.write(bucket=bucket, record=wifi_point)
        except Exception as e:
            pass
        
        # Her 30 saniyede bir çalıştır (Ağ pingini fazla bozmamak için)
        time.sleep(30)

def get_stats():
    """app.py buradan okuyacak."""
    with lock:
        return dict(current_stats)

def get_active_interface():
    """Aktif ağ arayüzünü otomatik bulur."""
    from scapy.arch.windows import get_windows_if_list
    import socket

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except:
        return "Wi-Fi"

    for iface in get_windows_if_list():
        for addr in iface.get("ips", []):
            if addr == local_ip:
                print(f"Aktif arayüz bulundu: {iface['name']} ({local_ip})")
                return iface["name"]

    return "Wi-Fi"

def start_capture(interface=None):
    stats_thread = threading.Thread(target=compute_stats, daemon=True)
    stats_thread.start()

    health_thread = threading.Thread(target=health_monitor, daemon=True)
    health_thread.start()

    wifi_thread = threading.Thread(target=wifi_monitor, daemon=True)
    wifi_thread.start()

    if interface is None:
        interface = get_active_interface()

    print(f"Paket yakalama başlıyor — arayüz: {interface}")
    sniff(prn=process_packet, store=False, iface=interface)

if __name__ == "__main__":
    start_capture()