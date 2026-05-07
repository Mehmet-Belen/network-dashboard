from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict, deque
import threading
import time
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import ASYNCHRONOUS
import os
from dotenv import load_dotenv

load_dotenv(override=True)  # .env dosyasını yükle ve mevcut env değişkenlerini geçersiz kıl

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
ip_bytes = defaultdict(int)  # defaultdict — olmayan key'e erişince 0 döndürür

# Son hesaplanan istatistikler — app.py buradan okuyo
current_stats = {
    "bandwidth_mbps": 0.0,
    "packets_per_second": 0,
    "protocols": {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0},
    "top_talkers": []
}

def process_packet(packet):
    """Her yakalanan paket sadece RAM'e (istatistik için) kaydedilir. Hızlı olmalıdır!"""
    if not packet.haslayer(IP):
        return 

    now = time.time()
    size = len(packet)
    # KANTAR: Eğer paket fiziksel sınır (1500 byte) üstündeyse terminale yazdır!
    if size > 1500:
        print(f"🔥 KANIT YAKALANDI: İşletim sistemi paketleri birleştirdi. Boyut: {size} Byte")
    src_ip = packet[IP].src
    
    # Protokol Belirleme
    proto_name = "Other"
    if packet.haslayer(TCP): proto_name = "TCP"
    elif packet.haslayer(UDP): proto_name = "UDP"
    elif packet.haslayer(ICMP): proto_name = "ICMP"

    with lock:
        packet_window.append((now, size, proto_name, src_ip))
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
        window_start = now - 1.0  # son 1 saniye

        with lock:
            # Pencereden 1 saniyeden eski paketleri temizle
            while packet_window and packet_window[0][0] < window_start:
                packet_window.popleft()

            # Penceredeki paketleri analiz et
            packets = list(packet_window)

        if not packets:
            current_stats = {
                "bandwidth_mbps": 0.0,
                "packets_per_second": 0,
                "protocols": {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0},
                "top_talkers": []
            }
            continue

        # Toplam byte → Mbps
        total_bytes = sum(p[1] for p in packets)
        bandwidth = round((total_bytes * 8) / 1_000_000, 2)
        pps = len(packets)

        # =================================================================
        # 🔥 YENİ SİSTEM: GRAFANA İÇİN TOPLU YAZMA (BATCH WRITE) 🔥
        # =================================================================
        influx_points = []
        aggregated_traffic = defaultdict(lambda: {"bytes": 0, "packets": 0})

        # 1. 1 Saniyelik veriyi IP ve Protokole göre grupla
        for p in packets:
            _, size, proto_name, src_ip = p
            aggregated_traffic[(src_ip, proto_name)]["bytes"] += size
            aggregated_traffic[(src_ip, proto_name)]["packets"] += 1

        # 2. Gruplanmış verileri InfluxDB noktalarına dönüştür
        for (src_ip, proto_name), data in aggregated_traffic.items():
            point = Point("network_traffic") \
                .tag("protocol", proto_name) \
                .tag("source_ip", src_ip) \
                .field("bytes", data["bytes"]) \
                .field("packet_count", data["packets"])
            influx_points.append(point)

        # 3. Hepsini tek seferde otobüsle InfluxDB'ye gönder!
        if influx_points:
            try:
                write_api.write(bucket=bucket, record=influx_points)
            except Exception as e:
                print(f"InfluxDB Yazma Hatası: {e}")
        # =================================================================

        # Protokol sayımı (React için)
        proto_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
        for p in packets:
            proto_counts[p[2]] += 1

        total = len(packets)
        proto_pct = {k: round((v / total) * 100) for k, v in proto_counts.items()}

        # Top talkers — en çok byte gönderen IP'ler (React için)
        with lock:
            sorted_ips = sorted(
                ip_bytes.items(),          # (ip, byte_sayısı) çiftleri
                key=lambda x: x[1],        # byte_sayısına göre sırala
                reverse=True               # büyükten küçüğe
            )[:5]                          # ilk 5

            talkers = [
                {
                    "ip": ip,
                    "mbps": round((byte_count * 8) / 1_000_000, 2)
                }
                for ip, byte_count in sorted_ips
            ]
            ip_bytes.clear()

        current_stats = {
            "bandwidth_mbps": bandwidth,
            "packets_per_second": pps,
            "protocols": proto_pct,
            "top_talkers": talkers
        }

def get_stats():
    """app.py buradan okuyacak."""
    with lock:
        return dict(current_stats)

def get_active_interface():
    """
    Aktif ağ arayüzünü otomatik bulur.
    Önce Wi-Fi, sonra Ethernet dener.
    """
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

    if interface is None:
        interface = get_active_interface()

    print(f"Paket yakalama başlıyor — arayüz: {interface}")
    sniff(prn=process_packet, store=False, iface=interface)

if __name__ == "__main__":
    start_capture()