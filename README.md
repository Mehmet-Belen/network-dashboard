# Real-Time Network Traffic Monitoring Dashboard
<img width="1878" height="982" alt="Ekran görüntüsü 2026-04-26 192058" src="https://github.com/user-attachments/assets/5f7f1f48-adde-4151-aef6-d5cecff98b9b" />

Wireless and Mobile Networks dersi projesi.

Gerçek zamanlı ağ trafiğini yakalayıp analiz eden ve web tabanlı bir dashboard üzerinde görselleştiren full-stack uygulama.

## Özellikler

- Gerçek zamanlı paket yakalama (scapy / libpcap)
- Canlı bant genişliği grafiği (WebSocket ile güncelleme)
- Protokol dağılımı — TCP / UDP / ICMP
- En çok trafik üreten IP'ler (top talkers)
- Otomatik anomali tespiti — kayan pencere ortalaması ile spike algılama

## Stack

| Katman |                      |Teknoloji |

| Paket yakalama|               |Python, scapy |
| Backend |                     |Python, Flask, Flask-SocketIO |
| Frontend |                    |React, Recharts |
| Gerçek zamanlı iletişim |     |WebSocket (socket.io) |

## Kurulum

### Backend

```bash
cd backend
python -m venv venv # bir kez yapmak yeterli
venv\Scripts\activate      # Windows
pip install -r requirements.txt # bir kez yapmak yeterli
python capture.py              # Yönetici yetkisi gerekebilir
```

```bash
cd backend
venv\Scripts\activate      # Windows
python app.py              # Yönetici yetkisi gerekebilir
```

### Frontend

```bash
cd frontend
npm install # bir kez
npm start
```

Uygulama `http://localhost:3000` adresinde açılır.

## Mimari
Ağ Arayüzü (NIC)
↓
Paket Yakalama (scapy)
↓
İstatistik Motoru + Anomali Tespiti
↓
Flask WebSocket Sunucusu
↓
React Dashboard

## Proje Yapısı

network-dashboard/
├── backend/
│   ├── app.py          # Flask sunucusu, WebSocket
│   ├── capture.py      # Paket yakalama ve istatistik
│   ├── anomaly.py      # Anomali tespiti
│   └── requirements.txt
└── frontend/
└── src/
├── hooks/
│   └── useWebSocket.js
└── components/
├── BandwidthChart.jsx
├── ProtocolPie.jsx
├── TopTalkers.jsx
└── AlertFeed.jsx


## Demo Modu

`app.py` içinde `DEMO_MODE = True` ayarıyla simüle edilmiş trafik üretilir.  
Gerçek trafiğe geçmek için `DEMO_MODE = False` yap ya da tarayıcıda şu adrese git:

- Demo aç: `http://localhost:5000/api/demo/on`
- Demo kapat: `http://localhost:5000/api/demo/off`