FROM python:3.10-slim

# Scapy için gerekli sistem kütüphanelerini kuralım
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --default-timeout=100 --no-cache-dir -r requirements.txt
COPY . .

# Paket yakalamak için root yetkisi gerekebilir
CMD ["python", "capture.py"]