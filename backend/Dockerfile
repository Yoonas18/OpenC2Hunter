FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev tcpdump iptables iproute2 gcc python3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN mkdir -p /app/data

CMD ["sh", "-c", "python3 sniffer_daemon.py & uvicorn backend_engine:app --host 127.0.0.1 --port 8000"]
