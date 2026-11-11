FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY config.py main.py ./
COPY core/ core/
COPY notifiers/ notifiers/
RUN mkdir -p /data
ENTRYPOINT ["python", "-u", "main.py"]
CMD ["--interface", "eth0", "--log-file", "/data/alerts.json"]
