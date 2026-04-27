FROM python:3.11-slim
RUN apt-get update && apt-get install -y iptables iproute2 procps && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY *.py ./
COPY config.yaml ./
RUN mkdir -p /var/log/detector /var/log/nginx
EXPOSE 8080
ENTRYPOINT ["python", "-u", "main.py"]
