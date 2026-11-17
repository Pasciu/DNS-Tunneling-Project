FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir dnslib
COPY server.py .
RUN mkdir -p /logs
EXPOSE 53/udp 53/tcp
CMD ["python", "-u", "server.py"]
