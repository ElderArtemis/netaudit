FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# masscan, nmap + scripts NSE, libcap para setcap
RUN apt-get update && apt-get install -y --no-install-recommends \
        masscan \
        nmap \
        ca-certificates \
        libcap2-bin \
        tini \
    && rm -rf /var/lib/apt/lists/*

# Capabilities mínimas para SYN scan sin ejecutar como root
RUN setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/masscan && \
    setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app ./app
COPY alembic ./alembic
COPY alembic.ini ./

# Usuario no-root con UID estable
RUN useradd -u 10001 -m -s /bin/bash netaudit && chown -R netaudit:netaudit /app
USER netaudit

EXPOSE 8000
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
