FROM python:3.12-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends libgomp1 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements-runtime.txt .
RUN pip install --no-cache-dir -r requirements-runtime.txt

COPY ids_gateway/ ids_gateway/
COPY models/ models/
COPY configs/ configs/

CMD ["python", "-m", "ids_gateway.main", "/app/configs/ids_config.yaml"]