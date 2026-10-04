FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY iot_gateway_agent/ iot_gateway_agent/

ENV AGENT_HOST=0.0.0.0
ENV AGENT_PORT=9138
EXPOSE 9138

CMD ["python", "-m", "iot_gateway_agent"]
