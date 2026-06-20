FROM nodered/node-red:latest 
USER root

RUN apk add --no-cache python3 py3-pip py3-scikit-learn

RUN pip3 install --no-cache-dir cryptography --break-system-packages

RUN pip3 install --no-cache-dir \
    lightgbm \
    paho-mqtt \
    numpy \
    pandas \
    pyyaml \
    joblib \
    --break-system-packages

RUN apk add --no-cache tzdata \
    && cp /usr/share/zoneinfo/Asia/Ho_Chi_Minh /etc/localtime \
    && echo "Asia/Ho_Chi_Minh" > /etc/timezone

COPY ids/ids_gateway /app/ids_gateway
COPY ids/configs /app/configs
COPY ids/models /app/models
COPY nodered/build/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh && \
    mkdir -p /app/ids/logs && \
    mkdir -p /app/nodered_logs && \
    chown -R node-red:node-red /app

USER node-red

ENV TZ=Asia/Ho_Chi_Minh
ENV PYTHONPATH=/app:$PYTHONPATH

ENTRYPOINT ["/app/entrypoint.sh"]