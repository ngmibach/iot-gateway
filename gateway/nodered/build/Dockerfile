FROM nodered/node-red:latest 
USER root

RUN apk add --no-cache python3 py3-pip

RUN pip3 install --no-cache-dir cryptography --break-system-packages

RUN apk add --no-cache tzdata \
    && cp /usr/share/zoneinfo/Asia/Ho_Chi_Minh /etc/localtime \
    && echo "Asia/Ho_Chi_Minh" > /etc/timezone

USER node-red

ENV TZ=Asia/Ho_Chi_Minh