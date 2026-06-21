FROM python:3.12-alpine

RUN apk add --no-cache tzdata \
    && cp /usr/share/zoneinfo/Asia/Ho_Chi_Minh /etc/localtime \
    && echo "Asia/Ho_Chi_Minh" > /etc/timezone

COPY monitor.py /usr/local/bin/monitor.py
RUN chmod +x /usr/local/bin/monitor.py

CMD ["python3", "-u", "/usr/local/bin/monitor.py"]