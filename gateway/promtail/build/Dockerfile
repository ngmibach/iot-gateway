FROM grafana/promtail:latest
RUN apt-get update && apt-get install -y ca-certificates curl
COPY ca-certificates.crt /usr/local/share/ca-certificates/bosch-ca.crt
RUN update-ca-certificates