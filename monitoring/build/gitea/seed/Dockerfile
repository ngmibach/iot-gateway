FROM alpine:latest
RUN apk add --no-cache \
    git \
    curl \
    jq \
    docker-cli

COPY scripts/seed-gitea.sh /seed-gitea.sh
RUN chmod +x /seed-gitea.sh

ENTRYPOINT ["/seed-gitea.sh"]
