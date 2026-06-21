FROM alpine:latest
RUN apk add --no-cache \
    git \
    curl \
    jq \
    docker

COPY build/gitea/seed/daemon.json /etc/docker/daemon.json

COPY build/gitea/action_latest/Dockerfile /runner/action/Dockerfile

COPY scripts/seed-gitea.sh /seed-gitea.sh
RUN chmod +x /seed-gitea.sh

ENTRYPOINT ["/seed-gitea.sh"]
