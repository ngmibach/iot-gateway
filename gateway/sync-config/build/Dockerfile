FROM alpine:3.19

RUN apk add --no-cache jq python3

COPY sync-config.sh /usr/local/bin/sync-config.sh
COPY acl_to_json.py /usr/local/bin/acl_to_json.py
RUN chmod +x /usr/local/bin/sync-config.sh /usr/local/bin/acl_to_json.py

CMD ["/usr/local/bin/sync-config.sh"]
