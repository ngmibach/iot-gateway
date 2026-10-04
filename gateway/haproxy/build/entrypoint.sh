#!/bin/sh
# Prepare log dir for bind-mount consumers; haproxy itself logs to stdout (see haproxy.cfg).
# Must exec haproxy as PID 1 so docker kill -s HUP reloads allowed-ips.txt.
mkdir -p /var/log/haproxy
touch /var/log/haproxy/haproxy.log
chown -R haproxy:haproxy /var/log/haproxy 2>/dev/null || chown -R 99:99 /var/log/haproxy 2>/dev/null || true
chmod 775 /var/log/haproxy
chmod 664 /var/log/haproxy/haproxy.log 2>/dev/null || true
exec haproxy -W -db -f /usr/local/etc/haproxy/haproxy.cfg
