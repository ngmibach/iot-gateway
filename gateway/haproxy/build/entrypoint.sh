#!/bin/sh
# Prepare log dir and keep FD 3 open across exec so haproxy can dual-log to the
# bind-mounted file (IDS/Promtail) while remaining PID 1 for HUP reload.
mkdir -p /var/log/haproxy
touch /var/log/haproxy/haproxy.log
chown -R haproxy:haproxy /var/log/haproxy 2>/dev/null || chown -R 99:99 /var/log/haproxy 2>/dev/null || true
chmod 775 /var/log/haproxy
chmod 664 /var/log/haproxy/haproxy.log 2>/dev/null || true
exec 3>>/var/log/haproxy/haproxy.log
exec haproxy -W -db -f /usr/local/etc/haproxy/haproxy.cfg
