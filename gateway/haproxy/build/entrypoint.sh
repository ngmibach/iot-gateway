#!/bin/sh
mkdir -p /var/log/haproxy
touch /var/log/haproxy/haproxy.log
chown -R haproxy:haproxy /var/log/haproxy 2>/dev/null || chown -R 99:99 /var/log/haproxy 2>/dev/null || true
chmod 775 /var/log/haproxy
chmod 664 /var/log/haproxy/haproxy.log 2>/dev/null || true
exec haproxy -W -db -f /usr/local/etc/haproxy/haproxy.cfg 2>&1 | tee -a /var/log/haproxy/haproxy.log